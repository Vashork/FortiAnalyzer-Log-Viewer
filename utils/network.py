import socket
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError, as_completed
from threading import Lock
from typing import Dict, Iterable, List, Optional
import os

from config import get_dynamic_reverse_dns_enabled

MAX_EXPANDED_TARGETS_LIMIT = int(os.getenv("MAX_EXPANDED_TARGETS_LIMIT", "4096"))

# Кэш для разрешения имён: ip -> (hostname, last_access_ts)
_hostname_cache: Dict[str, tuple[str, float]] = {}
_last_reverse_dns_enabled: Optional[bool] = None
_reverse_dns_timeout = float(os.getenv("REVERSE_DNS_TIMEOUT", "0.3"))
_reverse_dns_workers = int(os.getenv("REVERSE_DNS_WORKERS", "16"))
_reverse_dns_cache_ttl = float(os.getenv("REVERSE_DNS_CACHE_TTL_SECONDS", "86400"))
_reverse_dns_cache_size = int(os.getenv("REVERSE_DNS_CACHE_SIZE", "10000"))
_cache_lock = Lock()


def clear_hostname_cache() -> None:
    """Clear cached reverse-DNS lookups."""
    with _cache_lock:
        _hostname_cache.clear()


def configure_reverse_dns(enabled: Optional[bool]) -> None:
    """Set request-scoped reverse-DNS state; None resets to lazy env discovery."""
    global _last_reverse_dns_enabled
    if enabled != _last_reverse_dns_enabled:
        clear_hostname_cache()
    _last_reverse_dns_enabled = enabled


def _is_reverse_dns_enabled() -> bool:
    global _last_reverse_dns_enabled

    if _last_reverse_dns_enabled is None:
        _last_reverse_dns_enabled = get_dynamic_reverse_dns_enabled()
    return bool(_last_reverse_dns_enabled)


def _cache_get(ip: str) -> Optional[str]:
    now = time.monotonic()
    cached = _hostname_cache.get(ip)
    if cached is None:
        return None
    hostname, last_access = cached
    if _reverse_dns_cache_ttl > 0 and now - last_access > _reverse_dns_cache_ttl:
        _hostname_cache.pop(ip, None)
        return None
    _hostname_cache[ip] = (hostname, now)
    return hostname


def _cache_set(ip: str, hostname: str) -> None:
    now = time.monotonic()
    _hostname_cache[ip] = (hostname, now)
    if _reverse_dns_cache_size > 0 and len(_hostname_cache) > _reverse_dns_cache_size:
        overflow = len(_hostname_cache) - _reverse_dns_cache_size
        oldest_ips = sorted(_hostname_cache, key=lambda key: _hostname_cache[key][1])[:overflow]
        for old_ip in oldest_ips:
            _hostname_cache.pop(old_ip, None)


def _lookup_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ip


def _lookup_hostname_with_timeout(ip: str) -> str:
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_lookup_hostname, ip)
        try:
            return future.result(timeout=_reverse_dns_timeout)
        except TimeoutError:
            return ip


def resolve_hostname(ip: str) -> str:
    """Разрешает PTR-запись для IP. Возвращает hostname или сам IP, если не найден."""
    if not _is_reverse_dns_enabled():
        return ip
    with _cache_lock:
        cached = _cache_get(ip)
    if cached is not None:
        return cached

    hostname = _lookup_hostname_with_timeout(ip)
    with _cache_lock:
        _cache_set(ip, hostname)
    return hostname


def resolve_hostnames(ips: Iterable[str], max_workers: Optional[int] = None) -> Dict[str, str]:
    """Resolve many IPs with bounded concurrency and shared cache."""
    unique_ips = list(dict.fromkeys(str(ip) for ip in ips if ip))
    if not _is_reverse_dns_enabled():
        return {ip: ip for ip in unique_ips}

    result: Dict[str, str] = {}
    missing = []
    with _cache_lock:
        for ip in unique_ips:
            cached = _cache_get(ip)
            if cached is None:
                missing.append(ip)
            else:
                result[ip] = cached

    if missing:
        workers = max(1, min(max_workers or _reverse_dns_workers, len(missing)))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {executor.submit(_lookup_hostname_with_timeout, ip): ip for ip in missing}
            for future in as_completed(future_map):
                ip = future_map[future]
                try:
                    hostname = future.result()
                except Exception:
                    hostname = ip
                result[ip] = hostname
                with _cache_lock:
                    _cache_set(ip, hostname)

    return {ip: result.get(ip, ip) for ip in unique_ips}


# -----------------------------
#  CIDR / Ranges
# -----------------------------
def parse_ip_range(spec: str) -> List[str]:
    """Преобразует CIDR или диапазон в список IP-адресов с защитой от огромного расширения."""
    spec = spec.strip()
    if "/" in spec:
        network = ipaddress.IPv4Network(spec, strict=False)
        if network.num_addresses > MAX_EXPANDED_TARGETS_LIMIT:
            raise ValueError(
                f"CIDR {spec} expands to {network.num_addresses} IPs; "
                f"limit is {MAX_EXPANDED_TARGETS_LIMIT}"
            )
        return [str(ip) for ip in network]
    elif "-" in spec:
        start_ip, end_ip = spec.split("-", 1)
        start = ipaddress.IPv4Address(start_ip.strip())
        end = ipaddress.IPv4Address(end_ip.strip())
        if int(end) < int(start):
            raise ValueError(f"Invalid IP range {spec}: end is before start")
        count = int(end) - int(start) + 1
        if count > MAX_EXPANDED_TARGETS_LIMIT:
            raise ValueError(
                f"Range {spec} expands to {count} IPs; limit is {MAX_EXPANDED_TARGETS_LIMIT}"
            )
        return [str(ipaddress.IPv4Address(i)) for i in range(int(start), int(end) + 1)]
    else:
        return [spec]  # single IP


# -----------------------------
#  Targets loader
# -----------------------------
def load_machines(path: str) -> List[str]:
    """
    Загружает список целей из файла.

    Поддерживает:
      - одиночные IP-адреса
      - CIDR-сети (10.20.0.0/24)
      - диапазоны (192.168.1.10-192.168.1.20)
      - hostnames (orion.diasoft.ru) — резолвятся в IPv4-адрес
    """
    ips: List[str] = []

    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue

                # CIDR или диапазон
                if "/" in line or "-" in line:
                    try:
                        ips.extend(parse_ip_range(line))
                        continue
                    except Exception:
                        print(f"⚠️ Cannot parse CIDR/range in machines file: {line}")
                        continue

                # Пытаемся интерпретировать как IP
                try:
                    ipaddress.IPv4Address(line)
                    ips.append(line)
                    continue
                except ipaddress.AddressValueError:
                    pass

                # Если не IP — пытаемся как hostname
                try:
                    resolved_ip = socket.gethostbyname(line)
                    ips.append(resolved_ip)
                except socket.gaierror:
                    print(f"⚠️ Cannot resolve hostname in machines file: {line}")

    except FileNotFoundError:
        return []

    return ips


# -----------------------------
#  Ports loader for --proto
# -----------------------------
def load_ports(path: str) -> List[str]:
    """
    Загружает список портов из файла (по умолчанию ports.txt / значение из PORTS_FILE).

    Формат:
      53
      22
      445
      # комментарии начинаются с #
      53/tcp   # допустимо, будет взято только число до '/'

    Возвращает список строковых значений портов.
    """
    ports: List[str] = []

    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue

                # допускаем формат 53/tcp -> берём до '/'
                if "/" in line:
                    line = line.split("/", 1)[0].strip()

                if not line.isdigit():
                    print(f"⚠️ Invalid port value in {path}: {line}")
                    continue

                ports.append(line)
    except FileNotFoundError:
        print(f"⚠️ Ports file not found: {path}")

    return ports
