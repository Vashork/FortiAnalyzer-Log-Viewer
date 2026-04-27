import socket
import ipaddress
from typing import List
import os

from config import get_dynamic_reverse_dns_enabled

# Кэш для разрешения имён
_hostname_cache = {}
_reverse_dns_timeout = float(os.getenv("REVERSE_DNS_TIMEOUT", "0.3"))


def resolve_hostname(ip: str) -> str:
    """Разрешает PTR-запись для IP. Возвращает hostname или сам IP, если не найден."""
    if not get_dynamic_reverse_dns_enabled():
        return ip
    if ip in _hostname_cache:
        return _hostname_cache[ip]
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(_reverse_dns_timeout)
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        hostname = ip
    finally:
        socket.setdefaulttimeout(old_timeout)
    _hostname_cache[ip] = hostname
    return hostname


# -----------------------------
#  CIDR / Ranges
# -----------------------------
def parse_ip_range(spec: str) -> List[str]:
    """Преобразует CIDR или диапазон в список IP-адресов."""
    spec = spec.strip()
    if "/" in spec:
        return [str(ip) for ip in ipaddress.IPv4Network(spec, strict=False)]
    elif "-" in spec:
        start_ip, end_ip = spec.split("-", 1)
        start = ipaddress.IPv4Address(start_ip.strip())
        end = ipaddress.IPv4Address(end_ip.strip())
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
