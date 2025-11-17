# utils/network.py

import socket
import ipaddress
from typing import List, Tuple

# Кэш для разрешения имён
_hostname_cache = {}


def resolve_hostname(ip: str) -> str:
    """Разрешает PTR-запись для IP. Возвращает hostname или сам IP, если не найден."""
    if ip in _hostname_cache:
        return _hostname_cache[ip]
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        hostname = ip
    _hostname_cache[ip] = hostname
    return hostname


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


def ip_in_cidr_or_range(ip_str: str, spec: str) -> bool:
    """Проверяет, входит ли IP в CIDR или диапазон вида 'start-end'."""
    ip = ipaddress.IPv4Address(ip_str)
    spec = spec.strip()

    if "/" in spec:
        network = ipaddress.IPv4Network(spec, strict=False)
        return ip in network
    elif "-" in spec:
        start_str, end_str = spec.split("-", 1)
        start = ipaddress.IPv4Address(start_str.strip())
        end = ipaddress.IPv4Address(end_str.strip())
        return int(start) <= int(ip) <= int(end)
    else:
        return ip_str == spec


def normalize_vlan_key(s: str) -> str:
    return s.strip().lower()


def load_vlans(path: str) -> List[Tuple[str, str, str]]:
    vlans: List[Tuple[str, str, str]] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    cidr_or_range = parts[0]
                    vlan_id = parts[1]
                    vlan_name = " ".join(parts[2:])
                    vlans.append((cidr_or_range, vlan_id, vlan_name))
    except FileNotFoundError:
        # Обрабатывается в main.py
        pass
    return vlans


def load_machines(path: str) -> List[str]:
    """Загружает список целей из файла.

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

                # Похоже на hostname — резолвим
                try:
                    resolved_ip = socket.gethostbyname(line)
                    ips.append(resolved_ip)
                except socket.gaierror:
                    print(f"⚠️ Cannot resolve hostname in machines file: {line}")
    except FileNotFoundError:
        return []

    return ips
