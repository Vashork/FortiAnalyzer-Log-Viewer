import socket

_hostname_cache = {}

def resolve_hostname(ip: str) -> str:
    if ip in _hostname_cache:
        return _hostname_cache[ip]
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        hostname = ip
    _hostname_cache[ip] = hostname
    return hostname