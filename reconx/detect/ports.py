import socket
from reconx.core.config import COMMON_PORTS


def scan(host, ports=None, timeout=1.2):
    """Scan common ports, return list of open ones."""
    ports = ports or COMMON_PORTS
    opened = []
    for p in ports:
        try:
            with socket.create_connection((host, p), timeout=timeout):
                opened.append(p)
        except Exception:
            pass
    return opened
