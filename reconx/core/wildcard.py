"""Enhanced wildcard DNS detection & filtering."""
import random
import socket


def detect(domain, samples=3):
    """
    Return dict:
      - 'ips': set of wildcard IPs (empty if no wildcard)
      - 'status_codes': set of httpx status codes (if wildcard detected)
      - 'is_wildcard': bool
    """
    ips = set()
    for _ in range(samples):
        fake = f"nx-{random.randint(10**8, 10**9)}-{random.randint(10**8, 10**9)}.{domain}"
        try:
            for r in socket.getaddrinfo(fake, None):
                ips.add(r[4][0])
        except socket.gaierror:
            pass
    return {
        "ips": ips,
        "is_wildcard": len(ips) > 0,
    }


def is_valid_host(host, wildcard_ips, wildcard_cnames=None):
    """Check if host resolves to real IP (not wildcard)."""
    try:
        ips = {r[4][0] for r in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        return False
    if wildcard_ips and ips.issubset(wildcard_ips):
        return False
    return True
