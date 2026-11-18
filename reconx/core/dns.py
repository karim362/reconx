"""DNS with DoH (bypasses ISP hijacking)."""
import os
import socket
from reconx.core.config import DNS_TIMEOUT

DOH_URL = "https://cloudflare-dns.com/dns-query"
HAS_DNS = True


def _doh_lookup(host, rtype="A"):
    """Resolve via Cloudflare DoH."""
    import requests
    try:
        r = requests.get(
            DOH_URL,
            params={"name": host, "type": rtype},
            headers={"accept": "application/dns-json"},
            timeout=DNS_TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            answers = data.get("Answer", [])
            return [a["data"] for a in answers if a.get("type") == (1 if rtype == "A" else 5)]
    except Exception:
        pass
    return []


def dns_lookup(host):
    """Return (ip, cname) or (None, None) using DoH."""
    ips = _doh_lookup(host, "A")
    if ips:
        cnames = _doh_lookup(host, "CNAME")
        cname = cnames[0].rstrip(".").lower() if cnames else None
        return ips[0], cname
    return None, None


def wildcard_ips(domain):
    """Detect wildcard DNS via DoH."""
    import random
    fake = f"nx-{random.randint(10**8, 10**9)}.{domain}"
    ips = set(_doh_lookup(fake, "A"))
    return ips if ips else None
