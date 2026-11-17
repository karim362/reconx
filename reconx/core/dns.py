"""DNS resolution with dnspython, socket fallback (Termux-safe)."""
import os
import socket
import random
from reconx.core.config import DNS_SERVERS, DNS_TIMEOUT

# ─────────────────────────────────────────────
# Termux compatibility: /etc/resolv.conf is missing.
# We must configure the resolver WITHOUT auto-loading it.
# ─────────────────────────────────────────────
def _build_resolver():
    try:
        import dns.resolver
    except ImportError:
        return None, False

    try:
        # configure=False → skip reading /etc/resolv.conf
        resolver = dns.resolver.Resolver(configure=False)
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        resolver.nameservers = DNS_SERVERS
        return resolver, True
    except Exception:
        # ultimate fallback: socket only
        return None, False


_RESOLVER, HAS_DNS = _build_resolver()


def dns_lookup(host):
    """Return (ip, cname) or (None, None)."""
    if _RESOLVER is not None:
        try:
            answers = _RESOLVER.resolve(host, "A")
            ip = str(answers[0])
            cname = None
            try:
                cn = _RESOLVER.resolve(host, "CNAME")
                cname = str(cn[0]).rstrip(".").lower()
            except Exception:
                pass
            return ip, cname
        except Exception:
            pass  # fallback to socket
    try:
        return socket.gethostbyname(host), None
    except Exception:
        return None, None


def wildcard_ips(domain):
    """Detect wildcard DNS. Return set of IPs or None."""
    fake = f"nx-{random.randint(10**8, 10**9)}.{domain}"
    ips = set()
    try:
        for r in socket.getaddrinfo(fake, None):
            ips.add(r[4][0])
    except socket.gaierror:
        return None
    return ips
