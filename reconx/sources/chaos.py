from reconx.core.session import http_get
NAME = "Chaos"
def fetch(domain):
    out = set()
    try:
        r = http_get(f"https://dns.projectdiscovery.io/dns/{domain}/subdomains", timeout=20)
        if r.status_code == 200:
            for sub in r.json().get("subdomains", []):
                out.add(f"{sub}.{domain}".lower())
    except Exception:
        pass
    return out
