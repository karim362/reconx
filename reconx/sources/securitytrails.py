from reconx.core.session import http_get
NAME = "SecurityTrails"
def fetch(domain):
    out = set()
    try:
        r = http_get(f"https://securitytrails.com/api/v1/domain/{domain}/subdomains", timeout=15)
        if r.status_code == 200:
            for sub in r.json().get("subdomains", []):
                if isinstance(sub, str):
                    out.add(f"{sub}.{domain}".lower())
    except Exception:
        pass
    return out
