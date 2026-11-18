from reconx.core.session import http_get
NAME = "Anubis"
def fetch(domain):
    out = set()
    try:
        r = http_get(f"https://jldc.me/anubis/subdomains/{domain}", timeout=20)
        if r.status_code == 200:
            for s in r.json() or []:
                if isinstance(s, str):
                    out.add(s.lower())
    except Exception:
        pass
    return out
