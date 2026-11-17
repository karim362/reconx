from reconx.core.session import http_get

NAME = "crt.sh"

def fetch(domain):
    out = set()
    try:
        r = http_get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=45)
        if r.status_code == 200:
            for e in r.json():
                for n in e.get("name_value", "").split("\n"):
                    out.add(n.strip().lower())
    except Exception:
        pass
    return out
