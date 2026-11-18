from reconx.core.session import http_get
NAME = "Mnemonic"
def fetch(domain):
    out = set()
    try:
        r = http_get(f"https://api.mnemonic.no/pdns/v3/{domain}?limit=1000", timeout=20)
        if r.status_code == 200:
            for item in r.json().get("data", []):
                v = item.get("query", "")
                if v and v.endswith(domain):
                    out.add(v.lower())
    except Exception:
        pass
    return out
