from reconx.core.session import http_get

NAME = "AlienVault"

def fetch(domain):
    out = set()
    try:
        r = http_get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
        if r.status_code == 200:
            for e in r.json().get("passive_dns", []):
                if "hostname" in e:
                    out.add(e["hostname"].lower())
    except Exception:
        pass
    return out
