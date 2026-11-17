from reconx.core.session import http_get

NAME = "ThreatCrowd"

def fetch(domain):
    out = set()
    try:
        r = http_get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}")
        if r.status_code == 200:
            for s in r.json().get("subdomains", []):
                out.add(s.lower())
    except Exception:
        pass
    return out
