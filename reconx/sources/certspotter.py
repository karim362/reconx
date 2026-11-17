from reconx.core.session import http_get

NAME = "CertSpotter"

def fetch(domain):
    out = set()
    try:
        url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
               f"&include_subdomains=true&expand=dns_names")
        r = http_get(url, timeout=30)
        if r.status_code == 200:
            for e in r.json():
                for n in e.get("dns_names", []):
                    out.add(n.lower())
    except Exception:
        pass
    return out
