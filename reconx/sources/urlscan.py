from reconx.core.session import http_get

NAME = "URLScan"

def fetch(domain):
    out = set()
    try:
        r = http_get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000")
        if r.status_code == 200:
            for res in r.json().get("results", []):
                sub = res.get("page", {}).get("domain", "").lower()
                if sub:
                    out.add(sub)
    except Exception:
        pass
    return out
