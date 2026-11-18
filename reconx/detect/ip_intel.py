"""IP intel via ip-api.com."""
import requests

CACHE = {}

def lookup(ip):
    if not ip:
        return None
    if ip in CACHE:
        return CACHE[ip]
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}",
                         params={"fields": "status,country,countryCode,isp,org,as"},
                         timeout=5)
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                res = {
                    "country": d.get("country", ""),
                    "country_code": d.get("countryCode", ""),
                    "isp": d.get("isp", ""),
                    "asn": (d.get("as") or "").split()[0],
                    "org": d.get("org", ""),
                }
                CACHE[ip] = res
                return res
    except Exception:
        pass
    CACHE[ip] = None
    return None
