import re
from reconx.core.session import http_get

NAME = "RapidDNS"

def fetch(domain):
    out = set()
    try:
        r = http_get(f"https://rapiddns.io/subdomain/{domain}?full=1")
        if r.status_code == 200:
            out.update(re.findall(
                r"<td>([a-z0-9\.\-]+\." + re.escape(domain) + r")</td>",
                r.text.lower()))
    except Exception:
        pass
    return out
