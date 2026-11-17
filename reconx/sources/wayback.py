import re
from reconx.core.session import http_get

NAME = "Wayback"

def fetch(domain):
    out = set()
    try:
        url = (f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
               f"&output=json&collapse=urlkey&fl=original&limit=1000")
        r = http_get(url, timeout=20)
        if r.status_code == 200:
            for row in r.json()[1:]:
                m = re.match(r"https?://([^/:]+)", row[0])
                if m:
                    out.add(m.group(1).lower())
    except Exception:
        pass
    return out
