import re
from reconx.core.session import http_get


def fetch(base_url):
    paths = []
    try:
        r = http_get(f"{base_url}/robots.txt", timeout=6)
        if r.status_code == 200 and "text" in r.headers.get("Content-Type", ""):
            for line in r.text.splitlines():
                m = re.match(r"^\s*(Disallow|Allow)\s*:\s*(\S+)", line, re.I)
                if m and m.group(2) not in ("/", ""):
                    paths.append(m.group(2))
    except Exception:
        pass
    return paths[:30]
