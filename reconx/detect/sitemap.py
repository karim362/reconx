import re
from reconx.core.session import http_get


def fetch(base_url):
    urls = []
    try:
        r = http_get(f"{base_url}/sitemap.xml", timeout=8)
        if r.status_code == 200:
            for m in re.findall(r"<loc>([^<]+)</loc>", r.text):
                urls.append(m.strip())
                if len(urls) >= 20:
                    break
    except Exception:
        pass
    return urls
