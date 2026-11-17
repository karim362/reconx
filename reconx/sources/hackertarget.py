from reconx.core.session import http_get

NAME = "HackerTarget"

def fetch(domain):
    out = set()
    try:
        r = http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        if r.status_code == 200 and "API count exceeded" not in r.text:
            for line in r.text.splitlines():
                if "," in line:
                    out.add(line.split(",")[0].strip())
    except Exception:
        pass
    return out
