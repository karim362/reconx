"""JS analysis."""
import re
from urllib.parse import urljoin
from reconx.core.session import http_get

JS_PATS = [
    r'["\x27](/api/[\w\-/\.]+)["\x27]',
    r'["\x27](/v[0-9]/[\w\-/\.]+)["\x27]',
    r'fetch\(["\x27]([^"\x27]+)["\x27]',
    r'axios\.[a-z]+\(["\x27]([^"\x27]+)["\x27]',
]
URL_PAT = r"https?://[a-zA-Z0-9\.\-/_?=&#%]+"


def extract_urls(html, base):
    return [
        urljoin(base, m)
        for m in re.findall(r"<script[^>]+src=[\x22\x27]([^\x22\x27]+)", html or "", re.I)
    ][:15]


def analyze(urls, max_js=10):
    eps, exts = set(), set()
    for u in urls[:max_js]:
        try:
            r = http_get(u, timeout=6)
            if r.status_code != 200:
                continue
            for p in JS_PATS:
                for m in re.findall(p, r.text):
                    if m.startswith("/") and len(m) < 200:
                        eps.add(m)
            for m in re.findall(URL_PAT, r.text):
                if len(m) < 200:
                    exts.add(m)
        except Exception:
            continue
    return list(eps)[:50], list(exts)[:20]
