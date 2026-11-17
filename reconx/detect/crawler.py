"""Enhanced BFS crawler — endpoints + JS + forms + parameters."""
import re
from urllib.parse import urlparse, urljoin, parse_qs
from reconx.core.session import http_get

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

INTERESTING = re.compile(
    r"(admin|api|login|dashboard|upload|config|debug|test|dev|"
    r"backup|\.git|\.env|swagger|graphql|\.json|\.xml|\.bak|\.old|"
    r"phpmyadmin|wp-admin|\.htaccess|\.svn|\.aws|\.dockerfile|"
    r"internal|private|secret|token|key|password)", re.I
)

STATIC_EXT = re.compile(
    r"\.(css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|mp4|mp3|webm|"
    r"pdf|zip|tar|gz)$", re.I
)


def _is_same_domain(url, domain):
    try:
        return urlparse(url).netloc == domain
    except Exception:
        return False


def _extract_links(html, base):
    links = set()
    try:
        soup = BeautifulSoup(html, "lxml")
        for a in soup.find_all("a", href=True):
            links.add(urljoin(base, a["href"]))
        for f in soup.find_all("form", action=True):
            links.add(urljoin(base, f["action"]))
        for s in soup.find_all("script", src=True):
            links.add(urljoin(base, s["src"]))
        for l in soup.find_all("link", href=True):
            links.add(urljoin(base, l["href"]))
        for m in re.finditer(r'["\'](/[\w\-/\.]{3,100})["\']', html, re.I):
            path = m.group(1)
            if not any(path.endswith(ext) for ext in [".css", ".js", ".png", ".jpg"]):
                links.add(urljoin(base, path))
        for m in re.finditer(r'https?://[^\s"\'<>]+', html):
            links.add(m.group(0))
    except Exception:
        pass
    return links


def crawl(base_url, max_pages=20, depth=2, timeout=5):
    if not HAS_BS4:
        return [], [], [], []
    domain = urlparse(base_url).netloc
    seen = set()
    found_paths = set()
    forms = set()
    params = set()
    queue = [(base_url, 0)]

    while queue and len(seen) < max_pages:
        url, d = queue.pop(0)
        if url in seen or d > depth or STATIC_EXT.search(url):
            continue
        seen.add(url)
        try:
            r = http_get(url, timeout=timeout, allow_redirects=True)
            if r.status_code != 200:
                continue
            ct = r.headers.get("Content-Type", "")
            if "text/html" not in ct and "javascript" not in ct:
                continue
            try:
                qs = parse_qs(urlparse(url).query)
                for k in qs:
                    params.add(k)
            except Exception:
                pass
            if "text/html" in ct:
                soup = BeautifulSoup(r.text, "lxml")
                for f in soup.find_all("form"):
                    action = f.get("action", "")
                    method = f.get("method", "GET").upper()
                    inputs = [i.get("name", "") for i in f.find_all("input") if i.get("name")]
                    if action or inputs:
                        forms.add(f"{method} {urljoin(url, action)} [{','.join(inputs)}]")
            links = _extract_links(r.text, url)
            for link in links:
                if not _is_same_domain(link, domain):
                    continue
                path = urlparse(link).path
                if path and path != "/":
                    found_paths.add(path)
                if d < depth and link not in seen:
                    queue.append((link, d + 1))
        except Exception:
            continue

    interesting = [p for p in found_paths if INTERESTING.search(p)]
    other = [p for p in found_paths if not INTERESTING.search(p)]
    return (list(dict.fromkeys(interesting)),
            list(dict.fromkeys(other)), list(forms), list(params))
