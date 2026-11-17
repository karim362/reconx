#!/usr/bin/env python3
"""Install all 10 professional features."""
import sys
from pathlib import Path

BASE = Path.home() / "reconx"
if not BASE.exists():
    print("❌ ~/reconx not found"); sys.exit(1)

files = {}

files["reconx/detect/soft404.py"] = '''"""Soft 404 detector."""
import hashlib, random, re
from reconx.core.session import http_get

class Soft404Detector:
    def __init__(self, domain):
        self.domain = domain
        self.fingerprint = None
        self.enabled = False

    def build(self):
        fake = f"soft404test-{random.randint(10**8,10**9)}.{self.domain}"
        for scheme in ("https", "http"):
            try:
                r = http_get(f"{scheme}://{fake}", timeout=5, allow_redirects=True)
                body = r.text or ""
                m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I|re.S)
                self.fingerprint = {"status": r.status_code, "length": len(body),
                    "title": m.group(1).strip()[:100] if m else "",
                    "hash": hashlib.md5(body.encode("utf-8","ignore")).hexdigest()}
                self.enabled = True
                return True
            except Exception:
                continue
        return False

    def is_soft404(self, status, length, title, body_hash):
        if not self.enabled: return False
        fp = self.fingerprint
        if status != fp["status"]: return False
        if fp["length"] > 0 and abs(length - fp["length"]) / fp["length"] < 0.05:
            if title == fp["title"] or body_hash == fp["hash"]: return True
        return False
'''

files["reconx/detect/status.py"] = '''"""Status categorization."""
CATS = {200:"ok",201:"ok",204:"ok",301:"redirect",302:"redirect",307:"redirect",308:"redirect",
    400:"bad",401:"protected",403:"protected",405:"bad",429:"ratelimit",
    404:"notfound",410:"notfound",500:"error",502:"error",503:"error",504:"error"}
INTERESTING = {"protected","error","redirect"}

def categorize(s):
    return CATS.get(s, "other") if s else "unknown"

def is_interesting(s):
    return categorize(s) in INTERESTING

def emoji(s):
    return {"ok":"+","redirect":"~","protected":"!","error":"X","notfound":".","ratelimit":"~"}.get(categorize(s), "?")
'''

files["reconx/detect/secrets.py"] = '''"""Secrets scanner."""
import re
PATS = {
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "google_api": r"AIza[0-9A-Za-z\\-_]{35}",
    "github_token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "gitlab": r"glpat-[A-Za-z0-9_\\-]{20,}",
    "slack": r"xox[baprs]-[0-9A-Za-z\\-]{10,}",
    "slack_hook": r"https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    "stripe": r"sk_(?:live|test)_[0-9a-zA-Z]{24,}",
    "private_key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "jwt": r"eyJ[A-Za-z0-9_\\-]{10,}\\.eyJ[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]+",
    "db_url": r"(?:mysql|postgres|postgresql|mongodb|redis|amqp)://[^\\s\"'<>]+",
    "sendgrid": r"SG\\.[A-Za-z0-9_\\-]{20,}\\.[A-Za-z0-9_\\-]{20,}",
    "firebase": r"https://[a-z0-9\\-]+\\.firebaseio\\.com",
    "twilio": r"AC[a-z0-9]{32}",
}
SENSITIVE = [".env",".git/config",".aws/credentials","wp-config.php","backup.sql",".htpasswd"]

def scan(text):
    if not text: return []
    out, seen = [], set()
    for name, pat in PATS.items():
        try:
            for m in re.findall(pat, text)[:3]:
                if isinstance(m, tuple): m = m[0]
                k = (name, str(m)[:30])
                if k not in seen:
                    seen.add(k)
                    out.append({"type": name, "match": str(m)[:80]})
        except Exception: continue
    return out[:20]
'''

files["reconx/detect/takeover.py"] = '''"""Subdomain takeover v2 - 40+ services."""
SERVICES = {
    "github.io":"There isn't a GitHub Pages site here",
    "herokuapp.com":"No such app","s3.amazonaws.com":"NoSuchBucket",
    "cloudfront.net":"Bad request","azurewebsites.net":"404 Web Site not found",
    "cloudapp.net":"404 Web Site not found","blob.core.windows.net":"BlobNotFound",
    "azurestaticapps.net":"404","shopify.com":"Sorry, this shop is currently unavailable",
    "myshopify.com":"Sorry, this shop is currently unavailable",
    "tumblr.com":"Whatever you were looking for doesn't currently exist",
    "wordpress.com":"Do you want to register","ghost.io":"Domain error",
    "surge.sh":"project not found","bitbucket.io":"Repository not found",
    "zendesk.com":"Help Center Closed","readme.io":"Project doesnt exist",
    "readthedocs.io":"unknown to Read the Docs","fly.io":"404 Not Found",
    "netlify.app":"Not Found - Request ID","netlify.com":"Not Found - Request ID",
    "vercel.app":"The deployment could not be found","vercel.com":"The deployment could not be found",
    "webflow.io":"This site is not published","statuspage.io":"You are being redirected",
    "desk.com":"Sorry, this page is missing","fastly.net":"Fastly error: unknown domain",
    "ngrok.io":"Tunnel not found","ngrok-free.app":"Tunnel not found",
    "launchrock.com":"Site not found","cargo.site":"404 Not Found",
    "smugmug.com":"Page Not Found","tictail.com":"Sorry, this shop is currently unavailable",
    "smartjobboard.com":"Not Found","teamwork.com":"Oops - We didn't find your site",
    "helpscoutdocs.com":"No settings were found","feedpress.me":"The feed has not been found",
    "pantheon.io":"The gods are wise","unbounce.com":"The requested URL was not found",
    "myshopify.com":"Sorry, this shop is currently unavailable","ghost.io":"Domain error",
}

def detect(host, cname, body):
    if not cname or not body: return None
    cl, bl = cname.lower(), body.lower()
    for svc, fp in SERVICES.items():
        if svc in cl and fp.lower() in bl: return svc
    return None
'''

files["reconx/detect/s3.py"] = '''"""S3 bucket detection."""
import re
from reconx.core.session import http_get
PATS = [r"([a-z0-9.\\-]+)\\.s3\\.amazonaws\\.com",
        r"s3\\.amazonaws\\.com/([a-z0-9.\\-]+)",
        r"s3\\.([a-z0-9\\-]+)\\.amazonaws\\.com/([a-z0-9.\\-]+)"]

def extract(text):
    b = set()
    for p in PATS:
        for m in re.findall(p, text or "", re.I):
            if isinstance(m, tuple): m = m[0]
            if m and 3 <= len(m) <= 63: b.add(m)
    return b

def check(name):
    r = {"name": name, "public_list": False}
    try:
        resp = http_get(f"https://{name}.s3.amazonaws.com/", timeout=8)
        if resp.status_code == 200 and "<ListBucketResult" in resp.text:
            r["public_list"] = True
    except Exception: pass
    return r
'''

files["reconx/detect/js_analysis.py"] = '''"""JS analysis."""
import re
from urllib.parse import urljoin
from reconx.core.session import http_get
JS_PATS = [r"[\"'](/api/[\\w\\-/\\.]+)[\"']", r"[\"'](/v[0-9]/[\\w\\-/\\.]+)[\"']",
           r"fetch\\([\"']([^\"']+)[\"']", r"axios\\.[a-z]+\\([\"']([^\"']+)[\"']"]
URL_PAT = r"https?://[a-zA-Z0-9\\.\\-/_?=&#%]+"

def extract_urls(html, base):
    return [urljoin(base, m) for m in re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", html or "", re.I)][:15]

def analyze(urls, max_js=10):
    eps, exts = set(), set()
    for u in urls[:max_js]:
        try:
            r = http_get(u, timeout=6)
            if r.status_code != 200: continue
            for p in JS_PATS:
                for m in re.findall(p, r.text):
                    if m.startswith("/") and len(m) < 200: eps.add(m)
            for m in re.findall(URL_PAT, r.text):
                if len(m) < 200: exts.add(m)
        except Exception: continue
    return list(eps)[:50], list(exts)[:20]
'''

files["reconx/detect/cors.py"] = '''"""CORS detector."""
from reconx.core.session import http_get
EVIL = "https://evil-reconx-test.com"

def check(url):
    r = {"checked": False, "wildcard": False, "reflected": False, "credentials": False, "critical": False}
    try:
        resp = http_get(url, headers={"Origin": EVIL}, timeout=6)
        r["checked"] = True
        acao = resp.headers.get("Access-Control-Allow-Origin", "").strip()
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        r["wildcard"] = acao == "*"
        r["reflected"] = acao.lower() == EVIL.lower()
        r["credentials"] = acac == "true"
        r["critical"] = (r["reflected"] or r["wildcard"]) and r["credentials"]
    except Exception: pass
    return r
'''

files["reconx/output/diff.py"] = '''"""Diff reports."""
import json
from pathlib import Path

def save_snapshot(path, hosts):
    Path(path).write_text(json.dumps(sorted(hosts), indent=2))

def load_snapshot(path):
    p = Path(path)
    if not p.exists(): return []
    try: return json.loads(p.read_text())
    except Exception: return []

def compute(old, new):
    o, n = set(old), set(new)
    return {"new": sorted(n-o), "removed": sorted(o-n), "unchanged": sorted(o&n),
            "old_count": len(o), "new_count": len(n)}

def format_text(d):
    lines = []
    if d["new"]:
        lines.append(f"NEW ({len(d['new'])}):")
        for h in d["new"][:20]: lines.append(f"  + {h}")
    if d["removed"]:
        lines.append(f"REMOVED ({len(d['removed'])}):")
        for h in d["removed"][:20]: lines.append(f"  - {h}")
    return "\\n".join(lines) if lines else "No changes"
'''

files["reconx/notify/__init__.py"] = ""

files["reconx/notify/telegram.py"] = '''"""Telegram notifications."""
import requests

def send(token, chat_id, message):
    if not token or not chat_id: return False
    try:
        r = requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": message[:4000],
                  "parse_mode": "Markdown", "disable_web_page_preview": True}, timeout=10)
        return r.status_code == 200
    except Exception: return False

def format_result(domain, live, takeover, nuclei, secrets):
    msg = f"*ReconX: {domain}*\\n\\nLive: `{len(live)}`\\n"
    if takeover: msg += f"Takeover: *{len(takeover)}*\\n"
    if nuclei: msg += f"Nuclei: *{len(nuclei)}*\\n"
    if secrets: msg += f"Secrets: *{len(secrets)}*\\n"
    return msg
'''

files["reconx/core/yaml_config.py"] = '''"""YAML config loader."""
from pathlib import Path
try:
    import yaml; HAS_YAML = True
except ImportError: HAS_YAML = False

DEFAULTS = {
    "target": "", "threads": 15,
    "scan": {"bruteforce": False, "permutations": "high", "crawl": False, "nuclei": False},
    "detect": {"secrets": True, "cors": True, "js": True, "s3": True},
    "notifications": {"telegram": {"enabled": False, "token": "", "chat_id": ""}},
}

def load(path):
    if not HAS_YAML: return DEFAULTS
    p = Path(path)
    if not p.exists(): return DEFAULTS
    try:
        with open(p) as f: cfg = yaml.safe_load(f) or {}
        merged = dict(DEFAULTS); merged.update(cfg); return merged
    except Exception: return DEFAULTS

def save(path, cfg):
    if not HAS_YAML: return False
    with open(path, "w") as f: yaml.safe_dump(cfg, f, default_flow_style=False)
    return True
'''

print("[1/2] Writing 10 modules...")
for rel, content in files.items():
    p = BASE / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content.lstrip("\n"))
    print(f"  {rel}")

print("\n[2/2] Updating models.py...")
(BASE/"reconx/core/models.py").write_text('''"""Data models."""
from dataclasses import dataclass, field, asdict
from typing import Optional

@dataclass
class HostInfo:
    host: str
    ip: Optional[str] = None
    cname: Optional[str] = None
    status: Optional[int] = None
    server: str = "N/A"
    title: str = ""
    tech: list = field(default_factory=list)
    cdn: Optional[str] = None
    takeover: Optional[str] = None
    ports: list = field(default_factory=list)
    robots: list = field(default_factory=list)
    sitemap: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    screenshot: Optional[str] = None
    nuclei: list = field(default_factory=list)
    secrets: list = field(default_factory=list)
    cors: dict = field(default_factory=dict)
    js_endpoints: list = field(default_factory=list)
    s3_buckets: list = field(default_factory=list)
    status_category: str = "unknown"
    soft404: bool = False

    def to_dict(self):
        return asdict(self)
''')
print("  reconx/core/models.py")

print("\n=== MODULES INSTALLED ===")
print("Next: run fix_cli.py (provided next)")
