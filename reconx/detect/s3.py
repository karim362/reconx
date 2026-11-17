"""S3 bucket detection."""
import re
from reconx.core.session import http_get
PATS = [r"([a-z0-9.\-]+)\.s3\.amazonaws\.com",
        r"s3\.amazonaws\.com/([a-z0-9.\-]+)",
        r"s3\.([a-z0-9\-]+)\.amazonaws\.com/([a-z0-9.\-]+)"]

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
