"""Soft 404 detector."""
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
