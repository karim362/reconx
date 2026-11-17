"""CORS detector."""
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
