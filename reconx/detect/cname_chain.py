"""CNAME chain detection."""
import requests
from reconx.core.dns import DNS_TIMEOUT

DOH_URL = "https://cloudflare-dns.com/dns-query"
CDN_PATTERNS = {
    "cloudflare": ["cloudflare", "cf-"],
    "akamai": ["akamai", "edgesuite"],
    "fastly": ["fastly"],
    "cloudfront": ["cloudfront"],
    "bunnycdn": ["b-cdn", "bunnycdn"],
    "azure": ["azureedge", "trafficmanager"],
    "aws": ["elb.amazonaws", "s3.amazonaws"],
    "google": ["googlehosted", "ghs.google"],
    "vercel": ["vercel"],
    "netlify": ["netlify"],
    "heroku": ["herokudns", "herokuapp"],
    "github": ["github.io"],
    "shopify": ["myshopify"],
    "sendgrid": ["sendgrid", "smtp2go"],
}


def chain(host):
    result = []
    cur = host
    for _ in range(5):
        try:
            r = requests.get(DOH_URL, params={"name": cur, "type": "CNAME"},
                             headers={"accept": "application/dns-json"},
                             timeout=DNS_TIMEOUT)
            if r.status_code != 200:
                break
            cname = None
            for a in r.json().get("Answer", []):
                if a.get("type") == 5:
                    cname = a["data"].rstrip(".").lower()
                    break
            if not cname or cname == cur:
                break
            result.append(cname)
            cur = cname
        except Exception:
            break
    return result


def detect_cdn_from_chain(ch):
    if not ch:
        return None
    blob = " ".join(ch).lower()
    for cdn, pats in CDN_PATTERNS.items():
        for p in pats:
            if p in blob:
                return cdn
    return None
