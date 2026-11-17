CDN_SIGNATURES = {
    "cloudflare": ["cloudflare", "cf-ray"],
    "akamai":     ["akamai", "akamaighost"],
    "fastly":     ["fastly", "varnish"],
    "cloudfront": ["cloudfront", "x-amz-cf"],
    "incapsula":  ["incap", "visid_incap"],
    "sucuri":     ["sucuri", "x-sucuri"],
    "bunnycdn":   ["bunnycdn"],
}


def detect(headers):
    blob = " ".join(f"{k.lower()}:{v.lower()}" for k, v in headers.items())
    for name, sigs in CDN_SIGNATURES.items():
        for s in sigs:
            if s in blob:
                return name
    return None
