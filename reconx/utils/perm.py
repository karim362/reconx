"""Smart permutations — only high-value keywords."""

# فقط الكلمات ذات القيمة العالية (بدل 30)
HIGH_VALUE = [
    "api", "admin", "dev", "stg", "test", "stage", "qa", "uat",
    "internal", "private", "backup", "old",
]

MEDIUM_VALUE = [
    "app", "portal", "dashboard", "monitor",
]

def generate(subs, domain, mode="high"):
    """
    mode='high'   → فقط high-value (10 keywords, ~300 perms for 30 subs)
    mode='medium' → high + medium (~400 perms)
    mode='all'    → كل الكلمات (default --all فقط)
    """
    if mode == "high":
        words = HIGH_VALUE
    elif mode == "medium":
        words = HIGH_VALUE + MEDIUM_VALUE
    else:
        words = HIGH_VALUE + MEDIUM_VALUE + [
            "cdn", "static", "img", "mail", "vpn", "blog", "shop",
            "prod", "beta", "demo", "new", "ci", "git", "jenkins",
            "grafana", "kibana", "lab", "v2", "v3",
        ]

    out = set()
    for sub in subs:
        prefix = sub.replace("." + domain, "").split(".")[0]
        if not prefix or len(prefix) > 30:
            continue
        # فقط prefixes حقيقية (ليست permutations سابقة)
        if any(prefix.startswith(w + "-") or prefix.startswith(w) and len(prefix) > len(w) and prefix[len(w)] == "-" for w in words):
            continue
        for w in words:
            out.add(f"{w}-{prefix}.{domain}")
            out.add(f"{prefix}-{w}.{domain}")

    # كلمات منفردة
    for w in words:
        out.add(f"{w}.{domain}")

    return out
