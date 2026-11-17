from reconx.core.config import PERM_WORDS


def generate(subs, domain):
    """Generate permutations from existing subdomains."""
    out = set()
    for sub in subs:
        prefix = sub.replace("." + domain, "").split(".")[0]
        if not prefix or len(prefix) > 30:
            continue
        for p in PERM_WORDS:
            out.add(f"{p}-{prefix}.{domain}")
            out.add(f"{prefix}-{p}.{domain}")
            out.add(f"{p}{prefix}.{domain}")
    for p in PERM_WORDS:
        out.add(f"{p}.{domain}")
    return out
