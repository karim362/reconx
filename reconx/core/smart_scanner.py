"""
Smart batch scanner — progressive disclosure.
Runs in batches, sorts by likelihood, stops early if enough found.
"""
import time
from pathlib import Path


PERM_KEYWORDS = [
    "dev", "stg", "stage", "test", "qa", "uat", "prod", "api", "admin",
    "portal", "app", "blog", "shop", "mail", "vpn", "cdn", "static",
    "internal", "private", "secret", "backup", "old", "new", "beta",
    "demo", "monitor", "jenkins", "ci", "grafana", "kibana", "git",
]


def classify(hosts, domain):
    """
    Split hosts into 4 priority tiers:
    - tier0: real subdomains (from passive/brute, not permutations)
    - tier1: high-priority permutations (dev-api, api-dev, etc)
    - tier2: medium-priority (dev, test, staging alone)
    - tier3: everything else
    """
    tier0, tier1, tier2, tier3 = [], [], [], []

    for h in hosts:
        # extract prefix (subdomain part without domain)
        prefix = h.replace("." + domain, "")
        if not prefix or prefix == domain:
            tier0.append(h)
            continue

        parts = prefix.split(".")

        # tier0: no wildcard permutation pattern
        # A permutation looks like "dev-foo", "foo-dev", "devfoo"
        is_perm = False
        for kw in PERM_KEYWORDS:
            if prefix.startswith(kw + "-") or prefix.endswith("-" + kw):
                is_perm = True
                break
            if len(prefix) > len(kw) and prefix.startswith(kw) and prefix[len(kw)] != "-" and prefix[len(kw)] != ".":
                is_perm = True
                break

        if not is_perm:
            tier0.append(h)
        elif any(prefix.startswith(kw + "-") for kw in ["dev", "api", "admin", "test", "stg"]):
            tier1.append(h)
        elif any(prefix.startswith(kw + "-") for kw in PERM_KEYWORDS):
            tier2.append(h)
        else:
            tier3.append(h)

    return tier0, tier1, tier2, tier3


def scan_batches(hosts, domain, batch_fn, max_batches=4, min_live_per_batch=3):
    """
    Run batches progressively.
    batch_fn(hosts_subset) → dict of results {host: info}
    Returns: combined results dict
    """
    tier0, tier1, tier2, tier3 = classify(hosts, domain)
    tiers = [tier0, tier1, tier2, tier3]
    combined = {}
    stats = []

    for i, tier in enumerate(tiers[:max_batches]):
        if not tier:
            continue

        # limit per batch based on tier size
        batch_size = min(len(tier), 500 if i == 0 else 800)
        batch = tier[:batch_size]

        t0 = time.time()
        try:
            result = batch_fn(batch)
            elapsed = time.time() - t0
            combined.update(result)
            stats.append({
                "tier": i,
                "size": len(batch),
                "found": len(result),
                "elapsed": elapsed,
            })

            # early termination: if tier0/1 gave < 3 live, stop
            if i <= 1 and len(result) < min_live_per_batch:
                stats.append({"tier": "early_stop", "reason": f"tier{i} low yield"})
                break
        except Exception as e:
            stats.append({"tier": i, "error": str(e)})

    return combined, stats
