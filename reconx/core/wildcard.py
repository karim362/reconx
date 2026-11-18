"""Enhanced wildcard DNS detection & filtering using DoH - Production Grade."""
import random
from typing import Dict, Set, Optional
from reconx.core.dns import _doh_lookup

def detect(domain: str, samples: int = 3) -> Dict[str, any]:
    """كشف نطاقات الـ Wildcard بدقة باستخدام استعلامات DoH متعددة العينات."""
    if not domain:
        return {"ips": set(), "is_wildcard": False}

    domain = domain.strip().lower()
    ips: Set[str] = set()

    for _ in range(samples):
        fake = f"nx-{random.randint(10**8, 10**9)}-{random.randint(10**8, 10**9)}.{domain}"
        try:
            resolved_ips = _doh_lookup(fake, "A")
            for ip in resolved_ips:
                if ip:
                    ips.add(ip)
        except Exception:
            continue

    return {
        "ips": ips,
        "is_wildcard": len(ips) > 0,
    }


def is_valid_host(host: str, wildcard_ips: Optional[Set[str]], wildcard_cnames: Optional[Set[str]] = None) -> bool:
    """التحقق مما إذا كان النطاق حقيقياً ولا يتبع لـ Wildcard DNS."""
    if not host:
        return False
    
    host = host.strip().lower()
    try:
        resolved_ips = _doh_lookup(host, "A")
        if not resolved_ips:
            return False

        # إذا كانت جميع الأيونات الناتجة مطابقة لعناوين الـ Wildcard، فهو نطاق وهمي
        if wildcard_ips and set(resolved_ips).issubset(wildcard_ips):
            return False

        return True
    except Exception:
        return False
