"""DNS over HTTPS (DoH) - Production Grade with Multi-Provider Failover and Caching."""
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
import requests
from reconx.core.config import DNS_TIMEOUT

# مزودو خدمة DoH متعددون لتجاوز الحظر والفشل (Failover)
DOH_ENDPOINTS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
    "https://dns.quad9.net:505/dns-query"
]

HAS_DNS = True
_CACHE_LOCK = threading.Lock()
_DNS_CACHE: Dict[str, List[Dict]] = {}

def _doh_lookup(host: str, rtype: str = "A") -> List[str]:
    """استعلام DNS عبر DoH مع دعم تعدد المزودين والتخزين المؤقت الآمن."""
    cache_key = f"{host}:{rtype}"
    with _CACHE_LOCK:
        if cache_key in _DNS_CACHE:
            return _DNS_CACHE[cache_key]

    endpoints = list(DOH_ENDPOINTS)
    random.shuffle(endpoints)

    results = []
    for doh_url in endpoints:
        try:
            headers = {"accept": "application/dns-json"}
            # اختلاف بنية الطلب بين Google وبقية المزودين
            if "dns.google" in doh_url:
                params = {"name": host, "type": rtype}
            else:
                params = {"name": host, "type": rtype}

            r = requests.get(
                doh_url,
                params=params,
                headers=headers,
                timeout=DNS_TIMEOUT,
                verify=False
            )

            if r.status_code == 200:
                data = r.json()
                answers = data.get("Answer", [])
                
                target_type = 1 if rtype == "A" else 5
                for a in answers:
                    if a.get("type") == target_type or a.get("type") == rtype:
                        val = str(a.get("data", "")).strip()
                        if val:
                            results.append(val)
                
                if results:
                    break
        except Exception:
            continue

    with _CACHE_LOCK:
        _DNS_CACHE[cache_key] = results

    return results

def dns_lookup(host: str) -> Tuple[Optional[str], Optional[str]]:
    """إرجاع (IP, CNAME) للنطاق المستهدف باستخدام DoH المحسن."""
    if not host:
        return None, None

    host = host.strip().lower()
    ips = _doh_lookup(host, "A")
    if not ips:
        # تجربة البحث عن CNAME مباشرة إذا لم يوجد A Record
        cnames = _doh_lookup(host, "CNAME")
        cname = cnames[0].rstrip(".").lower() if cnames else None
        return None, cname

    cnames = _doh_lookup(host, "CNAME")
    cname = cnames[0].rstrip(".").lower() if cnames else None
    
    return ips[0], cname

def wildcard_ips(domain: str) -> Optional[set]:
    """كشف النطاقات الوهمية (Wildcard DNS) بدقة لتصفية النتائج المزيفة."""
    if not domain:
        return None
    fake = f"nx-{random.randint(10**8, 10**9)}.{domain.strip().lower()}"
    ips = set(_doh_lookup(fake, "A"))
    return ips if ips else None

def dns_batch(hosts: List[str], max_workers: int = 25) -> Dict[str, Optional[str]]:
    """فحص دفعة من النطاقات بشكل متوازي وآمن (Batch DNS Resolution)."""
    result = {}
    if not hosts:
        return result

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_to_host = {ex.submit(dns_lookup, h): h for h in hosts}
        for future in as_completed(future_to_host):
            h = future_to_host[future]
            try:
                ip, _ = future.result()
                result[h] = ip
            except Exception:
                result[h] = None
    return result
