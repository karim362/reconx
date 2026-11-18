"""JS analysis - Production Grade."""
import re
from typing import List, Tuple, Set
from urllib.parse import urljoin
from reconx.core.session import http_get

# تعابير منتظمة مجمعة ومحسنة للأداء
JS_PATTERNS = [
    re.compile(r'["\x27](/api/[\w\-/\.]+)["\x27]'),
    re.compile(r'["\x27](/v[0-9]/[\w\-/\.]+)["\x27]'),
    re.compile(r'fetch\s*\(\s*["\x27]([^"\x27]+)["\x27]'),
    re.compile(r'axios\.[a-z]+\s*\(\s*["\x27]([^"\x27]+)["\x27]'),
]

URL_PATTERN = re.compile(r'https?://[a-zA-Z0-9\.\-/_?=&#%]+')
SCRIPT_TAG_PATTERN = re.compile(r'<script[^>]+src=[\x22\x27]([^\x22\x27]+)', re.I)


def extract_urls(html: str, base: str) -> List[str]:
    """استخراج روابط ملفات الجافاسكريبت وتحويلها إلى روابط مطلقة بأمان."""
    if not html:
        return []
    
    urls = []
    for m in SCRIPT_TAG_PATTERN.findall(html):
        m_str = m.strip()
        if m_str:
            try:
                absolute_url = urljoin(base, m_str)
                urls.append(absolute_url)
            except Exception:
                continue
    return urls[:20]


def analyze(urls: List[str], max_js: int = 10) -> Tuple[List[str], List[str]]:
    """تحليل ملفات الجافاسكريبت لاستخراج نقاط النهاية (Endpoints) والروابط الخارجية بدقة."""
    eps: Set[str] = set()
    exts: Set[str] = set()

    if not urls:
        return [], []

    for u in urls[:max_js]:
        try:
            r = http_get(u, timeout=6)
            if not r or r.status_code != 200 or not r.text:
                continue

            text = r.text

            # استخراج الـ Endpoints الداخلية باستخدام الأنماط المحسنة
            for pat in JS_PATTERNS:
                for m in pat.findall(text):
                    if isinstance(m, tuple):
                        m = m[0]
                    clean_m = m.strip()
                    if clean_m.startswith("/") and len(clean_m) < 200:
                        eps.add(clean_m)

            # استخراج الروابط الخارجية
            for m in URL_PATTERN.findall(text):
                clean_m = m.strip()
                if len(clean_m) < 250:
                    exts.add(clean_m)

        except Exception:
            continue

    return list(eps)[:50], list(exts)[:30]
