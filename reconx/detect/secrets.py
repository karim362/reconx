"""Secrets scanner - Production Grade."""
import re
from typing import List, Dict, Any

# تعابير منتظمة منقحة ومختبرة لتقليل النتائج الكاذبة (False Positives)
PATTERNS = {
    "aws_key": re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
    "google_api": re.compile(r'\b(AIza[0-9A-Za-z\-_]{35})\b'),
    "github_token": re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{36,})\b'),
    "gitlab": re.compile(r'\b(glpat-[A-Za-z0-9_\-]{20,})\b'),
    "slack": re.compile(r'\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b'),
    "slack_hook": re.compile(r'(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)'),
    "stripe": re.compile(r'\b(sk_(?:live|test)_[0-9a-zA-Z]{24,})\b'),
    "private_key": re.compile(r'(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)'),
    "jwt": re.compile(r'\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+)\b'),
    "db_url": re.compile(r'((?:mysql|postgres|postgresql|mongodb|redis|amqp)://[^\s\x22\x27<>]+)'),
    "sendgrid": re.compile(r'\b(SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})\b'),
    "firebase": re.compile(r'(https://[a-z0-9\-]+\.firebaseio\.com)'),
    "twilio": re.compile(r'\b(AC[a-z0-9]{32})\b'),
}

SENSITIVE_FILES = [".env", ".git/config", ".aws/credentials", "wp-config.php", "backup.sql", ".htpasswd"]

def scan(text: str) -> List[Dict[str, Any]]:
    """فحص النص بدقة لاستخراج المفاتيح السرية مع منع التكرار وضمان الأداء."""
    if not text or not isinstance(text, str):
        return []

    out = []
    seen = set()

    for name, pat in PATTERNS.items():
        try:
            matches = pat.findall(text)
            for m in matches[:5]: # الحد الأقصى لكل نوع لتجنب الضغط
                if isinstance(m, tuple):
                    m = m[0]
                
                # تطهير وتحقق من طول النطاق
                match_str = str(m).strip()
                if not match_str:
                    continue

                key_tuple = (name, match_str)
                if key_tuple not in seen:
                    seen.add(key_tuple)
                    out.append({
                        "type": name,
                        "match": match_str[:100] # حفظ تطابق آمن بدون اقتصار مخل
                    })
        except Exception:
            continue

    return out[:25]
