"""Secrets scanner."""
import re
PATS = {
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "google_api": r"AIza[0-9A-Za-z\-_]{35}",
    "github_token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "gitlab": r"glpat-[A-Za-z0-9_\-]{20,}",
    "slack": r"xox[baprs]-[0-9A-Za-z\-]{10,}",
    "slack_hook": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    "stripe": r"sk_(?:live|test)_[0-9a-zA-Z]{24,}",
    "private_key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "jwt": r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+",
    "db_url": r"(?:mysql|postgres|postgresql|mongodb|redis|amqp)://[^\s\x22\x27<>]+",
    "sendgrid": r"SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}",
    "firebase": r"https://[a-z0-9\-]+\.firebaseio\.com",
    "twilio": r"AC[a-z0-9]{32}",
}
SENSITIVE = [".env", ".git/config", ".aws/credentials", "wp-config.php", "backup.sql", ".htpasswd"]

def scan(text):
    if not text:
        return []
    out, seen = [], set()
    for name, pat in PATS.items():
        try:
            for m in re.findall(pat, text)[:3]:
                if isinstance(m, tuple):
                    m = m[0]
                k = (name, str(m)[:30])
                if k not in seen:
                    seen.add(k)
                    out.append({"type": name, "match": str(m)[:80]})
        except Exception:
            continue
    return out[:20]
