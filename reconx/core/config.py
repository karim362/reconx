"""Global configuration and constants."""
import os
from pathlib import Path

BASE_DIR = Path(os.environ.get("RECONX_HOME", Path.home() / "reconx"))
OUTPUT_DIR = BASE_DIR / "output"
LOGS_DIR = BASE_DIR / "logs"
CONFIG_DIR = BASE_DIR / "config"

for d in (OUTPUT_DIR, LOGS_DIR, CONFIG_DIR):
    d.mkdir(parents=True, exist_ok=True)

UA_POOL = [
    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]

HTTP_TIMEOUT = 12
HTTP_RETRIES = 2
DEFAULT_THREADS = 15
MAX_THREADS = 100
DNS_SERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
DNS_TIMEOUT = 3
COMMON_PORTS = [80, 443, 8080, 8443, 8000, 3000, 5000, 9000]

PERM_WORDS = [
    "dev", "stg", "stage", "test", "qa", "uat", "prod", "api", "admin",
    "portal", "app", "blog", "shop", "mail", "vpn", "cdn", "static",
    "img", "backup", "old", "new", "beta", "demo", "internal",
    "v2", "v3", "lab", "git", "jenkins", "ci", "monitor",
]
