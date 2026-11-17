"""Shared HTTP session with retries and UA rotation."""
import random
import threading
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from reconx.core.config import UA_POOL, HTTP_TIMEOUT, HTTP_RETRIES

requests.packages.urllib3.disable_warnings()

_LOCK = threading.Lock()
_SESSION = None


def get_session():
    global _SESSION
    if _SESSION is None:
        s = requests.Session()
        retries = Retry(total=HTTP_RETRIES, backoff_factor=0.4,
                        status_forcelist=[429, 500, 502, 503, 504],
                        allowed_methods=["GET"])
        s.mount("https://", HTTPAdapter(max_retries=retries, pool_maxsize=50))
        s.mount("http://", HTTPAdapter(max_retries=retries, pool_maxsize=50))
        _SESSION = s
    return _SESSION


def http_get(url, **kwargs):
    session = get_session()
    with _LOCK:
        session.headers["User-Agent"] = random.choice(UA_POOL)
    kwargs.setdefault("timeout", HTTP_TIMEOUT)
    kwargs.setdefault("verify", False)
    return session.get(url, **kwargs)
