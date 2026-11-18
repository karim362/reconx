"""Shared HTTP session with thread-safe retries and UA rotation - Production Grade."""
import random
import threading
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from reconx.core.config import UA_POOL, HTTP_TIMEOUT, HTTP_RETRIES

requests.packages.urllib3.disable_warnings()

class ThreadSafeSession:
    """جلسة HTTP آمنة للخيوط المتعددة ومتعددة الاستخدامات بدون قفل عام مخنق للأداء."""
    def __init__(self):
        self._local = threading.local()

    def get_session(self) -> requests.Session:
        if not hasattr(self._local, "session"):
            s = requests.Session()
            # إعداد نظام إعادة المحاولة مع مراعاة العشوائية (Jitter)
            retries = Retry(
                total=HTTP_RETRIES,
                backoff_factor=0.6,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["GET", "POST", "HEAD"],
                raise_on_status=False,
                respect_retry_after_header=True
            )
            adapter = HTTPAdapter(max_retries=retries, pool_maxsize=100, pool_block=False)
            s.mount("https://", adapter)
            s.mount("http://", adapter)
            self._local.session = s
        return self._local.session

# تهيئة الجلسة العامة للخيوط
_SESSION_MANAGER = ThreadSafeSession()

def http_get(url: str, **kwargs) -> requests.Response:
    """تنفيذ طلب GET بشكل آمن، سريع، وبتدوير عشوائي لـ User-Agent بدون قفل عام."""
    session = _SESSION_MANAGER.get_session()
    
    # تعيين User-Agent محلياً لل thread الح الحالي دون قفل عام يبطئ البرنامج
    headers = kwargs.get("headers", {})
    if UA_POOL:
        headers["User-Agent"] = random.choice(UA_POOL)
    kwargs["headers"] = headers

    kwargs.setdefault("timeout", HTTP_TIMEOUT)
    kwargs.setdefault("verify", False)

    try:
        response = session.get(url, **kwargs)
        return response
    except Exception as e:
        # إرجاع استجابة فارغة أو معالجة الخطأ بصمت حسب حاجة الاسكانر
        raise e
