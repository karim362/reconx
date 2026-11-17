"""DNS bruteforce — try wordlist against domain."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from reconx.core.dns import dns_lookup
from reconx.core.config import BASE_DIR


WORDLIST_PATH = BASE_DIR / "wordlists" / "subs-1000.txt"


def _load_wordlist(path):
    if not Path(path).exists():
        return []
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def bruteforce(domain, wordlist=None, threads=50, progress_cb=None):
    words = wordlist or _load_wordlist(WORDLIST_PATH)
    if not words:
        return set()

    total = len(words)
    found = set()
    done = 0

    def _check(word):
        sub = f"{word}.{domain}"
        ip, cname = dns_lookup(sub)
        return sub, ip

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_check, w): w for w in words}
        for f in as_completed(futures):
            done += 1
            try:
                sub, ip = f.result()
                if ip:
                    found.add(sub)
            except Exception:
                pass
            if progress_cb and done % 50 == 0:
                progress_cb(done, total, len(found))

    if progress_cb:
        progress_cb(done, total, len(found))
    return found
