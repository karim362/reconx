"""Passive collection from all sources."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from reconx.sources import (
    crtsh, hackertarget, rapiddns, alienvault,
    urlscan, wayback, certspotter,
    chaos, anubis, mnemonic, securitytrails,
)
from reconx.utils.clean import clean_subdomain
from reconx.core.dns import dns_lookup

ALL_SOURCES = [
    crtsh, hackertarget, rapiddns, alienvault,
    urlscan, wayback, certspotter,
    chaos, anubis, mnemonic, securitytrails,
]


def collect(domain, wildcard=None, progress_cb=None):
    raw = set()
    with ThreadPoolExecutor(max_workers=len(ALL_SOURCES)) as ex:
        futures = {ex.submit(src.fetch, domain): src.NAME for src in ALL_SOURCES}
        for f in as_completed(futures):
            src_name = futures[f]
            try:
                cleaned = {c for c in (clean_subdomain(s, domain) for s in f.result()) if c}
                if wildcard:
                    cleaned = {c for c in cleaned if dns_lookup(c)[0] not in wildcard}
                raw.update(cleaned)
                if progress_cb:
                    progress_cb(src_name, len(cleaned))
            except Exception:
                if progress_cb:
                    progress_cb(src_name, 0)
    return raw
