"""YAML config loader."""
from pathlib import Path
try:
    import yaml; HAS_YAML = True
except ImportError: HAS_YAML = False

DEFAULTS = {
    "target": "", "threads": 15,
    "scan": {"bruteforce": False, "permutations": "high", "crawl": False, "nuclei": False},
    "detect": {"secrets": True, "cors": True, "js": True, "s3": True},
    "notifications": {"telegram": {"enabled": False, "token": "", "chat_id": ""}},
}

def load(path):
    if not HAS_YAML: return DEFAULTS
    p = Path(path)
    if not p.exists(): return DEFAULTS
    try:
        with open(p) as f: cfg = yaml.safe_load(f) or {}
        merged = dict(DEFAULTS); merged.update(cfg); return merged
    except Exception: return DEFAULTS

def save(path, cfg):
    if not HAS_YAML: return False
    with open(path, "w") as f: yaml.safe_dump(cfg, f, default_flow_style=False)
    return True
