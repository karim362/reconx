"""Wrappers for external tools: httpx, nuclei."""
import os
import re
import json
import shutil
import subprocess
import random
import tempfile
from pathlib import Path

_GO_BIN = Path.home() / "go" / "bin"
_TEMPLATES = Path.home() / "nuclei-templates"


def tool_available(name):
    if shutil.which(name):
        return True
    go_bin = _GO_BIN / name
    return go_bin.exists() and os.access(go_bin, os.X_OK)


def _tool_path(name):
    p = shutil.which(name)
    if p:
        return p
    go_bin = _GO_BIN / name
    if go_bin.exists() and os.access(go_bin, os.X_OK):
        return str(go_bin)
    return None


def run_httpx(hosts, threads=10, timeout=180):
    if not tool_available("httpx") or not hosts:
        return {}
    tmp = Path(tempfile.gettempdir()) / f"httpx_{random.randint(1000, 9999)}.txt"
    tmp.write_text("\n".join(hosts))
    try:
        proc = subprocess.run(
            [_tool_path("httpx"), "-l", str(tmp), "-silent", "-json",
             "-title", "-tech-detect", "-status-code", "-web-server",
             "-cdn", "-no-color", "-timeout", "6",
             "-threads", str(threads), "-rate-limit", "50"],
            capture_output=True, text=True, timeout=timeout)
        results = {}
        for line in proc.stdout.splitlines():
            try:
                d = json.loads(line)
                host = d.get("input", "")
                results[host] = {
                    "status": d.get("status_code"),
                    "title": d.get("title", ""),
                    "tech": d.get("tech", []),
                    "cdn": d.get("cdn_name", ""),
                    "server": d.get("webserver", ""),
                    "url": d.get("url", ""),
                }
            except json.JSONDecodeError:
                continue
        return results
    except subprocess.TimeoutExpired:
        return {}
    finally:
        tmp.unlink(missing_ok=True)


NUCLEI_LINE_RE = re.compile(
    r"^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.+)$"
)


def run_nuclei(host, timeout=600):
    """Run nuclei, parse plain text output (Termux-friendly)."""
    if not tool_available("nuclei"):
        return []
    findings = []
    try:
        proc = subprocess.run(
            [_tool_path("nuclei"), "-u", f"https://{host}", "-silent",
             "-t", str(_TEMPLATES / "http" / "exposures"),
             "-t", str(_TEMPLATES / "http" / "misconfiguration"),
             "-t", str(_TEMPLATES / "http" / "technologies"),
             "-t", str(_TEMPLATES / "http" / "cves"),
             "-timeout", "5", "-retries", "1", "-no-color"],
            capture_output=True, text=True, timeout=timeout)
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            m = NUCLEI_LINE_RE.match(line)
            if m:
                findings.append({
                    "template": m.group(1),
                    "type": m.group(2),
                    "severity": m.group(3),
                    "matched": m.group(4).strip(),
                    "name": m.group(1),
                })
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    return findings
