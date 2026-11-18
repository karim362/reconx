"""Advanced wrapper module for external recon tools (Arjun, ffuf, etc.)."""
import subprocess
import shutil
from pathlib import Path

def run_arjun(target_url, output_path):
    """Run Arjun for hidden parameter discovery if available."""
    if not shutil.which("arjun"):
        return False, "arjun not installed"
    try:
        cmd = ["arjun", "-u", target_url, "-oJ", str(output_path)]
        subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return True, str(output_path)
    except Exception as e:
        return False, str(e)

def run_ffuf(target_url, wordlist_path, output_path):
    """Run ffuf for API/path fuzzing if available."""
    if not shutil.which("ffuf"):
        return False, "ffuf not installed"
    try:
        url_target = f"{target_url}/FUZZ"
        cmd = ["ffuf", "-u", url_target, "-w", wordlist_path, "-o", str(output_path), "-of", "json", "-s"]
        subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        return True, str(output_path)
    except Exception as e:
        return False, str(e)
