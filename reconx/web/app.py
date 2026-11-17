"""ReconX Web Dashboard."""
import os, json, uuid, sqlite3, subprocess, threading
from pathlib import Path
from datetime import datetime
from flask import Flask, request, jsonify, Response, render_template

app = Flask(__name__)
HOME = Path.home() / "reconx"
OUTPUT = HOME / "output"
SCANS = {}

def _load_results(domain):
    out = OUTPUT / domain
    res = {"live": [], "hosts": [], "stats": {}, "html_report": None}
    live_file = out / f"{domain}_live.txt"
    if live_file.exists():
        res["live"] = [h for h in live_file.read_text().strip().split("\n") if h]
    db_file = out / f"{domain}.db"
    if db_file.exists():
        try:
            conn = sqlite3.connect(str(db_file))
            conn.row_factory = sqlite3.Row
            cols = {row[1] for row in conn.execute("PRAGMA table_info(hosts)").fetchall()}
            has_secrets = "secrets" in cols
            q = "SELECT host, ip, status, server, cdn, takeover, nuclei"
            if has_secrets:
                q += ", secrets"
            q += " FROM hosts"
            rows = conn.execute(q).fetchall()
            for r in rows:
                nuc = r["nuclei"]
                sec = r["secrets"] if has_secrets else "[]"
                res["hosts"].append({
                    "host": r["host"], "ip": r["ip"],
                    "status": r["status"], "server": r["server"],
                    "cdn": r["cdn"], "takeover": r["takeover"],
                    "nuclei": len(json.loads(nuc)) if nuc and nuc != "[]" else 0,
                    "secrets": len(json.loads(sec)) if sec and sec != "[]" else 0,
                })
            res["stats"] = {
                "live": len(res["live"]),
                "takeover": sum(1 for h in res["hosts"] if h["takeover"]),
                "nuclei": sum(h["nuclei"] for h in res["hosts"]),
                "secrets": sum(h["secrets"] for h in res["hosts"]),
            }
            conn.close()
        except Exception:
            pass
    html_p = out / f"{domain}_report.html"
    if html_p.exists():
        res["html_report"] = f"/report/{domain}"
    return res

def _runner(scan_id, domain, mode, flags, threads):
    s = SCANS[scan_id]
    s["status"] = "running"
    if mode == "fast":
        args = ["-d", domain, "--fast", "-t", str(threads)]
    elif mode == "full":
        args = ["-d", domain, "--all", "-t", str(threads)]
    else:
        args = ["-d", domain] + (flags.split() if flags else []) + ["-t", str(threads)]
    cmd = ["python", "-m", "reconx"] + args
    env = os.environ.copy(); env["PYTHONPATH"] = str(HOME)
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, env=env, cwd=str(HOME), bufsize=1,
                                errors="ignore")
        for line in proc.stdout:
            s["output"] += line
            if len(s["output"]) > 20000:
                s["output"] = s["output"][-20000:]
        proc.wait()
        s["status"] = "done" if proc.returncode == 0 else "failed"
    except Exception as e:
        s["output"] += f"\nERROR: {e}"
        s["status"] = "failed"
    s["ended"] = datetime.now().isoformat()
    s["result"] = _load_results(domain)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def start_scan():
    d = request.get_json() or {}
    domain = (d.get("domain") or "").strip().lower()
    domain = domain.replace("https://","").replace("http://","").split("/")[0]
    if not domain: return jsonify({"error":"domain required"}), 400
    scan_id = str(uuid.uuid4())[:8]
    SCANS[scan_id] = {
        "id": scan_id, "domain": domain, "mode": d.get("mode","fast"),
        "status": "starting", "output": "", "result": None,
        "started": datetime.now().isoformat(), "ended": None,
    }
    threading.Thread(target=_runner, daemon=True, args=(
        scan_id, domain, d.get("mode","fast"), d.get("flags",""), d.get("threads",15)
    )).start()
    return jsonify({"scan_id": scan_id})

@app.route("/api/scan/<sid>")
def scan_status(sid):
    if sid not in SCANS: return jsonify({"error":"not found"}), 404
    s = SCANS[sid]
    return jsonify({k: s[k] for k in ("id","domain","status","output","result")})

@app.route("/api/scans")
def list_scans():
    return jsonify([{"id":k,"domain":v["domain"],"status":v["status"]} for k,v in SCANS.items()])

@app.route("/report/<domain>")
def report(domain):
    p = OUTPUT / domain / f"{domain}_report.html"
    if not p.exists(): return "Report not found", 404
    return Response(p.read_text(encoding="utf-8"), mimetype="text/html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False, threaded=True)
