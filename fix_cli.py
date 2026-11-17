#!/usr/bin/env python3
"""Patch cli.py to integrate all 10 features."""
from pathlib import Path

path = Path.home() / "reconx" / "reconx" / "cli.py"
src = path.read_text()

# 1) imports
if "from reconx.detect import" in src and "soft404" not in src:
    src = src.replace(
        "from reconx.detect import cdn, tech, takeover, ports, robots, sitemap, crawler, external, bruteforce",
        "from reconx.detect import cdn, tech, takeover, ports, robots, sitemap, crawler, external, bruteforce, soft404, status, secrets, s3, js_analysis, cors\nfrom reconx.output import diff\nfrom reconx.notify import telegram"
    )

# 2) add new args
if '"--secrets"' not in src:
    src = src.replace(
        '    ap.add_argument("--no-sitemap", action="store_true")',
        '''    ap.add_argument("--no-sitemap", action="store_true")
    ap.add_argument("--secrets", action="store_true", help="Scan for API keys/tokens")
    ap.add_argument("--cors", action="store_true", help="CORS misconfig check")
    ap.add_argument("--js", action="store_true", help="Analyze JS files")
    ap.add_argument("--s3", action="store_true", help="S3 bucket detection")
    ap.add_argument("--soft404", action="store_true", help="Soft 404 filter (recommended)")
    ap.add_argument("--diff", action="store_true", help="Diff with last scan")
    ap.add_argument("--telegram-token", help="Telegram bot token")
    ap.add_argument("--telegram-chat", help="Telegram chat ID")'''
    )

# 3) --all enables new features
src = src.replace(
    "args.perm = args.crawl = args.nuclei = True\n        args.screenshots = args.httpx = args.brute = True",
    "args.perm = args.crawl = args.nuclei = True\n        args.screenshots = args.httpx = args.brute = True\n        args.secrets = args.cors = args.js = args.s3 = args.soft404 = True"
)

# 4) update probe_host to include new detections
old_probe = '''    if opts.get("nuclei") and base_url and info.status:
        info.nuclei = external.run_nuclei(host)

    return info'''

new_probe = '''    if opts.get("nuclei") and base_url and info.status:
        info.nuclei = external.run_nuclei(host)

    # NEW: status category
    info.status_category = status.categorize(info.status)

    # NEW: secrets scan
    if opts.get("secrets") and body:
        info.secrets = secrets.scan(body)

    # NEW: CORS check
    if opts.get("cors") and base_url:
        info.cors = cors.check(base_url)

    # NEW: JS analysis
    if opts.get("js") and base_url and body:
        js_urls = js_analysis.extract_urls(body, base_url)
        js_eps, js_ext = js_analysis.analyze(js_urls)
        info.js_endpoints = js_eps

    # NEW: S3 detection
    if opts.get("s3") and body:
        buckets = s3.extract(body)
        for b in list(buckets)[:3]:
            info.s3_buckets.append(s3.check(b))

    return info'''

if old_probe in src:
    src = src.replace(old_probe, new_probe)

# 5) build opts dict with new flags
old_opts = '''    opts = {
        "ports":   not args.no_ports and not args.fast,
        "robots":  not args.no_robots and not args.fast,
        "sitemap": not args.no_sitemap and not args.fast,
        "crawl":   args.crawl,
        "nuclei":  args.nuclei,
    }'''

new_opts = '''    opts = {
        "ports":   not args.no_ports and not args.fast,
        "robots":  not args.no_robots and not args.fast,
        "sitemap": not args.no_sitemap and not args.fast,
        "crawl":   args.crawl,
        "nuclei":  args.nuclei,
        "secrets": args.secrets,
        "cors":    args.cors,
        "js":      args.js,
        "s3":      args.s3,
    }'''

if old_opts in src:
    src = src.replace(old_opts, new_opts)

# 6) Add diff + telegram at end of recon_domain (before return live)
old_ret = '''    if live:
        console.print(results_table(live,
                                    show_nuclei=opts["nuclei"],
                                    show_screens=args.screenshots))
    return live'''

new_ret = '''    if live:
        console.print(results_table(live,
                                    show_nuclei=opts["nuclei"],
                                    show_screens=args.screenshots))

    # Diff reports
    if args.diff:
        snapshot_path = out / f"{domain}_prev.txt"
        prev = diff.load_snapshot(snapshot_path)
        if prev:
            d = diff.compute(prev, [h.host for h in live])
            console.print(f"\\n[bold cyan]Diff vs last scan:[/bold cyan]")
            console.print(diff.format_text(d))
        diff.save_snapshot(snapshot_path, [h.host for h in live])
        console.print(f"[dim]Snapshot saved: {snapshot_path.name}[/dim]")

    # Telegram
    if args.telegram_token and args.telegram_chat:
        takeovers = [h.host for h in live if h.takeover]
        nuclei_hits = [(h.host, len(h.nuclei)) for h in live if h.nuclei]
        secrets_all = [s for h in live for s in h.secrets]
        msg = telegram.format_result(domain, live, takeovers, nuclei_hits, secrets_all)
        ok = telegram.send(args.telegram_token, args.telegram_chat, msg)
        if ok:
            console.print("[green]Telegram notification sent[/green]")
        else:
            console.print("[yellow]Telegram send failed[/yellow]")

    return live'''

if old_ret in src:
    src = src.replace(old_ret, new_ret)

# 7) soft404 filter before probing
old_probe_start = '''    # 6) Full probe
    to_probe = [h for h in raw if h not in done_hosts]
    console.print(f"[bold cyan][3.75/6][/bold cyan] Probing {len(to_probe)} hosts")'''

new_probe_start = '''    # 6) Soft 404 build
    soft404_det = None
    if args.soft404:
        soft404_det = soft404.Soft404Detector(domain)
        ok = soft404_det.build()
        if ok:
            console.print(f"[green]Soft 404 fingerprint built[/green]")
        else:
            console.print(f"[yellow]Soft 404 fingerprint failed — disabled[/yellow]")
            soft404_det = None

    # 6) Full probe
    to_probe = [h for h in raw if h not in done_hosts]
    console.print(f"[bold cyan][3.75/6][/bold cyan] Probing {len(to_probe)} hosts")'''

if old_probe_start in src:
    src = src.replace(old_probe_start, new_probe_start)

path.write_text(src)
print("✅ cli.py patched for 10 features")
