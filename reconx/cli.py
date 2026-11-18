"""ReconX CLI entry point with AI Mastermind & 4 Specialized Agents."""
import sys
import re
import time
import argparse
from pathlib import Path
from urllib.parse import urljoin

from rich.console import Console
from rich.panel import Panel

from reconx.core import config
from reconx.core.database import Database
from reconx.core.dns import dns_lookup, HAS_DNS
from reconx.core.wildcard import detect as wildcard_detect, is_valid_host
from reconx.core.session import http_get
from reconx.core.models import HostInfo
from reconx.core.mastermind import Mastermind

from reconx.sources.manager import collect
from reconx.detect import cdn, tech, takeover, ports, robots, sitemap, crawler, external, status, secrets, s3, js_analysis, cors
from reconx.output import diff
from reconx.notify import telegram

from reconx.ui.banner import show_banner
from reconx.ui.tables import results_table, summary_table
from reconx.ui.progress import make_progress

from reconx.output import txt, csv_out, json_out, markdown, html_report

console = Console(color_system='standard')


def probe_host(host, opts):
    info = HostInfo(host=host)
    ip, cname = dns_lookup(host)
    if not ip:
        return None
    info.ip = ip
    info.cname = cname

    body = ""
    base_url = None
    for scheme in ("https", "http"):
        try:
            r = http_get(f"{scheme}://{host}", allow_redirects=True, timeout=8)
            info.status = r.status_code
            info.server = r.headers.get("Server", "Unknown")
            info.cdn = cdn.detect(r.headers)
            m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
            if m:
                info.title = m.group(1).strip()[:70]
            info.tech = tech.detect(r.headers, r.text)
            body = r.text
            base_url = f"{scheme}://{host}"
            break
        except Exception:
            continue

    info.takeover = takeover.detect(host, cname, body)

    if base_url:
        if opts.get("robots"):
            info.robots = robots.fetch(base_url)
        if opts.get("sitemap"):
            info.sitemap = sitemap.fetch(base_url)
        if opts.get("crawl") and crawler.HAS_BS4:
            interesting, other, forms, params = crawler.crawl(
                base_url, max_pages=5, depth=1)
            info.endpoints = (interesting or []) + (other[:10] if other else [])
            for f in (forms[:5] if forms else []):
                info.endpoints.append(f"FORM: {f}")
            if params:
                info.endpoints.append(f"PARAMS: {','.join(params[:15])}")

    if opts.get("ports"):
        info.ports = ports.scan(host)

    if opts.get("nuclei") and base_url and info.status:
        info.nuclei = external.run_nuclei(host)

    info.status_category = status.categorize(info.status)

    if opts.get("secrets") and body:
        info.secrets = secrets.scan(body) or []

    if opts.get("cors") and base_url:
        info.cors = cors.check(base_url)

    if opts.get("js") and base_url and body:
        js_urls = js_analysis.extract_urls(body, base_url)
        js_eps, js_ext = js_analysis.analyze(js_urls)
        info.js_endpoints = js_eps or []

    if opts.get("s3") and body:
        buckets = s3.extract(body)
        for b in list(buckets)[:3]:
            info.s3_buckets.append(s3.check(b))

    return info


def recon_domain(domain, args):
    from concurrent.futures import ThreadPoolExecutor, as_completed

    out = config.OUTPUT_DIR / domain
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()

    # إذا تم تفعيل وضع الذكاء الاصطناعي، العقل المركزي يتولى التوجيه
    if args.ai_mode:
        console.print(Panel(f"[bold cyan]🧠 Mastermind AI Engine Active for: {domain}[/bold cyan]", border_style="cyan"))
        brain = Mastermind(domain, aggressiveness="high" if args.all else "normal")
        ai_results = brain.evaluate_and_execute()
        for agent_name, res in ai_results.items():
            console.print(f"  -> [green]Agent [{res.get('agent', agent_name)}]:[/green] Status: {res.get('status')} | Tools: {res.get('tools_used')}")

    with console.status("[cyan]Checking wildcard DNS...[/cyan]", spinner="dots"):
        wc_info = {'ips': set(), 'is_wildcard': False}
    wc = wc_info["ips"] if wc_info["is_wildcard"] else None

    db_path = out / f"{domain}.db"
    db = Database(db_path)
    done_hosts = set()
    live = []
    if args.resume:
        prev = db.load_all()
        if prev:
            done_hosts = {h.host for h in prev}
            live = prev
            console.print(f"[yellow]♻ Resume: {len(prev)} hosts[/yellow]")

    console.print(f"\n[bold cyan][1/5][/bold cyan] Collecting from sources...")
    raw = set()
    with make_progress() as prog:
        task = prog.add_task("sources", total=8)
        def cb(name, count):
            prog.update(task, advance=1, description=f"{name}: +{count}")
        raw = collect(domain, wildcard=wc, progress_cb=cb)

    console.print(f"[green]✓ Unique: {len(raw)}[/green]")
    txt.write(out / f"{domain}_all.txt", sorted(raw))

    to_probe = [h for h in raw if h not in done_hosts]

    console.print(f"[bold cyan][2/5][/bold cyan] DNS pre-filter {len(to_probe)} hosts...")
    from reconx.core.dns import dns_batch
    batch = dns_batch(to_probe)
    to_probe = [h for h in to_probe if batch.get(h)]
    console.print(f"  -> [green]{len(to_probe)}[/green] hosts have DNS")

    opts = {
        "ports":   not args.no_ports and not args.fast,
        "robots":  not args.no_robots and not args.fast,
        "sitemap": not args.no_sitemap and not args.fast,
        "crawl":   args.crawl,
        "nuclei":  args.nuclei,
        "secrets": args.secrets,
        "cors":    args.cors,
        "js":      args.js,
        "s3":      args.s3,
    }

    try:
        with make_progress("[green]live:{task.fields[live]}[/green]") as prog:
            task = prog.add_task("probe", total=len(to_probe), live=len(live))
            with ThreadPoolExecutor(max_workers=args.threads) as ex:
                futures = {ex.submit(probe_host, h, opts): h for h in to_probe}
                for f in as_completed(futures):
                    try:
                        info = f.result()
                    except Exception:
                        info = None
                    if info:
                        live.append(info)
                        db.save(info)
                    prog.update(task, advance=1, live=len(live))
    finally:
        db.close()

    elapsed = time.time() - t0
    txt.write(out / f"{domain}_live.txt", sorted([h.host for h in live]))
    csv_out.write(out / f"{domain}_live.csv", live)
    json_out.write(out / f"{domain}.json", live)
    markdown.write(out / f"{domain}_report.md", domain, len(raw), live, elapsed)
    html_report.write(out / f"{domain}_report.html", domain, raw, live, elapsed)

    if live:
        console.print(results_table(live, show_nuclei=opts["nuclei"]))

    if args.telegram_token and args.telegram_chat:
        takeovers = [h.host for h in live if h.takeover]
        nuclei_hits = [(h.host, len(h.nuclei)) for h in live if h.nuclei]
        secrets_all = [s for h in live for s in (h.secrets or [])]
        msg = telegram.format_result(domain, live, takeovers, nuclei_hits, secrets_all)
        telegram.send(args.telegram_token, args.telegram_chat, msg)

    return live


def main():
    ap = argparse.ArgumentParser(prog="reconx", description="ReconX Elite AI Framework")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-d", "--domain")
    g.add_argument("-dL", "--domain-list")
    ap.add_argument("-t", "--threads", type=int, default=config.DEFAULT_THREADS)
    ap.add_argument("--all", action="store_true", help="Enable all flags")
    ap.add_argument("--ai-mode", action="store_true", help="Activate Mastermind AI & 4 Specialized Agents")
    ap.add_argument("--crawl", action="store_true")
    ap.add_argument("--nuclei", action="store_true")
    ap.add_argument("--screenshots", action="store_true")
    ap.add_argument("--httpx", action="store_true")
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--no-ports", action="store_true")
    ap.add_argument("--no-robots", action="store_true")
    ap.add_argument("--no-sitemap", action="store_true")
    ap.add_argument("--secrets", action="store_true")
    ap.add_argument("--cors", action="store_true")
    ap.add_argument("--js", action="store_true")
    ap.add_argument("--s3", action="store_true")
    ap.add_argument("--soft404", action="store_true")
    ap.add_argument("--diff", action="store_true")
    ap.add_argument("--telegram-token", help="Telegram bot token")
    ap.add_argument("--telegram-chat", help="Telegram chat ID")
    args = ap.parse_args()

    if args.ai_mode:
        args.all = True  # تفعيل الوضع الشامل تلقائياً تحت إدارة العقل المركزي

    if args.domain:
        domains = [re.sub(r"^https?://", "", args.domain.strip().lower()).split("/")[0]]
    else:
        p = Path(args.domain_list)
        domains = [re.sub(r"^https?://", "", l.strip().lower()).split("/")[0] for l in p.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]

    show_banner(domains)
    t0 = time.time()
    summary = []

    for i, d in enumerate(domains, 1):
        try:
            live = recon_domain(d, args)
            summary.append((d, live))
        except KeyboardInterrupt:
            console.print("[red]Interrupted[/red]")
            break
        except Exception as e:
            console.print(f"[red]✗ {d} failed: {e}[/red]")
            summary.append((d, []))

    console.rule("[bold green]ALL DONE[/bold green]")
    console.print(summary_table(summary))
    console.print(f"\n⏱ Elapsed: [yellow]{time.time()-t0:.1f}s[/yellow]")
    console.print(f"📁 Outputs: [cyan]{config.OUTPUT_DIR}[/cyan]")


if __name__ == "__main__":
    main()
