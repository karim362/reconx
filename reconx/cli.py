"""ReconX CLI entry point."""
import sys
import re
import time
import argparse
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from reconx.core import config
from reconx.core.database import Database
from reconx.core.smart_scanner import scan_batches
from reconx.core.dns import wildcard_ips, dns_lookup, HAS_DNS
from reconx.core.session import http_get
from reconx.core.models import HostInfo

from reconx.sources.manager import collect
from reconx.detect import cdn, tech, takeover, ports, robots, sitemap, crawler, external, bruteforce
from reconx.utils.clean import clean_subdomain
from reconx.utils.perm import generate as gen_perms

from reconx.ui.banner import show_banner
from reconx.ui.tables import results_table, summary_table
from reconx.ui.progress import make_progress

from reconx.output import txt, csv_out, json_out, markdown, html_report

console = Console()


# ─────────────────────────────────────────────
# Host probing
# ─────────────────────────────────────────────
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
            info.endpoints = interesting + other[:10]
            for f in forms[:5]:
                info.endpoints.append(f"FORM: {f}")
            if params:
                info.endpoints.append(f"PARAMS: {','.join(params[:15])}")

    if opts.get("ports"):
        info.ports = ports.scan(host)

    if opts.get("nuclei") and base_url and info.status:
        info.nuclei = external.run_nuclei(host)

    return info


# ─────────────────────────────────────────────
# Per-domain flow
# ─────────────────────────────────────────────
def recon_domain(domain, args):
    from concurrent.futures import ThreadPoolExecutor, as_completed

    out = config.OUTPUT_DIR / domain
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()

    # 1) Wildcard
    with console.status("[cyan]Checking wildcard DNS...[/cyan]", spinner="dots"):
        wc = wildcard_ips(domain)
    if wc:
        console.print(f"[yellow]⚠ Wildcard: {wc}[/yellow]")
    else:
        console.print("[green]✓ No wildcard[/green]")

    # 2) Resume
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

    # 3) Collect sources
    console.print(f"\n[bold cyan][1/6][/bold cyan] Collecting from sources...")
    raw = set()
    with make_progress() as prog:
        task = prog.add_task("sources", total=8)
        def cb(name, count):
            prog.update(task, advance=1,
                        description=f"{name}: +{count}")
        raw = collect(domain, wildcard=wc, progress_cb=cb)

    # 3b) Bruteforce
    if args.brute:
        console.print("[bold cyan][2.5/6][/bold cyan] DNS bruteforce...")
        with make_progress() as prog:
            t = prog.add_task("brute", total=1)
            def bcb(done, total, found):
                prog.update(t, completed=done, total=total,
                            description=f"bruteforce: {done}/{total} ({found} found)")
            brute_subs = bruteforce.bruteforce(domain, threads=args.threads,
                                               progress_cb=bcb)
        console.print(f"  -> {len(brute_subs)} new from bruteforce")
        raw.update(brute_subs)

    # 4) Permutations
    if args.perm and raw:
        console.print("[bold cyan][2/6][/bold cyan] Permutations...")
        perms = gen_perms(raw, domain)
        raw.update(perms)
        console.print(f"  → {len(perms)} generated")
    else:
        console.print("[bold cyan][2/6][/bold cyan] Permutations skipped")

    console.print(f"[green]✓ Unique: {len(raw)}[/green]")
    txt.write(out / f"{domain}_all.txt", raw)

    # 5) httpx smart batch scanning
    httpx_results = {}
    if args.httpx and external.tool_available("httpx"):
        to_check = list(raw - done_hosts)
        if to_check:
            console.print(f"[bold cyan][3/6][/bold cyan] httpx smart-scan {len(to_check)} hosts (batches)...")

            def _batch(subset):
                return external.run_httpx(
                    subset, threads=min(args.threads, 20), timeout=300)

            httpx_results, stats = scan_batches(
                to_check, domain, _batch,
                max_batches=4, min_live_per_batch=3)

            total_tested = sum(s.get("size", 0) for s in stats if "size" in s)
            total_time = sum(s.get("elapsed", 0) for s in stats if "elapsed" in s)

            console.print(f"  -> httpx live: [green]{len(httpx_results)}[/green] / {total_tested} tested in {total_time:.0f}s")

            # print batch breakdown
            for s in stats:
                if "tier" in s and isinstance(s["tier"], int):
                    console.print(f"     batch {s['tier']}: {s['size']} tested, {s['found']} live ({s['elapsed']:.1f}s)")
                elif "early_stop" in str(s):
                    console.print(f"     [yellow]early stop: {s.get('reason', '')}[/yellow]")
    else:
        console.print("[bold cyan][3/6][/bold cyan] httpx skipped")

    # 6) Full probe
    to_probe = [h for h in raw if h not in done_hosts]
    # DNS pre-filter: skip hosts without A record (saves ~80% probing time)
    console.print(f"[bold cyan][3.5/6][/bold cyan] DNS pre-filter {len(to_probe)} hosts...")
    from reconx.core.dns import dns_lookup as _dns
    from concurrent.futures import ThreadPoolExecutor as _TPE
    with _TPE(max_workers=50) as _ex:
        alive = list(_ex.map(lambda h: h if _dns(h)[0] else None, to_probe))
    to_probe = [h for h in alive if h]
    console.print(f"  -> [green]{len(to_probe)}[/green] hosts have DNS (filtered from {len(raw)})")
    # pre-filter: skip hosts without DNS (saves ~80% of probing time)
    console.print(f"[bold cyan][3.5/6][/bold cyan] DNS pre-filter {len(to_probe)} hosts...")
    from reconx.core.dns import dns_lookup as _dns
    from concurrent.futures import ThreadPoolExecutor as _TPE
    with _TPE(max_workers=50) as _ex:
        alive = list(_ex.map(lambda h: h if _dns(h)[0] else None, to_probe))
    to_probe = [h for h in alive if h]
    console.print(f"  -> {len(to_probe)} hosts have DNS (filtered)")
    console.print(f"[bold cyan][4/6][/bold cyan] Probing {len(to_probe)} hosts ({args.threads} threads)...")

    opts = {
        "ports":   not args.no_ports and not args.fast,
        "robots":  not args.no_robots and not args.fast,
        "sitemap": not args.no_sitemap and not args.fast,
        "crawl":   args.crawl,
        "nuclei":  args.nuclei,
    }

    with make_progress("[green]live:{task.fields[live]}[/green]") as prog:
        task = prog.add_task("probe", total=len(to_probe), live=len(live))
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = {ex.submit(probe_host, h, opts): h for h in to_probe}
            for f in as_completed(futures):
                info = f.result()
                if info:
                    live.append(info)
                    db.save(info)
                prog.update(task, advance=1, live=len(live))

    # 7) Screenshots
    if args.screenshots and external.tool_available("gowitness") and live:
        console.print(f"[bold cyan][5/6][/bold cyan] Screenshots {len(live)}...")
        external.run_gowitness([h.host for h in live], out)
    else:
        console.print("[bold cyan][5/6][/bold cyan] Screenshots skipped")

    db.close()

    # 8) Outputs
    console.print("[bold cyan][6/6][/bold cyan] Writing outputs...")
    elapsed = time.time() - t0
    txt.write(out / f"{domain}_live.txt", [h.host for h in live])
    csv_out.write(out / f"{domain}_live.csv", live)
    json_out.write(out / f"{domain}.json", live)
    markdown.write(out / f"{domain}_report.md", domain, len(raw), live, elapsed)
    html_report.write(out / f"{domain}_report.html", domain, raw, live, elapsed)

    # endpoints aggregate
    eps = {f"{h.host}{ep}" for h in live for ep in h.endpoints}
    if eps:
        txt.write_lines(out / f"{domain}_endpoints.txt", eps)

    # show results table
    if live:
        console.print(results_table(live,
                                    show_nuclei=opts["nuclei"],
                                    show_screens=args.screenshots))
    return live


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(prog="reconx",
                                 description="ReconX — Recon Framework v3.0")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-d", "--domain")
    g.add_argument("-dL", "--domain-list")
    ap.add_argument("-t", "--threads", type=int, default=config.DEFAULT_THREADS)
    ap.add_argument("--all", action="store_true",
                    help="Enable perm+crawl+nuclei+screenshots+httpx")
    ap.add_argument("--perm", action="store_true")
    ap.add_argument("--crawl", action="store_true")
    ap.add_argument("--nuclei", action="store_true")
    ap.add_argument("--screenshots", action="store_true")
    ap.add_argument("--httpx", action="store_true")
    ap.add_argument("--brute", action="store_true",
                    help="DNS bruteforce with wordlist")
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--no-ports", action="store_true")
    ap.add_argument("--no-robots", action="store_true")
    ap.add_argument("--no-sitemap", action="store_true")
    args = ap.parse_args()

    if args.all:
        args.perm = args.crawl = args.nuclei = True
        args.screenshots = args.httpx = args.brute = True

    # sanity checks
    if not HAS_DNS:
        console.print("[yellow]⚠ pip install dnspython[/yellow]")
    if args.crawl and not crawler.HAS_BS4:
        console.print("[yellow]⚠ pip install beautifulsoup4 lxml — crawl disabled[/yellow]")
        args.crawl = False
    if args.nuclei and not external.tool_available("nuclei"):
        console.print("[yellow]⚠ nuclei not found — disabled[/yellow]")
        args.nuclei = False
    if args.screenshots and not external.tool_available("gowitness"):
        console.print("[yellow]⚠ gowitness not found — disabled[/yellow]")
        args.screenshots = False
    if args.httpx and not external.tool_available("httpx"):
        console.print("[yellow]⚠ httpx not found — disabled[/yellow]")
        args.httpx = False

    # load domains
    if args.domain:
        domains = [re.sub(r"^https?://", "", args.domain.strip().lower()).split("/")[0]]
    else:
        p = Path(args.domain_list)
        if not p.exists():
            console.print(f"[red]✗ File not found: {p}[/red]")
            sys.exit(1)
        domains = [re.sub(r"^https?://", "", l.strip().lower()).split("/")[0]
                   for l in p.read_text().splitlines() if l.strip()]

    show_banner(domains)
    t0 = time.time()
    summary = []

    for i, d in enumerate(domains, 1):
        if len(domains) > 1:
            console.rule(f"[bold yellow]Domain {i}/{len(domains)}: {d}[/bold yellow]")
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
