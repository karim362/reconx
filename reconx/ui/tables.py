"""Terminal tables and formatting."""
from rich.table import Table

def results_table(live, show_nuclei=False, show_screens=False):
    table = Table(title="[bold cyan]Live Targets & Recon Summary[/bold cyan]", show_lines=False)
    table.add_column("Host", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Server", style="magenta")
    table.add_column("CDN", style="yellow")
    table.add_column("Takeover", style="bold red")
    if show_nuclei:
        table.add_column("Nuclei", style="red")

    for h in live:
        status_style = "green" if h.status == 200 else ("yellow" if h.status in [403, 401] else "blue")
        status_str = f"[{status_style}]{h.status}[/{status_style}]" if h.status else "[dim]-[/dim]"
        takeover_str = "⚠ VULN" if h.takeover else "[dim]-[/dim]"
        
        row = [
            h.host,
            status_str,
            h.server or "-",
            h.cdn or "-",
            takeover_str
        ]
        if show_nuclei:
            row.append(str(len(h.nuclei)) if h.nuclei else "0")
        table.add_row(*row)

    return table

def summary_table(summary):
    table = Table(title="[bold green]Global Summary[/bold green]")
    table.add_column("Domain", style="cyan")
    table.add_column("Live", justify="right", style="green")
    table.add_column("Takeover", justify="right", style="red")
    table.add_column("Nuclei", justify="right", style="yellow")

    for domain, live in summary:
        takeovers = sum(1 for h in live if h.takeover)
        nuclei_hits = sum(len(h.nuclei) for h in live if h.nuclei)
        table.add_row(domain, str(len(live)), str(takeovers), str(nuclei_hits))

    return table
