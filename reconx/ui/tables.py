from rich.table import Table
from rich import box


def results_table(results, show_nuclei=False, show_screens=False):
    t = Table(box=box.SIMPLE_HEAVY, expand=False)
    t.add_column("Host", style="cyan", max_width=38)
    t.add_column("ST", justify="center", width=4)
    t.add_column("Srv", style="magenta", max_width=10)
    t.add_column("CDN", style="blue", max_width=8)
    if show_nuclei:
        t.add_column("N", justify="center", width=3)
    if show_screens:
        t.add_column("SS", justify="center", width=3)
    t.add_column("!", justify="center", width=2)

    for h in results:
        st_style = "green" if h.status and h.status < 400 else \
                   "yellow" if h.status else "red"
        row = [
            h.host[:38],
            f"[{st_style}]{h.status or '-'}[/{st_style}]",
            (h.server or "-")[:9],
            (h.cdn or "-")[:8],
        ]
        if show_nuclei:
            n = len(h.nuclei)
            row.append(f"[red]{n}[/red]" if n else "-")
        if show_screens:
            row.append("Y" if h.screenshot else "-")
        row.append("[red]![/red]" if h.takeover else "")
        t.add_row(*row)
    return t


def summary_table(summary):
    st = Table(box=box.HEAVY, title="Global Summary")
    st.add_column("Domain", style="cyan")
    st.add_column("Live", justify="right", style="green")
    st.add_column("Takeover", justify="right", style="red")
    st.add_column("Nuclei", justify="right", style="red")
    tl = tt = tn = 0
    for d, live in summary:
        takes = sum(1 for h in live if h.takeover)
        nucs = sum(len(h.nuclei) for h in live)
        tl += len(live); tt += takes; tn += nucs
        st.add_row(d, str(len(live)), str(takes), str(nucs))
    st.add_row("[bold]TOTAL[/bold]", f"[bold]{tl}[/bold]",
               f"[bold]{tt}[/bold]", f"[bold]{tn}[/bold]")
    return st
