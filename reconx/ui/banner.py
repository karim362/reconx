from rich.console import Console
from rich.text import Text

console = Console()


def show_banner(domains):
    t = Text()
    t.append("╔════════════════════════════════════════════════╗\n", style="bold cyan")
    t.append("║  ", style="bold cyan")
    t.append("ReconX", style="bold white")
    t.append(" — Professional Recon Framework v3.0    ║\n", style="bold cyan")
    t.append("╚════════════════════════════════════════════════╝\n", style="bold cyan")
    console.print(t)
    if len(domains) == 1:
        console.print(f"[bold]Target:[/bold] [yellow]{domains[0]}[/yellow]\n")
    else:
        console.print(f"[bold]Targets:[/bold] [yellow]{len(domains)} domains[/yellow]\n")
