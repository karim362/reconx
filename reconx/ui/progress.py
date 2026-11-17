from rich.progress import (Progress, SpinnerColumn, BarColumn,
                           TextColumn, TimeElapsedColumn)


def make_progress(extra_fields=None):
    """Return a configured Progress (for use with `with`)."""
    columns = [
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[cyan]{task.completed}/{task.total}[/cyan]"),
        TimeElapsedColumn(),
    ]
    if extra_fields:
        columns.append(TextColumn(extra_fields))
    return Progress(*columns)
