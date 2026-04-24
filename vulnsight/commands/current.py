"""Command for displaying the active VulnSight context."""

from __future__ import annotations

import requests
import typer
from rich import box
from rich.console import Console
from rich.table import Table

from vulnsight.commands.history import _get_latest_history_entry
from vulnsight.commands.scans import _build_client
from vulnsight.context import load_context


console = Console()


def show_current() -> None:
    """Display the currently selected scan context."""

    context = load_context()
    if not context:
        console.print(
            "[red]No active scan context.[/red] "
            "Use 'vulnsight use <scan_name>' first."
        )
        raise typer.Exit(code=1)

    client = _build_client()
    scan_id = int(context.get("scan_id", 0))
    current_history_id = int(context.get("history_id", 0))

    try:
        scan_details = client.get_scan_details(scan_id)
    except requests.RequestException as exc:
        console.print(f"[red]Failed to retrieve current scan context:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    latest_entry = _get_latest_history_entry(scan_details)
    latest_history_id = (
        int(latest_entry.get("history_id", 0) or 0) if latest_entry is not None else None
    )
    latest_status = str(latest_entry.get("status", "") or "").strip().lower() if latest_entry else ""
    history_label = str(current_history_id)
    if latest_history_id == current_history_id:
        history_label = f"{history_label} (latest)"
    elif latest_history_id is not None:
        history_label = f"{history_label} (historical)"

    table = Table(title="Current Scan Context", box=box.ROUNDED)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    table.add_row("Scan Name", str(context.get("scan_name", "")))
    table.add_row("Scan ID", str(scan_id))
    table.add_row("History ID", history_label)

    console.print(table)

    if latest_history_id is not None and current_history_id != latest_history_id:
        console.print()
        console.print(
            "[cyan]Note: You are viewing a previous scan run[/cyan]",
            highlight=False,
        )

        if latest_status == "running":
            console.print(
                f"[yellow]Note: A newer scan run (ID: {latest_history_id}) is currently in progress[/yellow]",
                highlight=False,
            )
