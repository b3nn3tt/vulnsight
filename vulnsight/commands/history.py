"""Commands and helpers for working with scan history."""

from __future__ import annotations

from datetime import datetime, timezone

import requests
import typer
from rich import box
from rich.console import Console
from rich.table import Table

from vulnsight.commands.scans import _build_client
from vulnsight.context import load_context


console = Console()


def _format_timestamp(timestamp: int | str | None) -> str:
    """Convert a Nessus timestamp into a readable UTC datetime."""

    if not timestamp:
        return "-"

    try:
        return datetime.fromtimestamp(int(timestamp), tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    except (TypeError, ValueError, OSError):
        return "-"


def _get_sorted_history_entries(scan_details: dict) -> list[dict]:
    """Return scan history entries sorted newest first."""

    history = scan_details.get("history", [])
    return sorted(
        history,
        key=lambda entry: (
            int(entry.get("history_id", 0) or 0),
            int(entry.get("creation_date", 0) or 0),
        ),
        reverse=True,
    )


def _get_latest_history_entry(scan_details: dict) -> dict | None:
    """Return the latest history entry for a scan."""

    history = _get_sorted_history_entries(scan_details)
    return history[0] if history else None


def show_history() -> None:
    """Display the history for the currently selected scan."""

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
    scan_name = str(context.get("scan_name", ""))

    try:
        scan_details = client.get_scan_details(scan_id)
    except requests.RequestException as exc:
        console.print(f"[red]Failed to retrieve scan history:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    history_entries = _get_sorted_history_entries(scan_details)
    if not history_entries:
        console.print("[yellow]No scan history found.[/yellow]")
        return

    table = Table(title=f"Scan History: {scan_name or scan_id}", box=box.ROUNDED)
    table.add_column("History ID", style="cyan", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Start Time", no_wrap=True)
    table.add_column("End Time", no_wrap=True)

    for entry in history_entries:
        history_id = int(entry.get("history_id", 0) or 0)
        status = str(entry.get("status", "unknown"))
        history_label = str(history_id)
        history_markers: list[str] = []

        if status.lower() == "running":
            history_markers.append("[yellow]<- in progress[/yellow]")

        if history_id == current_history_id:
            history_markers.append("<- current")

        if history_markers:
            history_label = f"{history_label} {' '.join(history_markers)}"

        table.add_row(
            history_label,
            status,
            _format_timestamp(entry.get("creation_date")),
            _format_timestamp(entry.get("last_modification_date")),
        )

    console.print(table)
