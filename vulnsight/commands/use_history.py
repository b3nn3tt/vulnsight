"""Command for selecting a specific history entry for the active scan."""

from __future__ import annotations

import requests
import typer
from rich.console import Console

from vulnsight.commands.history import _get_latest_history_entry, _get_sorted_history_entries
from vulnsight.commands.scans import _build_client
from vulnsight.context import load_context, save_context


console = Console()


def use_history(history_id: str) -> None:
    """Select a specific scan history entry or switch back to the latest."""

    context = load_context()
    if not context:
        console.print(
            "[red]No active scan context.[/red] "
            "Use 'vulnsight use <scan_name>' first."
        )
        raise typer.Exit(code=1)

    client = _build_client()
    scan_id = int(context.get("scan_id", 0))
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

    if history_id.strip().lower() == "latest":
        latest_entry = _get_latest_history_entry(scan_details)
        if latest_entry is None:
            console.print("[yellow]No scan history found.[/yellow]")
            return

        selected_history_id = int(latest_entry.get("history_id", 0) or 0)
        save_context(scan_id=scan_id, history_id=selected_history_id, scan_name=scan_name)
        console.print(f"Using latest scan run (history ID: {selected_history_id})")
        return

    try:
        target_history_id = int(history_id)
    except ValueError:
        console.print(f"[red]History ID '{history_id}' not found for this scan.[/red]")
        console.print("Use 'vulnsight history' to view available runs.")
        return

    matching_entry = next(
        (
            entry
            for entry in history_entries
            if int(entry.get("history_id", 0) or 0) == target_history_id
        ),
        None,
    )
    if matching_entry is None:
        console.print(f"[red]History ID '{history_id}' not found for this scan.[/red]")
        console.print("Use 'vulnsight history' to view available runs.")
        return

    save_context(scan_id=scan_id, history_id=target_history_id, scan_name=scan_name)
    console.print(f"Using scan '{scan_name}' (history ID: {target_history_id})")
