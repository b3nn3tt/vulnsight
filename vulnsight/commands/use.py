"""Command for selecting an active scan context."""

from __future__ import annotations

import requests
import typer
from rich.console import Console

from vulnsight.commands.scans import _build_client
from vulnsight.context import save_context


console = Console()


def use_scan(scan_name: str) -> None:
    """Resolve a scan name, select its latest completed run, and save context."""

    client = _build_client()

    try:
        scan = client.find_scan_by_name(scan_name)
        if scan is None:
            console.print(f"[red]Scan not found:[/red] {scan_name}")
            raise typer.Exit(code=1)

        scan_id = int(scan.get("id", 0))
        history = client.get_latest_completed_history(scan_id)
    except requests.RequestException as exc:
        console.print(f"[red]Failed to retrieve scan details:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except ValueError:
        console.print(f"[red]No completed runs found for scan:[/red] {scan_name}")
        raise typer.Exit(code=1)

    history_id = int(history.get("history_id", 0))
    resolved_name = str(scan.get("name", scan_name))

    save_context(scan_id=scan_id, history_id=history_id, scan_name=resolved_name)

    console.print(f"Using scan: {resolved_name}")
    console.print(f"Scan ID   : {scan_id}")
    console.print(f"History ID: {history_id}")
