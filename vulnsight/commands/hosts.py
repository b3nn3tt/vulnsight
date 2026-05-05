"""Command for displaying hosts in the current scan context."""

from __future__ import annotations

import re

import requests
import typer
from rich import box
from rich.console import Console
from rich.table import Table

from vulnsight.commands.scans import _build_client
from vulnsight.context import load_context


console = Console()

OS_IDENTIFICATION_PLUGIN_ID = 11936


def normalise_outputs(value: object) -> list[dict]:
    """Return Nessus plugin output rows as a safe list."""

    if not isinstance(value, list):
        return []

    return [item for item in value if isinstance(item, dict)]


def _extract_os_from_text(text: str) -> str:
    """Extract a readable operating system string from plugin output."""

    patterns = [
        r"Remote operating system\s*:\s*(.+)",
        r"The remote host is running\s+(.+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()

    return ""


def _get_host_os(client, scan_id: int, history_id: int, host: dict) -> str:
    """Return a best-effort operating system string for a host."""

    host_id = host.get("host_id")
    if host_id is None:
        return "Unknown"

    try:
        host_details = client.get_host_details(scan_id, int(host_id), history_id)
    except requests.RequestException:
        host_details = {}

    info = host_details.get("info", {})
    for key in ("operating-system", "operating_system", "os"):
        value = str(info.get(key) or host.get(key) or "").strip()
        if value:
            return value

    try:
        plugin_output = client.get_host_plugin_output(
            scan_id, int(host_id), OS_IDENTIFICATION_PLUGIN_ID, history_id
        )
    except requests.RequestException:
        return "Unknown"

    outputs = normalise_outputs(plugin_output.get("outputs"))
    for output in outputs:
        text = str(output.get("plugin_output") or "").strip()
        if not text:
            continue

        os_value = _extract_os_from_text(text)
        if os_value:
            return os_value

    return "Unknown"


def list_hosts() -> None:
    """Display all hosts in the currently selected scan."""

    context = load_context()
    if not context:
        console.print(
            "[red]No active scan context.[/red] "
            "Use 'vulnsight use <scan_name>' first."
        )
        raise typer.Exit(code=1)

    client = _build_client()
    scan_id = int(context.get("scan_id", 0))
    history_id = int(context.get("history_id", 0))

    try:
        details = client.get_scan_result_details(scan_id, history_id)
    except requests.RequestException as exc:
        console.print(f"[red]Failed to retrieve hosts:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    hosts = details.get("hosts", [])
    if not hosts:
        console.print("[yellow]No hosts found in this scan.[/yellow]")
        return

    table = Table(title="Hosts", box=box.ROUNDED)
    table.add_column("Host", style="cyan")
    table.add_column("Operating System", style="white")

    for host in hosts:
        host_value = str(
            host.get("hostname") or host.get("host") or host.get("ip") or "-"
        )
        operating_system = _get_host_os(client, scan_id, history_id, host)

        table.add_row(host_value, operating_system)

    console.print(table)
