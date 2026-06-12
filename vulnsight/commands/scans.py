"""Scan-related CLI commands."""

from __future__ import annotations

from datetime import datetime, timezone

import requests
import typer
from rich import box
from rich.console import Console
from rich.table import Table

from vulnsight.client import NessusClient
from vulnsight.config import ENV_FILE, get_settings


console = Console()

SUCCESS_CREDENTIAL_PLUGIN_IDS = {
    141118,  # Valid credentials provided
    110095,  # Successful auth with no issues found
    110385,  # Successful auth but insufficient privilege
    117885,  # Successful auth with intermittent failures
    117887,  # Local checks available
}

FAILURE_CREDENTIAL_PLUGIN_IDS = {
    104410,  # Failure for provided credentials
    110723,  # No credentials provided
}


def _build_client() -> NessusClient:
    """Create a Nessus client from environment configuration."""

    settings = get_settings()
    if not settings.access_key or not settings.secret_key:
        if ENV_FILE.exists():
            console.print(
                "[red]VulnSight configuration is incomplete.[/red] "
                "Missing Nessus API credentials."
            )
        else:
            console.print(
                "[red]VulnSight is not yet configured.[/red] "
                "No local Nessus credentials were found."
            )

        console.print("Run [cyan]python .\\main.py setup[/cyan] to configure or reconfigure the tool.")
        raise typer.Exit(code=1)
    return NessusClient(settings)


def _format_date(timestamp: int | str | None) -> str:
    """Convert a Nessus timestamp into YYYY-MM-DD format."""

    if not timestamp:
        return "-"

    try:
        return datetime.fromtimestamp(int(timestamp), tz=timezone.utc).strftime(
            "%Y-%m-%d"
        )
    except (TypeError, ValueError, OSError):
        return "-"


def _format_status(status: str | None) -> str:
    """Render a scan status with a simple colour mapping."""

    value = str(status or "unknown")
    colour_map = {
        "completed": "green",
        "running": "yellow",
        "failed": "red",
    }
    colour = colour_map.get(value.lower())
    if colour is None:
        return value
    return f"[{colour}]{value}[/{colour}]"


def _format_credential_status(status: str) -> str:
    """Render the credential status with a simple colour mapping."""

    if status == "Yes":
        return "[green]Yes[/green]"
    if status == "No":
        return "[red]No[/red]"
    return "[dim]Unknown[/dim]"


def _get_host_credential_status(hosts: list[dict[str, object]]) -> str | None:
    """Determine credential status from host-level flags when present."""

    if not hosts:
        return None

    credentialed_values = [
        host.get("credentialed")
        for host in hosts
        if "credentialed" in host and host.get("credentialed") is not None
    ]

    if not credentialed_values:
        return None

    if any(value is True for value in credentialed_values):
        return "Yes"

    if any(value is False for value in credentialed_values):
        return "No"

    return None


def _count_plugin_signals(vulnerabilities: list[dict[str, object]]) -> tuple[int, int]:
    """Count auth-related success and failure plugin signals."""

    plugin_ids = {
        int(vulnerability.get("plugin_id", 0) or 0) for vulnerability in vulnerabilities
    }
    success_count = len(plugin_ids & SUCCESS_CREDENTIAL_PLUGIN_IDS)
    failure_count = len(plugin_ids & FAILURE_CREDENTIAL_PLUGIN_IDS)
    return success_count, failure_count


def _get_credential_status(
    client: NessusClient,
    scan_id: int,
    scan_details: dict | None = None,
) -> str:
    """Determine whether a scan was credentialed using auth-status findings."""

    try:
        details = (
            scan_details
            if scan_details is not None
            else client.get_scan_details(scan_id)
        )
        history_entries = details.get("history", [])
        completed_runs = [
            entry
            for entry in history_entries
            if str(entry.get("status", "")).lower() == "completed"
        ]
    except ValueError:
        return "Unknown"

    if not completed_runs:
        return "Unknown"

    history = max(
        completed_runs,
        key=lambda entry: (
            int(entry.get("creation_date", 0) or 0),
            int(entry.get("history_id", 0) or 0),
        ),
    )

    history_id = history.get("history_id")
    if history_id is None:
        return "Unknown"

    result_details = client._get(f"/scans/{scan_id}?history_id={history_id}")
    hosts = result_details.get("hosts", [])
    host_status = _get_host_credential_status(hosts)
    if host_status is not None:
        return host_status

    vulnerabilities = result_details.get("vulnerabilities", [])
    success_count, failure_count = _count_plugin_signals(vulnerabilities)

    if success_count > 0:
        return "Yes"

    if failure_count > 0:
        return "No"

    return "Unknown"


def _build_folder_map(client: NessusClient) -> dict[int, str]:
    """Return a mapping of folder ID to folder name.

    Degrades to an empty map (folders shown as '-') if the folders endpoint
    cannot be reached, rather than failing the whole listing.
    """

    try:
        folders = client.list_folders()
    except requests.RequestException as exc:
        console.print(
            f"[yellow]Warning:[/yellow] Could not retrieve folders: {exc}"
        )
        return {}

    return {
        int(folder.get("id", 0) or 0): str(folder.get("name", "") or "")
        for folder in folders
    }


def _resolve_folder_name(folder_map: dict[int, str], scan: dict) -> str:
    """Return the folder name for a scan, or '-' when unknown."""

    folder_id = scan.get("folder_id")
    if folder_id is None:
        return "-"
    return folder_map.get(int(folder_id), "-") or "-"


def _resolve_folder_filter(folder_map: dict[int, str], folder: str) -> int | None:
    """Resolve a folder name to its ID (case-insensitive), or None if absent."""

    target = folder.strip().lower()
    for folder_id, name in folder_map.items():
        if name.strip().lower() == target:
            return folder_id
    return None


def _add_basic_scan_row(table: Table, scan: dict, folder_name: str) -> None:
    """Append one row using only the lightweight scan-list payload."""

    table.add_row(
        str(scan.get("id", "")),
        str(scan.get("name", "")),
        folder_name,
        _format_status(scan.get("status")),
        _format_date(scan.get("last_modification_date")),
    )


def _add_detailed_scan_row(
    table: Table, client: NessusClient, scan: dict, folder_name: str
) -> None:
    """Append one row enriched with per-scan details where available."""

    scan_id = int(scan.get("id", 0))

    try:
        details = client.get_scan_details(scan_id)
        history = details.get("history", [])
        run_count = str(len(history))
        credential_status = _get_credential_status(client, scan_id, details)
    except requests.RequestException as exc:
        run_count = "unavailable"
        credential_status = "Unknown"
        console.print(
            f"[yellow]Warning:[/yellow] Could not retrieve details for scan "
            f"{scan_id}: {exc}"
        )

    table.add_row(
        str(scan_id),
        str(scan.get("name", "")),
        folder_name,
        _format_status(scan.get("status")),
        _format_date(scan.get("last_modification_date")),
        run_count,
        _format_credential_status(credential_status),
    )


def list_scans(include_details: bool = False, folder: str | None = None) -> None:
    """List scans with summary details and run counts."""

    client = _build_client()
    try:
        with console.status("Fetching scan list from Nessus...", spinner="dots"):
            scans = client.list_scans()
    except requests.RequestException as exc:
        console.print(f"[red]Failed to retrieve scans:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if not scans:
        console.print("[yellow]No scans found.[/yellow]")
        return

    folder_map = _build_folder_map(client)

    if folder is not None:
        folder_id = _resolve_folder_filter(folder_map, folder)
        if folder_id is None:
            console.print(f"[red]Folder not found:[/red] {folder}")
            if folder_map:
                available = ", ".join(
                    sorted(name for name in folder_map.values() if name)
                )
                console.print(f"Available folders: {available}")
            raise typer.Exit(code=1)

        scans = [
            scan
            for scan in scans
            if scan.get("folder_id") is not None
            and int(scan.get("folder_id")) == folder_id
        ]
        if not scans:
            console.print(
                f"[yellow]No scans found in folder '{folder_map[folder_id]}'.[/yellow]"
            )
            return

    table = Table(title="Nessus Scans", box=box.ROUNDED)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Folder", style="white", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Last Modified", no_wrap=True)

    if include_details:
        table.add_column("Runs", justify="right", no_wrap=True)
        table.add_column("Creds", no_wrap=True)

    if include_details:
        with console.status(
            "Fetching per-scan details from Nessus...",
            spinner="dots",
        ) as status:
            for scan in scans:
                scan_id = int(scan.get("id", 0))
                scan_name = str(scan.get("name", "") or scan_id)
                status.update(f"Fetching details for {scan_name} ({scan_id})...")
                _add_detailed_scan_row(
                    table, client, scan, _resolve_folder_name(folder_map, scan)
                )
    else:
        for scan in scans:
            _add_basic_scan_row(table, scan, _resolve_folder_name(folder_map, scan))

    console.print(table)


def ping() -> None:
    """Test basic Nessus API connectivity."""

    client = _build_client()

    try:
        scan_count = client.check_connection()
    except requests.RequestException as exc:
        console.print(f"[red]Connection failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(
        "[green]Connection successful.[/green] "
        f"Authenticated to Nessus and found {scan_count} scan(s)."
    )


def get_scan(scan_name: str) -> None:
    """Resolve a scan by name and print its scan ID."""

    client = _build_client()
    scan = client.find_scan_by_name(scan_name)

    if scan is None:
        console.print(f"[red]Scan not found:[/red] {scan_name}")
        raise typer.Exit(code=1)

    console.print(str(scan.get("id", "")))
