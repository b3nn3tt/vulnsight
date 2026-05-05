"""Command for selecting an active scan context."""

from __future__ import annotations

import requests
import typer
from rich.console import Console

from vulnsight.commands.scans import _build_client
from vulnsight.context import save_context


console = Console()


def _resolve_scan_selector(
    positional_name: str | None,
    option_name: str | None,
    scan_id: int | None,
) -> tuple[str, str | int]:
    """Validate and return the requested scan selector."""

    selectors: list[tuple[str, str | int]] = []
    if positional_name is not None:
        selectors.append(("name", positional_name))
    if option_name is not None:
        selectors.append(("name", option_name))
    if scan_id is not None:
        selectors.append(("id", scan_id))

    if len(selectors) != 1:
        console.print(
            "[red]Choose exactly one scan selector.[/red] "
            "Use a scan name, --name, or --id."
        )
        raise typer.Exit(code=1)

    selector_type, selector_value = selectors[0]
    if selector_type == "name":
        resolved_name = str(selector_value).strip()
        if not resolved_name:
            console.print("[red]Scan name cannot be empty.[/red]")
            raise typer.Exit(code=1)
        return selector_type, resolved_name

    resolved_id = int(selector_value)
    if resolved_id < 1:
        console.print("[red]Scan ID must be 1 or greater.[/red]")
        raise typer.Exit(code=1)
    return selector_type, resolved_id


def _get_latest_completed_history(scan_details: dict) -> dict:
    """Return the latest completed history entry from scan details."""

    completed_runs = [
        entry
        for entry in scan_details.get("history", [])
        if str(entry.get("status", "")).lower() == "completed"
    ]

    if not completed_runs:
        raise ValueError("No completed scan runs found.")

    return max(
        completed_runs,
        key=lambda entry: (
            int(entry.get("creation_date", 0) or 0),
            int(entry.get("history_id", 0) or 0),
        ),
    )


def _get_scan_name(scan: dict | None, scan_details: dict, fallback: str) -> str:
    """Return the best available scan name."""

    info = scan_details.get("info", {})
    values = [
        scan.get("name") if scan else None,
        scan_details.get("name"),
        info.get("name") if isinstance(info, dict) else None,
        fallback,
    ]
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return fallback


def use_scan(
    positional_name: str | None = None,
    option_name: str | None = None,
    scan_id: int | None = None,
) -> None:
    """Resolve a scan selector, select its latest completed run, and save context."""

    client = _build_client()
    selector_type, selector_value = _resolve_scan_selector(
        positional_name,
        option_name,
        scan_id,
    )
    scan: dict | None = None

    try:
        if selector_type == "name":
            scan_name = str(selector_value)
            with console.status(
                f"Resolving scan '{scan_name}' from Nessus...",
                spinner="dots",
            ) as status:
                scan = client.find_scan_by_name(scan_name)
                if scan is None:
                    console.print(f"[red]Scan not found:[/red] {scan_name}")
                    raise typer.Exit(code=1)

                resolved_scan_id = int(scan.get("id", 0))
                status.update("Fetching scan history from Nessus...")
                scan_details = client.get_scan_details(resolved_scan_id)
                history = _get_latest_completed_history(scan_details)
        else:
            resolved_scan_id = int(selector_value)
            with console.status(
                f"Fetching scan {resolved_scan_id} from Nessus...",
                spinner="dots",
            ):
                scan_details = client.get_scan_details(resolved_scan_id)
                history = _get_latest_completed_history(scan_details)
    except requests.ReadTimeout as exc:
        console.print(
            "[red]Timed out while retrieving scan details from Nessus.[/red] "
            "Try again, increase NESSUS_TIMEOUT, or check the scan in Nessus."
        )
        raise typer.Exit(code=1) from exc
    except requests.RequestException as exc:
        console.print(f"[red]Failed to retrieve scan details:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except ValueError:
        console.print(f"[red]No completed runs found for scan:[/red] {selector_value}")
        raise typer.Exit(code=1)

    history_id = int(history.get("history_id", 0))
    resolved_name = _get_scan_name(scan, scan_details, str(selector_value))

    save_context(
        scan_id=resolved_scan_id,
        history_id=history_id,
        scan_name=resolved_name,
    )

    console.print(f"Using scan: {resolved_name}")
    console.print(f"Scan ID   : {resolved_scan_id}")
    console.print(f"History ID: {history_id}")
