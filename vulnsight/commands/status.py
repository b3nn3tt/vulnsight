"""Command for displaying a quick operational status snapshot."""

from __future__ import annotations

import json
import shutil
from typing import Any

import requests
from rich import box
from rich.console import Console
from rich.table import Table

from vulnsight.client import NessusClient
from vulnsight.commands.findings import SEVERITY_LABELS
from vulnsight.commands.history import _format_timestamp, _get_sorted_history_entries
from vulnsight.commands.report import DEFAULT_TEMPLATE_PATH
from vulnsight.config import get_settings
from vulnsight.context import CONTEXT_FILE, load_context


console = Console()


def _load_status_context() -> tuple[dict[str, Any], str | None]:
    """Load context for status output without crashing on invalid JSON."""

    if not CONTEXT_FILE.exists():
        return {}, None

    try:
        return load_context(), None
    except json.JSONDecodeError:
        return {}, "Context file is present but invalid."


def _get_selected_history_entry(
    scan_details: dict[str, Any], history_id: int
) -> dict[str, Any] | None:
    """Return the selected history entry from scan details."""

    for entry in scan_details.get("history", []):
        if int(entry.get("history_id", 0) or 0) == history_id:
            return entry
    return None


def _get_previous_history_entry(
    scan_details: dict[str, Any], history_id: int
) -> dict[str, Any] | None:
    """Return the previous scan run relative to the selected history ID."""

    history_entries = _get_sorted_history_entries(scan_details)
    current_index = next(
        (
            index
            for index, entry in enumerate(history_entries)
            if int(entry.get("history_id", 0) or 0) == history_id
        ),
        None,
    )
    if current_index is None:
        return None

    previous_index = current_index + 1
    if previous_index >= len(history_entries):
        return None

    return history_entries[previous_index]


def _build_severity_counts(vulnerabilities: list[dict[str, Any]]) -> dict[int, int]:
    """Count findings by severity from scan result details."""

    counts = {level: 0 for level in SEVERITY_LABELS}
    for vulnerability in vulnerabilities:
        severity = int(vulnerability.get("severity", 0) or 0)
        if severity in counts:
            counts[severity] += 1
    return counts


def _format_availability(available: bool, present_label: str, missing_label: str) -> str:
    """Render a simple availability label."""

    if available:
        return f"[green]{present_label}[/green]"
    return f"[yellow]{missing_label}[/yellow]"


def _build_suggestions(
    has_context: bool,
    has_previous_run: bool,
    has_live_scan_data: bool,
    pandoc_available: bool,
    template_present: bool,
) -> list[str]:
    """Build a short set of next-step suggestions."""

    if not has_context:
        return [
            "Run `python main.py scans` to list available scans.",
            "Run `python main.py use \"<scan name>\"` to select a scan context.",
            "Run `python main.py doctor` to validate the local environment.",
        ]

    suggestions = ["Run `python main.py summary` to review findings."]

    if has_live_scan_data and has_previous_run:
        suggestions.append("Run `python main.py diff` to compare the current run with the previous run.")

    if has_live_scan_data and pandoc_available and template_present:
        suggestions.append("Run `python main.py report --format docx` to generate a report.")
    else:
        suggestions.append("Run `python main.py doctor` to review environment issues before generating reports.")

    return suggestions


def show_status() -> None:
    """Display a read-only operational snapshot for the current CLI context."""

    context, context_error = _load_status_context()
    settings = get_settings()
    pandoc_available = shutil.which("pandoc") is not None
    template_present = DEFAULT_TEMPLATE_PATH.exists()

    scan_name = "not set"
    scan_date = "not set"
    history_id_label = "not set"
    previous_run_label = "not set"
    host_count = "n/a"
    severity_counts = {level: "n/a" for level in SEVERITY_LABELS}
    has_live_scan_data = False

    if context:
        scan_name = str(context.get("scan_name", "") or "not set")
        scan_id = int(context.get("scan_id", 0) or 0)
        history_id = int(context.get("history_id", 0) or 0)
        history_id_label = str(history_id) if history_id else "not set"

        if settings.access_key and settings.secret_key and scan_id and history_id:
            client = NessusClient(settings)

            try:
                scan_details = client.get_scan_details(scan_id)
                selected_history = _get_selected_history_entry(scan_details, history_id)
                previous_history = _get_previous_history_entry(scan_details, history_id)

                if selected_history is not None:
                    scan_date = _format_timestamp(selected_history.get("creation_date"))

                if previous_history is not None:
                    previous_history_id = int(previous_history.get("history_id", 0) or 0)
                    previous_date = _format_timestamp(previous_history.get("creation_date"))
                    previous_run_label = f"{previous_history_id} ({previous_date})"

                scan_result_details = client.get_scan_result_details(scan_id, history_id)
                hosts = scan_result_details.get("hosts", [])
                vulnerabilities = scan_result_details.get("vulnerabilities", [])
                host_count = str(len(hosts))
                severity_counts = _build_severity_counts(vulnerabilities)
                has_live_scan_data = True
            except requests.RequestException as exc:
                previous_run_label = "unavailable"
                host_count = "unavailable"
                severity_counts = {level: "unavailable" for level in SEVERITY_LABELS}
                if scan_date == "not set":
                    scan_date = "unavailable"
                context_error = f"Unable to refresh scan status from Nessus: {exc}"
        else:
            context_error = "Nessus API credentials are not configured, so live scan details are unavailable."

    status_table = Table(title="VulnSight Status", box=box.ROUNDED)
    status_table.add_column("Field", style="cyan", no_wrap=True)
    status_table.add_column("Value", style="white")
    status_table.add_row("Current Scan", scan_name)
    status_table.add_row("Scan Date", scan_date)
    status_table.add_row("History ID", history_id_label)
    status_table.add_row("Previous Run", previous_run_label)

    counts_table = Table(title="Summary Counts", box=box.ROUNDED)
    counts_table.add_column("Metric", style="cyan", no_wrap=True)
    counts_table.add_column("Value", justify="right", style="white")
    counts_table.add_row("Hosts", str(host_count))
    for level in (4, 3, 2, 1, 0):
        counts_table.add_row(SEVERITY_LABELS[level], str(severity_counts[level]))

    environment_table = Table(title="Environment", box=box.ROUNDED)
    environment_table.add_column("Check", style="cyan", no_wrap=True)
    environment_table.add_column("Status", style="white")
    environment_table.add_row(
        "Pandoc",
        _format_availability(pandoc_available, "available", "not found"),
    )
    environment_table.add_row(
        "Report Template",
        _format_availability(template_present, "found", "missing"),
    )

    suggestions = _build_suggestions(
        bool(context),
        previous_run_label not in {"not set", "unavailable"},
        has_live_scan_data,
        pandoc_available,
        template_present,
    )

    console.print(status_table)
    console.print()
    console.print(counts_table)
    console.print()
    console.print(environment_table)

    if context_error:
        console.print()
        console.print(f"[yellow]{context_error}[/yellow]")

    console.print()
    console.print("Suggested Next Actions", highlight=False)
    for suggestion in suggestions:
        console.print(f"- {suggestion}", highlight=False)
