"""Commands for viewing and updating finding validation state."""

from __future__ import annotations

import requests
import typer
from rich import box
from rich.console import Console
from rich.table import Table

from vulnsight.commands.findings import SEVERITY_LABELS, _format_severity
from vulnsight.commands.scans import _build_client
from vulnsight.context import load_context
from vulnsight.validation import (
    get_validation,
    get_validation_display,
    parse_validation_status,
    write_validation,
)


console = Console()


def _get_active_context() -> tuple[int, int, str]:
    """Return the current scan context values."""

    context = load_context()
    if not context:
        console.print(
            "[red]No active scan context.[/red] "
            "Use 'vulnsight use <scan_name>' first."
        )
        raise typer.Exit(code=1)

    return (
        int(context.get("scan_id", 0)),
        int(context.get("history_id", 0)),
        str(context.get("scan_name", "")),
    )


def _resolve_validation_status(status: str | None, *, required: bool = False) -> str | None:
    """Validate a user-supplied validation status."""

    try:
        return parse_validation_status(status, required=required)
    except ValueError:
        console.print(
            "[red]Invalid validation status.[/red] "
            "Use one of: confirmed, false_positive, unreviewed."
        )
        raise typer.Exit(code=1)


def _get_scan_findings(scan_id: int, history_id: int) -> dict:
    """Load the current scan findings for validation operations."""

    client = _build_client()
    try:
        return client.get_scan_result_details(scan_id, history_id)
    except requests.RequestException as exc:
        console.print(f"[red]Failed to retrieve scan findings:[/red] {exc}")
        raise typer.Exit(code=1) from exc


def _get_finding_summary(scan_details: dict, plugin_id: int) -> dict | None:
    """Return one finding summary from the current scan results."""

    for vulnerability in scan_details.get("vulnerabilities", []):
        if int(vulnerability.get("plugin_id", 0) or 0) == plugin_id:
            return vulnerability
    return None


def run_validate(plugin_id: int, status: str, note: str | None = None) -> None:
    """Store or clear validation for a finding in the current scan run."""

    scan_id, history_id, scan_name = _get_active_context()
    resolved_status = _resolve_validation_status(status, required=True)
    scan_details = _get_scan_findings(scan_id, history_id)
    finding_summary = _get_finding_summary(scan_details, plugin_id)

    if finding_summary is None:
        console.print(f"[red]Plugin ID '{plugin_id}' not found in this scan.[/red]")
        raise typer.Exit(code=1)

    write_validation(
        scan_id,
        scan_name,
        history_id,
        plugin_id,
        resolved_status,
        note,
    )

    finding_name = str(finding_summary.get("plugin_name", ""))
    display_status = get_validation_display(resolved_status)

    if resolved_status == "unreviewed":
        console.print(f"[green]Validation cleared:[/green] {finding_name} ({plugin_id})")
        console.print("Status: Unreviewed", highlight=False)
        return

    console.print(f"[green]Validation saved:[/green] {finding_name} ({plugin_id})")
    console.print(f"Status: {display_status}", highlight=False)
    if note:
        console.print(f"Note  : {note}", highlight=False)


def show_validation(status: str | None = None) -> None:
    """Show validation state for findings in the current scan run."""

    scan_id, history_id, scan_name = _get_active_context()
    resolved_status = _resolve_validation_status(status)
    scan_details = _get_scan_findings(scan_id, history_id)

    findings = sorted(
        scan_details.get("vulnerabilities", []),
        key=lambda finding: (
            int(finding.get("severity", 0) or 0),
            str(finding.get("plugin_name", "")).lower(),
        ),
        reverse=True,
    )

    table = Table(title=f"Validation: {scan_name or scan_id}", box=box.ROUNDED)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Validation", no_wrap=True)
    table.add_column("Notes", style="white")
    table.add_column("Validated At", no_wrap=True)

    rows_added = 0
    for finding in findings:
        plugin_id = int(finding.get("plugin_id", 0) or 0)
        severity_value = int(finding.get("severity", 0) or 0)
        validation = get_validation(scan_id, history_id, plugin_id)
        validation_status = str(validation.get("status") or "unreviewed")

        if resolved_status is not None and validation_status != resolved_status:
            continue

        table.add_row(
            str(plugin_id),
            str(finding.get("plugin_name", "")),
            _format_severity(severity_value),
            get_validation_display(validation_status),
            str(validation.get("notes") or ""),
            str(validation.get("validated_at") or ""),
        )
        rows_added += 1

    if rows_added == 0:
        if resolved_status is not None:
            console.print(
                f"[yellow]No findings with validation status '{get_validation_display(resolved_status)}' were found.[/yellow]"
            )
            return
        console.print("[yellow]No findings available for validation.[/yellow]")
        return

    console.print(table)
