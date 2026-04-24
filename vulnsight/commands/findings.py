"""Command for displaying aggregated scan findings."""

from __future__ import annotations

import csv
import sys

import requests
import typer
from rich import box
from rich.console import Console
from rich.table import Table

from vulnsight.commands.finding import build_finding_data
from vulnsight.commands.remediation import clean_recommendation, has_recommendation
from vulnsight.commands.scans import _build_client
from vulnsight.context import load_context
from vulnsight.validation import (
    get_validation,
    get_validation_display,
    parse_validation_status,
)


console = Console()

SEVERITY_MAP = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITY_LABELS = {
    0: "Info",
    1: "Low",
    2: "Medium",
    3: "High",
    4: "Critical",
}

SEVERITY_STYLES = {
    0: "dim",
    1: "green",
    2: "blue",
    3: "yellow",
    4: "red",
}


def _validate_output_format(output_format: str) -> str:
    """Validate the requested output format."""

    value = str(output_format or "table").strip().lower()
    if value not in {"table", "csv"}:
        console.print("[red]Invalid format.[/red] Use one of: table, csv.")
        raise typer.Exit(code=1)
    return value


def _write_findings_csv(rows: list[dict]) -> None:
    """Write scan-level findings rows as CSV to stdout."""

    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(
        ["id", "name", "severity", "count", "host_count", "hosts", "validation_status"]
    )

    for row in rows:
        writer.writerow(
            [
                int(row["id"]),
                str(row["name"]),
                str(row["severity"]),
                int(row["count"]),
                int(row["host_count"]),
                "|".join(row["hosts"]),
                str(row["validation_status"]),
            ]
        )


def _resolve_validation_filter(validation_status: str | None) -> str | None:
    """Validate an optional validation-status filter."""

    try:
        return parse_validation_status(validation_status)
    except ValueError:
        console.print(
            "[red]Invalid validation status.[/red] "
            "Use one of: confirmed, false_positive, unreviewed."
        )
        raise typer.Exit(code=1)


def _format_host_entry(hostname: str, port: str) -> str:
    """Build a readable host entry including port when available."""

    if hostname and port and port != "0":
        return f"{hostname}:{port}"
    return hostname


def _extract_hosts_from_outputs(outputs: list[dict]) -> list[str]:
    """Extract a sorted host list from plugin output entries."""

    hosts: set[str] = set()

    for output in outputs:
        hostname = str(output.get("hostname") or output.get("host") or "").strip()
        port = str(output.get("port") or "").strip()

        host_entry = _format_host_entry(hostname, port)
        if host_entry:
            hosts.add(host_entry)

    return sorted(hosts)


def _format_severity(severity: int | str | None) -> str:
    """Render a severity value using a label and colour."""

    try:
        level = int(severity)
    except (TypeError, ValueError):
        return "Unknown"

    label = SEVERITY_LABELS.get(level, "Unknown")
    style = SEVERITY_STYLES.get(level)
    if style is None:
        return label
    return f"[{style}]{label}[/{style}]"


def _resolve_minimum_severity(severity: str | None) -> int | None:
    """Validate and convert a severity filter into its numeric threshold."""

    if severity is None:
        return None

    level = SEVERITY_MAP.get(severity.strip().lower())
    if level is None:
        console.print(
            "[red]Invalid severity.[/red] "
            "Use one of: info, low, medium, high, critical."
        )
        raise typer.Exit(code=1)

    return level


def _get_plugin_hosts_from_host_details(
    client,
    scan_id: int,
    history_id: int,
    plugin_id: int,
    scan_hosts: list[dict],
) -> list[str]:
    """Return impacted hosts for a plugin by checking host-level plugin output."""

    hosts: set[str] = set()

    for host in scan_hosts:
        host_id = host.get("host_id")
        if host_id is None:
            continue

        try:
            host_plugin_details = client.get_host_plugin_output(
                scan_id, int(host_id), plugin_id, history_id
            )
        except requests.RequestException:
            continue

        outputs = host_plugin_details.get("outputs", [])
        output_hosts = _extract_hosts_from_outputs(outputs)
        if output_hosts:
            hosts.update(output_hosts)
            continue

        if not outputs and not host_plugin_details:
            continue

        hostname = str(
            host.get("hostname") or host.get("host") or host.get("ip") or ""
        ).strip()
        port = str(host.get("port") or "").strip()
        host_entry = _format_host_entry(hostname, port)
        if host_entry:
            hosts.add(host_entry)

    return sorted(hosts)


def _get_plugin_hosts(
    client, scan_id: int, history_id: int, plugin_id: int, scan_hosts: list[dict]
) -> list[str]:
    """Return a sorted list of impacted hosts for a plugin."""

    details = client.get_plugin_details(scan_id, plugin_id, history_id)
    hosts = _extract_hosts_from_outputs(details.get("outputs", []))
    if hosts:
        return hosts

    return _get_plugin_hosts_from_host_details(
        client, scan_id, history_id, plugin_id, scan_hosts
    )


def _format_hosts_display(hosts: list[str], limit: int = 5) -> str:
    """Format a host list for compact table display."""

    if not hosts:
        return "-"

    if len(hosts) <= limit:
        return ", ".join(hosts)

    return f"{', '.join(hosts[:limit])}, ..."


def _get_scan_host_names(scan_hosts: list[dict]) -> list[str]:
    """Return the sorted list of host names present in the scan."""

    host_names = {
        str(host.get("hostname") or host.get("host") or "").strip()
        for host in scan_hosts
        if str(host.get("hostname") or host.get("host") or "").strip()
    }
    return sorted(host_names)


def _get_remediation_data(
    client,
    scan_details: dict,
    scan_id: int,
    history_id: int,
    plugin_id: int,
) -> tuple[list[str], str]:
    """Return hosts and cleaned recommendation guidance for a finding."""

    try:
        finding = build_finding_data(
            client,
            scan_details,
            scan_id,
            history_id,
            plugin_id,
        )
    except requests.RequestException:
        return [], clean_recommendation("")
    except ValueError:
        return [], clean_recommendation("")

    hosts = [str(host) for host in finding.get("hosts", [])]
    recommendation = clean_recommendation(str(finding.get("solution") or ""))
    return hosts, recommendation


def _print_remediation_block(
    name: str,
    plugin_id: int,
    severity_value: int,
    hosts: list[str],
    recommendation: str,
    validation_status: str,
) -> None:
    """Render one remediation block for findings output."""

    severity_label = SEVERITY_LABELS.get(severity_value, "Unknown").upper()

    console.print(
        f"[{severity_label}] {name} (ID: {plugin_id})",
        highlight=False,
    )
    console.print(
        f"Hosts: {', '.join(hosts) if hosts else 'No host information available'}",
        highlight=False,
    )
    console.print(f"Validation: {validation_status}", highlight=False)
    console.print()
    console.print("Recommendation:", highlight=False)
    console.print(recommendation, highlight=False)
    console.print()
    console.print("-" * 50, highlight=False)


def _resolve_remediation_filters(
    severity: str | None,
    min_severity: str | None,
    exact_severity: int | None,
    minimum_severity: int | None,
) -> tuple[int | None, int | None]:
    """Apply recommendation-specific severity rules."""

    if severity is None and min_severity is None:
        return exact_severity, 0

    return exact_severity, minimum_severity


def _confirm_info_recommendation_output(
    exact_severity: int | None,
    minimum_severity: int | None,
) -> None:
    """Warn before rendering recommendation output that includes info findings."""

    includes_info = exact_severity == 0 or (
        exact_severity is None and minimum_severity is not None and minimum_severity <= 0
    )
    if not includes_info:
        return

    console.print(
        "[yellow]Recommendation output including informational findings may produce a large amount of output.[/yellow]"
    )
    if not typer.confirm("Continue?", default=False):
        raise typer.Exit(code=1)


def list_findings(
    severity: str | None = None,
    host: str | None = None,
    min_severity: str | None = None,
    remediation: bool = False,
    output_format: str = "table",
    validation_status: str | None = None,
    exclude_validation_status: str | None = None,
    exclude_false_positives: bool = False,
) -> None:
    """Display aggregated findings for the currently selected scan."""

    context = load_context()
    if not context:
        console.print(
            "[red]No active scan context.[/red] "
            "Use 'vulnsight use <scan_name>' first."
        )
        raise typer.Exit(code=1)

    if severity and min_severity:
        console.print("[red]Use either --severity or --min-severity, not both.[/red]")
        return

    exact_severity = _resolve_minimum_severity(severity) if severity else None
    minimum_severity = _resolve_minimum_severity(min_severity) if min_severity else None
    resolved_format = _validate_output_format(output_format)
    resolved_validation_status = _resolve_validation_filter(validation_status)
    resolved_exclude_validation_status = _resolve_validation_filter(exclude_validation_status)

    if (
        resolved_validation_status is not None
        and resolved_exclude_validation_status is not None
    ):
        console.print("[red]Use either --only/--validation or --exclude, not both.[/red]")
        raise typer.Exit(code=1)

    if remediation:
        exact_severity, minimum_severity = _resolve_remediation_filters(
            severity,
            min_severity,
            exact_severity,
            minimum_severity,
        )
        _confirm_info_recommendation_output(exact_severity, minimum_severity)

    client = _build_client()
    scan_id = int(context.get("scan_id", 0))
    history_id = int(context.get("history_id", 0))
    scan_name = str(context.get("scan_name", ""))

    try:
        details = client.get_scan_result_details(scan_id, history_id)
    except requests.RequestException as exc:
        console.print(f"[red]Failed to retrieve scan findings:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    scan_hosts = details.get("hosts", [])
    scan_host_names = _get_scan_host_names(scan_hosts)
    findings = details.get("vulnerabilities", [])

    if host is not None:
        host = host.strip()
        if host not in scan_host_names:
            console.print(f"[red]Host '{host}' not found in this scan.[/red]")
            console.print("Use 'vulnsight hosts' to list valid hosts.")
            return

    if minimum_severity is not None:
        findings = [
            finding
            for finding in findings
            if int(finding.get("severity", 0) or 0) >= minimum_severity
        ]

    findings = sorted(
        findings,
        key=lambda finding: (
            int(finding.get("severity", 0) or 0),
            int(finding.get("count", 0) or 0),
        ),
        reverse=True,
    )

    if not findings:
        if resolved_format == "csv":
            _write_findings_csv([])
            return
        console.print("[yellow]No findings found for the selected criteria.[/yellow]")
        return

    rows: list[dict] = []
    for finding in findings:
        plugin_id = int(finding.get("plugin_id", 0) or 0)
        severity_value = int(finding.get("severity", 0) or 0)

        if exact_severity is not None and severity_value != exact_severity:
            continue

        if minimum_severity is not None and severity_value < minimum_severity:
            continue

        try:
            hosts = _get_plugin_hosts(client, scan_id, history_id, plugin_id, scan_hosts)
        except requests.RequestException:
            hosts = []

        if host and host not in hosts:
            continue

        validation = get_validation(scan_id, history_id, plugin_id)
        effective_validation_status = str(validation.get("status") or "unreviewed")
        validation_display = get_validation_display(effective_validation_status)

        if resolved_validation_status is not None and effective_validation_status != resolved_validation_status:
            continue

        if (
            resolved_exclude_validation_status is not None
            and effective_validation_status == resolved_exclude_validation_status
        ):
            continue

        if exclude_false_positives and effective_validation_status == "false_positive":
            continue

        if remediation:
            remediation_hosts, recommendation = _get_remediation_data(
                client,
                details,
                scan_id,
                history_id,
                plugin_id,
            )

            if host and host not in remediation_hosts:
                continue

            if not has_recommendation(recommendation):
                continue

            rows.append(
                {
                    "id": plugin_id,
                    "name": str(finding.get("plugin_name", "")),
                    "severity_value": severity_value,
                    "severity": SEVERITY_LABELS.get(severity_value, "Unknown"),
                    "count": int(finding.get("count", 0) or 0),
                    "host_count": len(set(remediation_hosts)),
                    "hosts": remediation_hosts,
                    "recommendation": recommendation,
                    "validation_status": validation_display,
                }
            )
            continue

        rows.append(
            {
                "id": plugin_id,
                "name": str(finding.get("plugin_name", "")),
                "severity_value": severity_value,
                "severity": SEVERITY_LABELS.get(severity_value, "Unknown"),
                "count": int(finding.get("count", 0) or 0),
                "host_count": len(set(hosts)),
                "hosts": hosts,
                "validation_status": validation_display,
            }
        )

    if resolved_format == "csv":
        csv_rows = [
            {
                "id": row["id"],
                "name": row["name"],
                "severity": row["severity"],
                "count": row["count"],
                "host_count": row["host_count"],
                "hosts": row["hosts"],
                "validation_status": row["validation_status"],
            }
            for row in rows
        ]
        _write_findings_csv(csv_rows)
        return

    if remediation:
        if not rows:
            if host:
                console.print(f"[yellow]No findings for host '{host}' with current filters.[/yellow]")
                return
            console.print("[yellow]No findings with recommendation guidance were found for the selected criteria.[/yellow]")
            return

        for row in rows:
            _print_remediation_block(
                str(row["name"]),
                int(row["id"]),
                int(row["severity_value"]),
                list(row["hosts"]),
                str(row["recommendation"]),
                str(row["validation_status"]),
            )
        return

    if exact_severity is not None:
        label = SEVERITY_LABELS[exact_severity]
        console.print(f"[dim]Note: Showing findings with severity = {label}[/dim]")
    elif minimum_severity is not None:
        label = SEVERITY_LABELS[minimum_severity]
        console.print(f"[dim]Note: Showing findings with severity >= {label}[/dim]")

    if len(scan_host_names) == 1 and host is None:
        console.print(f"[dim]Scan contains a single host: {scan_host_names[0]}[/dim]")

    table = Table(title=f"Findings: {scan_name or scan_id}", box=box.ROUNDED)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Count", justify="right", no_wrap=True)
    table.add_column("Hosts", style="white")
    table.add_column("Validation", no_wrap=True)

    if not rows:
        if host:
            console.print(f"[yellow]No findings for host '{host}' with current filters.[/yellow]")
            return
        console.print("[yellow]No findings found for the selected criteria.[/yellow]")
        return

    for row in rows:
        table.add_row(
            str(row["id"]),
            str(row["name"]),
            _format_severity(int(row["severity_value"])),
            str(row["count"]),
            _format_hosts_display(list(row["hosts"])),
            str(row["validation_status"]),
        )

    console.print(table)
