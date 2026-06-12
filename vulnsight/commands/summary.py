"""Command for displaying a severity summary for the active scan context."""

from __future__ import annotations

import csv
import sys
from typing import Any

import requests
import typer
from rich import box
from rich.console import Console
from rich.table import Table

from vulnsight.commands.findings import (
    SEVERITY_LABELS,
    _format_severity,
    _get_plugin_hosts,
    _get_scan_host_names,
    _resolve_minimum_severity,
)
from vulnsight.commands.scans import _build_client
from vulnsight.context import load_context
from vulnsight.validation import get_validation, get_validation_display


console = Console()

TOP_RISK_MODES = {"severity", "volume", "weighted"}
SORT_DIRECTIONS = {"asc", "desc"}
SEVERITY_WEIGHTS = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def _validate_top_risks_mode(top_risks: str | None) -> str | None:
    """Validate the requested Top Risks mode."""

    if top_risks is None:
        return None

    mode = top_risks.strip().lower()
    if mode not in TOP_RISK_MODES:
        console.print(
            "[red]Invalid top risks mode.[/red] "
            "Use one of: severity, volume, weighted."
        )
        raise typer.Exit(code=1)

    return mode


def _validate_sort_direction(sort: str) -> str:
    """Validate the requested sort direction."""

    direction = sort.strip().lower()
    if direction not in SORT_DIRECTIONS:
        console.print("[red]Invalid sort.[/red] Use one of: asc, desc.")
        raise typer.Exit(code=1)

    return direction


def _validate_limit(limit: int) -> int:
    """Validate the requested Top Risks row limit."""

    if limit < 1:
        console.print("[red]Invalid limit.[/red] Limit must be 1 or greater.")
        raise typer.Exit(code=1)

    return limit


def _resolve_host_scope(
    scan_hosts: list[dict[str, Any]],
    host: list[str] | None,
    exclude_host: list[str] | None,
) -> tuple[list[str], set[str], str] | None:
    """Validate and build the requested host scope."""

    all_hosts = _get_scan_host_names(scan_hosts)

    requested_hosts = host or exclude_host or []
    invalid_hosts = [value for value in requested_hosts if value not in all_hosts]
    if invalid_hosts:
        console.print(f"[red]Host '{invalid_hosts[0]}' not found in this scan.[/red]")
        console.print("Use 'vulnsight hosts' to list valid hosts.")
        return None

    if host:
        scoped_hosts = set(host)
        scope_label = f"Scope          : {', '.join(host)}"
    elif exclude_host:
        scoped_hosts = set(all_hosts) - set(exclude_host)
        scope_label = f"Scope          : All hosts (excluding {', '.join(exclude_host)})"
    else:
        scoped_hosts = set(all_hosts)
        scope_label = "Scope          : All hosts"

    if not scoped_hosts:
        console.print("[yellow]No hosts remain in scope after applying filters.[/yellow]")
        return None

    return all_hosts, scoped_hosts, scope_label


def _aggregate_summary_findings(
    client,
    scan_id: int,
    history_id: int,
    scan_hosts: list[dict[str, Any]],
    scoped_hosts: set[str],
    minimum_severity: int | None,
    vulnerabilities: list[dict[str, Any]],
) -> dict[int, dict[str, Any]]:
    """Aggregate scoped findings for summary and Top Risks output."""

    aggregated_findings: dict[int, dict[str, Any]] = {}

    for vulnerability in vulnerabilities:
        plugin_id = int(vulnerability.get("plugin_id", 0) or 0)
        severity = int(vulnerability.get("severity", 0) or 0)

        if minimum_severity is not None and severity < minimum_severity:
            continue

        try:
            plugin_hosts = _get_plugin_hosts(
                client, scan_id, history_id, plugin_id, scan_hosts
            )
        except requests.RequestException:
            plugin_hosts = []

        if not (set(plugin_hosts) & scoped_hosts):
            continue

        aggregated_findings[plugin_id] = {
            "plugin_id": plugin_id,
            "name": str(vulnerability.get("plugin_name", "")),
            "severity": severity,
            "instances": int(vulnerability.get("count", 0) or 0),
            "hosts": plugin_hosts,
        }

    return aggregated_findings


def _format_scope_hosts(scoped_hosts: set[str], limit: int = 12) -> str:
    """Render the in-scope hosts as a readable, length-bounded list."""

    hosts = sorted(scoped_hosts)
    if not hosts:
        return "None"
    if len(hosts) <= limit:
        return ", ".join(hosts)
    shown = ", ".join(hosts[:limit])
    return f"{shown} (+{len(hosts) - limit} more)"


def _print_summary_header(
    scan_name: str,
    scan_id: int,
    all_hosts: list[str],
    scoped_hosts: set[str],
    scope_label: str,
    minimum_severity: int | None,
) -> None:
    """Render the main scan summary header and counts."""

    console.print(f"Summary: {scan_name or scan_id}", highlight=False)
    console.print()
    console.print(f"Hosts in scan  : {len(all_hosts)}", highlight=False)
    console.print(f"Hosts in scope : {len(scoped_hosts)}", highlight=False)
    console.print(scope_label, highlight=False)
    console.print(f"Hosts          : {_format_scope_hosts(scoped_hosts)}", highlight=False)
    console.print()

    if minimum_severity is not None:
        label = SEVERITY_LABELS[minimum_severity]
        console.print(f"Note: Showing findings with severity >= {label}", highlight=False)
        console.print()


VALIDATION_ORDER = ("confirmed", "false_positive", "unreviewed")


def _build_severity_validation_matrix(
    aggregated_findings: dict[int, dict[str, Any]],
    scan_id: int,
    history_id: int,
) -> dict[int, dict[str, int]]:
    """Build per-severity totals broken down by validation status.

    Returns a mapping of severity level to a row with a ``total`` plus a count
    per validation status. The ``total`` preserves the raw severity metric.
    """

    matrix = {
        level: {"total": 0, "confirmed": 0, "false_positive": 0, "unreviewed": 0}
        for level in SEVERITY_LABELS
    }

    for finding in aggregated_findings.values():
        level = int(finding["severity"])
        if level not in matrix:
            continue
        status = str(
            get_validation(scan_id, history_id, int(finding["plugin_id"])).get("status")
            or "unreviewed"
        )
        row = matrix[level]
        row["total"] += 1
        row[status] = int(row.get(status, 0)) + 1

    return matrix


def _validate_summary_format(output_format: str) -> str:
    """Validate the requested summary output format."""

    value = str(output_format or "table").strip().lower()
    if value not in {"table", "csv"}:
        console.print("[red]Invalid format.[/red] Use one of: table, csv.")
        raise typer.Exit(code=1)
    return value


def _write_summary_csv(
    matrix: dict[int, dict[str, int]], scoped_hosts: set[str]
) -> None:
    """Write the severity-by-validation matrix as CSV to stdout (chart-ready).

    A leading ``host`` column names the covered host when the scope is a single
    host, otherwise ``ALL`` (use ``--by-host`` for per-host rows).
    """

    hosts = sorted(scoped_hosts)
    host_value = hosts[0] if len(hosts) == 1 else "ALL"

    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(
        ["host", "severity", "total", "confirmed", "false_positive", "unreviewed"]
    )
    for level in (4, 3, 2, 1, 0):
        row = matrix[level]
        writer.writerow(
            [
                host_value,
                SEVERITY_LABELS[level],
                int(row["total"]),
                int(row["confirmed"]),
                int(row["false_positive"]),
                int(row["unreviewed"]),
            ]
        )


def _print_severity_validation_matrix(matrix: dict[int, dict[str, int]]) -> None:
    """Render the severity-by-validation matrix as a table."""

    table = Table(box=box.ROUNDED)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Total", justify="right", no_wrap=True)
    for status in VALIDATION_ORDER:
        table.add_column(get_validation_display(status), justify="right", no_wrap=True)

    for level in (4, 3, 2, 1, 0):
        row = matrix[level]
        table.add_row(
            _format_severity(level),
            str(row["total"]),
            str(row["confirmed"]),
            str(row["false_positive"]),
            str(row["unreviewed"]),
        )

    console.print(table)


def _build_per_host_matrices(
    aggregated_findings: dict[int, dict[str, Any]],
    scoped_hosts: set[str],
    scan_id: int,
    history_id: int,
) -> dict[str, dict[int, dict[str, int]]]:
    """Build a severity-by-validation matrix per in-scope host.

    A finding's validation status applies to every host it affects, so a finding
    spanning multiple hosts is counted once per affected host.
    """

    matrices = {
        host: {
            level: {"total": 0, "confirmed": 0, "false_positive": 0, "unreviewed": 0}
            for level in SEVERITY_LABELS
        }
        for host in scoped_hosts
    }

    for finding in aggregated_findings.values():
        level = int(finding["severity"])
        if level not in SEVERITY_LABELS:
            continue
        status = str(
            get_validation(scan_id, history_id, int(finding["plugin_id"])).get("status")
            or "unreviewed"
        )
        for host in finding.get("hosts", []):
            host_matrix = matrices.get(host)
            if host_matrix is None:
                continue
            row = host_matrix[level]
            row["total"] += 1
            row[status] = int(row.get(status, 0)) + 1

    return matrices


def _print_per_host_matrices(
    matrices: dict[str, dict[int, dict[str, int]]]
) -> None:
    """Render a per-host severity-by-validation matrix for each in-scope host."""

    console.print()
    console.print("Per-Host Breakdown", highlight=False)
    for host in sorted(matrices):
        console.print()
        console.print(f"Host: {host}", highlight=False)
        _print_severity_validation_matrix(matrices[host])


def _write_per_host_summary_csv(
    matrices: dict[str, dict[int, dict[str, int]]]
) -> None:
    """Write per-host severity-by-validation rows as CSV to stdout."""

    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(
        ["host", "severity", "total", "confirmed", "false_positive", "unreviewed"]
    )
    for host in sorted(matrices):
        host_matrix = matrices[host]
        for level in (4, 3, 2, 1, 0):
            row = host_matrix[level]
            writer.writerow(
                [
                    host,
                    SEVERITY_LABELS[level],
                    int(row["total"]),
                    int(row["confirmed"]),
                    int(row["false_positive"]),
                    int(row["unreviewed"]),
                ]
            )


def _get_top_risk_intro(mode: str) -> list[str]:
    """Return the explanatory text for a Top Risks mode."""

    if mode == "severity":
        return [
            "Top Risks (by severity)",
            "",
            "Findings are ranked by severity level first, then by the number of instances.",
        ]

    if mode == "volume":
        return [
            "Top Risks (by volume)",
            "",
            "Findings are ranked by total number of instances across this scan scope.",
        ]

    return [
        "Top Risks (weighted)",
        "",
        "Findings are ranked using a weighted score:",
        "severity weight^2 x number of instances.",
        "",
        "Severity weights:",
        "Critical=5, High=4, Medium=3, Low=2, Info=1",
        "",
        "This model prioritises higher severity findings while still accounting for widespread issues.",
    ]


def _get_top_risk_rows(
    aggregated_findings: dict[int, dict[str, Any]],
    mode: str,
    direction: str,
    limit: int,
) -> tuple[list[dict[str, Any]], int, bool]:
    """Return sorted rows for Top Risks analysis."""

    rows: list[dict[str, Any]] = []

    for finding in aggregated_findings.values():
        severity_level = int(finding["severity"])
        severity_label = SEVERITY_LABELS.get(severity_level, "Info")
        severity_weight = SEVERITY_WEIGHTS.get(severity_label.lower(), 1)
        instances = int(finding["instances"])
        score = (severity_weight**2) * instances

        rows.append(
            {
                "plugin_id": int(finding["plugin_id"]),
                "name": str(finding["name"]),
                "severity": severity_level,
                "instances": instances,
                "hosts": len(set(finding["hosts"])),
                "score": score,
            }
        )

    if mode == "severity":
        rows.sort(
            key=lambda row: (
                int(row["severity"]),
                int(row["instances"]),
                int(row["hosts"]),
                str(row["name"]).lower(),
            ),
            reverse=True,
        )
    elif mode == "volume":
        rows.sort(
            key=lambda row: (
                int(row["instances"]),
                int(row["hosts"]),
                int(row["severity"]),
                str(row["name"]).lower(),
            ),
            reverse=True,
        )
    else:
        rows.sort(
            key=lambda row: (
                int(row["score"]),
                int(row["instances"]),
                int(row["severity"]),
                str(row["name"]).lower(),
            ),
            reverse=True,
        )

    if direction == "asc":
        rows.reverse()

    total_records = len(rows)
    limit_exceeded = limit > total_records
    if limit_exceeded:
        return rows, total_records, True

    return rows[:limit], total_records, False


def _print_top_risks_table(
    aggregated_findings: dict[int, dict[str, Any]],
    mode: str,
    direction: str,
    limit: int,
) -> None:
    """Render the Top Risks analysis section."""

    console.print()
    for line in _get_top_risk_intro(mode):
        console.print(line, highlight=False)

    if not aggregated_findings:
        console.print()
        console.print("[yellow]No findings available for Top Risks analysis.[/yellow]")
        return

    rows, total_records, limit_exceeded = _get_top_risk_rows(
        aggregated_findings, mode, direction, limit
    )
    if not rows:
        console.print()
        console.print("[yellow]No findings available for Top Risks analysis.[/yellow]")
        return

    if limit_exceeded:
        console.print()
        console.print(
            f"[dim]Requested {limit} rows, but only {total_records} records are available. "
            "Showing all records.[/dim]"
        )

    score_label = "Weighted Score" if mode == "weighted" else "Score"

    table = Table(box=box.ROUNDED)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Instances", justify="right", no_wrap=True)
    table.add_column("Hosts", justify="right", no_wrap=True)
    table.add_column(score_label, justify="right", no_wrap=True)

    for row in rows:
        table.add_row(
            str(row["plugin_id"]),
            str(row["name"]),
            _format_severity(int(row["severity"])),
            str(int(row["instances"])),
            str(int(row["hosts"])),
            str(int(row["score"])),
        )

    console.print()
    console.print(table)


def show_summary(
    host: list[str] | None = None,
    exclude_host: list[str] | None = None,
    min_severity: str | None = None,
    top_risks: str | None = None,
    sort: str = "desc",
    limit: int = 10,
    format: str = "table",
    by_host: bool = False,
) -> None:
    """Display a severity summary for the active scan context."""

    context = load_context()
    if not context:
        console.print(
            "[red]No active scan context.[/red] "
            "Use 'vulnsight use <scan_name>' first."
        )
        raise typer.Exit(code=1)

    if host and exclude_host:
        console.print("[red]Use either --host or --exclude-host, not both.[/red]")
        return

    minimum_severity = _resolve_minimum_severity(min_severity)
    resolved_format = _validate_summary_format(format)
    top_risks_mode = _validate_top_risks_mode(top_risks)
    sort_direction = _validate_sort_direction(sort)
    row_limit = _validate_limit(limit)
    client = _build_client()
    scan_id = int(context.get("scan_id", 0))
    history_id = int(context.get("history_id", 0))
    scan_name = str(context.get("scan_name", ""))

    try:
        details = client.get_scan_result_details(scan_id, history_id)
    except requests.RequestException as exc:
        console.print(f"[red]Failed to retrieve summary data:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    scan_hosts = details.get("hosts", [])
    host_scope = _resolve_host_scope(scan_hosts, host, exclude_host)
    if host_scope is None:
        return

    all_hosts, scoped_hosts, scope_label = host_scope
    aggregated_findings = _aggregate_summary_findings(
        client,
        scan_id,
        history_id,
        scan_hosts,
        scoped_hosts,
        minimum_severity,
        details.get("vulnerabilities", []),
    )

    matrix = _build_severity_validation_matrix(aggregated_findings, scan_id, history_id)

    if resolved_format == "csv":
        if by_host:
            per_host = _build_per_host_matrices(
                aggregated_findings, scoped_hosts, scan_id, history_id
            )
            _write_per_host_summary_csv(per_host)
        else:
            _write_summary_csv(matrix, scoped_hosts)
        return

    _print_summary_header(
        scan_name,
        scan_id,
        all_hosts,
        scoped_hosts,
        scope_label,
        minimum_severity,
    )
    _print_severity_validation_matrix(matrix)

    if by_host:
        per_host = _build_per_host_matrices(
            aggregated_findings, scoped_hosts, scan_id, history_id
        )
        _print_per_host_matrices(per_host)

    if top_risks_mode is None:
        if not aggregated_findings:
            console.print()
            console.print("[yellow]No findings match the selected criteria.[/yellow]")
        return

    _print_top_risks_table(
        aggregated_findings,
        top_risks_mode,
        sort_direction,
        row_limit,
    )
