"""Global cross-scan commands for VulnSight."""

from __future__ import annotations

import csv
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
from typing import Any

import click
import requests
import typer
from rich import box
from rich.console import Console
from rich.table import Table

from vulnsight.commands.finding import (
    _clean_description,
    _collect_evidence_entries,
    _extract_cves,
    _format_severity,
    _get_finding_summary,
    _get_metadata_text,
    _get_plugin_attribute_text,
    _get_severity_label,
    _get_text_field,
)
from vulnsight.commands.findings import SEVERITY_LABELS, _resolve_minimum_severity
from vulnsight.commands.report import (
    DEFAULT_TEMPLATE_PATH,
    SUPPORTED_REPORT_FORMATS,
    _convert_with_pandoc,
    _normalise_report_format,
    _resolve_output_path,
    build_global_report,
    check_pandoc_available,
    write_global_report_csv,
)
from vulnsight.client import select_latest_usable_run
from vulnsight.commands.scans import (
    _build_client,
    _build_folder_map,
    _resolve_folder_filter,
)
from vulnsight.formatters.report import iter_global_report_markdown
from vulnsight.validation import (
    get_validation,
    get_validation_display,
    parse_validation_status,
)


console = Console()


class AlphabeticalTyperGroup(typer.core.TyperGroup):
    """Render help command lists alphabetically."""

    def list_commands(self, ctx: click.Context) -> list[str]:
        """Return command names sorted for predictable help output."""

        return sorted(self.commands)


global_app = typer.Typer(
    cls=AlphabeticalTyperGroup,
    help="Cross-scan views using the latest completed run from each scan.",
    no_args_is_help=True,
)

TOP_RISK_MODES = {"severity", "volume", "weighted"}
SORT_DIRECTIONS = {"asc", "desc"}
SEVERITY_WEIGHTS = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

VALIDATION_ORDER = ("confirmed", "false_positive", "unreviewed")


def _validate_output_format(output_format: str) -> str:
    """Validate the requested output format."""

    value = str(output_format or "table").strip().lower()
    if value not in {"table", "csv"}:
        console.print("[red]Invalid format.[/red] Use one of: table, csv.")
        raise typer.Exit(code=1)
    return value


def _write_global_findings_csv(rows: list[dict[str, Any]]) -> None:
    """Write global findings rows as CSV to stdout."""

    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(["id", "name", "severity", "instances", "scan_count", "scans"])

    for row in rows:
        writer.writerow(
            [
                int(row["plugin_id"]),
                str(row["name"]),
                str(row["severity"]),
                int(row["instances"]),
                int(row["scan_count"]),
                "|".join(row["scans"]),
            ]
        )


def _resolve_validation_status_filter(status: str | None) -> str | None:
    """Validate an optional validation-status filter."""

    try:
        return parse_validation_status(status)
    except ValueError:
        console.print(
            "[red]Invalid validation status.[/red] "
            "Use one of: confirmed, false_positive, unreviewed."
        )
        raise typer.Exit(code=1)


def _build_validation_summary(validation_counts: dict[str, int]) -> str:
    """Render a compact validation summary for global findings."""

    parts: list[str] = []
    for status in VALIDATION_ORDER:
        count = int(validation_counts.get(status, 0) or 0)
        if count < 1:
            continue
        parts.append(f"{get_validation_display(status)}: {count}")

    if not parts:
        return "Unreviewed"

    return ", ".join(parts)


def _get_latest_completed_history(scan_details: dict[str, Any]) -> dict[str, Any] | None:
    """Return the latest usable history entry for a scan, or None."""

    return select_latest_usable_run(scan_details.get("history", []))


def _fetch_completed_run(client, scan: dict[str, Any]) -> dict[str, Any] | None:
    """Fetch the latest usable run details for a single scan.

    Returns the run dict, or None when the scan has no usable run. API failures
    raise requests.RequestException for the caller to surface.
    """

    scan_id = int(scan.get("id", 0) or 0)
    scan_name = str(scan.get("name", f"Scan {scan_id}"))

    scan_details = client.get_scan_details(scan_id)
    latest_completed = _get_latest_completed_history(scan_details)
    if latest_completed is None:
        return None

    history_id = int(latest_completed.get("history_id", 0) or 0)
    result_details = client.get_scan_result_details(scan_id, history_id)

    return {
        "scan_id": scan_id,
        "scan_name": scan_name,
        "history_id": history_id,
        "result_details": result_details,
    }


def _iter_completed_scan_runs(
    client, scans: Iterable[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Collect the latest usable run for each scan, fetched concurrently.

    Each scan needs two API round-trips (details, then results); running them in
    a small thread pool turns an N-scan estate from 2N sequential requests into
    a handful of concurrent batches. Input order is preserved. A failure on any
    scan aborts the whole operation, matching the previous sequential behaviour
    (an estate report must not silently omit a scan).
    """

    scan_list = list(scans)
    if not scan_list:
        return []

    results: list[dict[str, Any] | None] = [None] * len(scan_list)
    total = len(scan_list)
    max_workers = min(8, total)

    with console.status(
        f"Fetching scan data for {total} scan(s)...", spinner="dots"
    ) as progress:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_index = {
                executor.submit(_fetch_completed_run, client, scan): index
                for index, scan in enumerate(scan_list)
            }

            completed = 0
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                try:
                    results[index] = future.result()
                except requests.RequestException as exc:
                    console.print(f"[red]Failed to retrieve scan data:[/red] {exc}")
                    raise typer.Exit(code=1) from exc

                completed += 1
                progress.update(f"Fetching scan data... {completed}/{total}")

    return [run for run in results if run is not None]


def _extract_plugin_core_fields(
    response: dict[str, Any],
    finding_summary: dict[str, Any],
    plugin_metadata: dict[str, Any],
) -> dict[str, Any]:
    """Extract the core plugin fields using the same logic as the finding command."""

    plugin_name = _get_text_field(
        response,
        ("plugin_name",),
        ("pluginname",),
        ("name",),
        ("info", "plugin_name"),
        ("info", "pluginname"),
    )
    if plugin_name == "Not available.":
        plugin_name = str(finding_summary.get("plugin_name", "Not available."))
    if plugin_name == "Not available.":
        plugin_name = _get_metadata_text(plugin_metadata, "name")

    severity_value = response.get("severity")
    if severity_value is None:
        severity_value = finding_summary.get("severity")

    description = _get_text_field(
        response,
        ("description",),
        ("info", "description"),
        ("info", "plugindescription"),
        ("info", "plugin_description"),
        ("info", "pluginattributes", "description"),
    )
    if description == "Not available.":
        description = _get_plugin_attribute_text(
            response,
            "description",
            "plugin_description",
            "plugindescription",
        )
    if description == "Not available.":
        description = _get_metadata_text(plugin_metadata, "description", "synopsis")
    if description != "Not available.":
        description = _clean_description(description)

    solution = _get_text_field(
        response,
        ("solution",),
        ("info", "solution"),
        ("info", "pluginattributes", "solution"),
    )
    if solution == "Not available.":
        solution = _get_plugin_attribute_text(response, "solution")
    if solution == "Not available.":
        solution = _get_metadata_text(plugin_metadata, "solution")

    return {
        "plugin_name": plugin_name,
        "severity_value": severity_value,
        "severity_label": _get_severity_label(severity_value),
        "severity_display": _format_severity(severity_value),
        "description": description,
        "solution": solution,
        "cves": _extract_cves(description if description != "Not available." else ""),
    }


def _load_scans_and_completed_runs(client) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Load all scans and the latest completed run for each scan."""

    try:
        scans = client.list_scans()
    except requests.RequestException as exc:
        console.print(f"[red]Failed to retrieve scans:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if not scans:
        console.print("[yellow]No scans found.[/yellow]")
        return [], []

    completed_runs = _iter_completed_scan_runs(client, scans)
    if not completed_runs:
        console.print("[yellow]No completed scan data available.[/yellow]")
        return scans, []

    return scans, completed_runs


def _aggregate_global_findings(
    completed_runs: list[dict[str, Any]],
    exact_severity: int | None = None,
    minimum_severity: int | None = None,
    validation_status: str | None = None,
    exclude_validation_status: str | None = None,
) -> dict[int, dict[str, Any]]:
    """Aggregate findings across completed scan runs by plugin ID."""

    aggregated_findings: dict[int, dict[str, Any]] = {}

    for completed_run in completed_runs:
        scan_id = int(completed_run["scan_id"])
        history_id = int(completed_run["history_id"])
        scan_name = str(completed_run["scan_name"])
        result_details = completed_run["result_details"]

        for vulnerability in result_details.get("vulnerabilities", []):
            plugin_id = int(vulnerability.get("plugin_id", 0) or 0)
            severity_value = int(vulnerability.get("severity", 0) or 0)
            finding_validation_status = str(
                get_validation(scan_id, history_id, plugin_id).get("status") or "unreviewed"
            )

            if exact_severity is not None and severity_value != exact_severity:
                continue
            if minimum_severity is not None and severity_value < minimum_severity:
                continue
            if (
                validation_status is not None
                and finding_validation_status != validation_status
            ):
                continue
            if (
                exclude_validation_status is not None
                and finding_validation_status == exclude_validation_status
            ):
                continue

            aggregated = aggregated_findings.setdefault(
                plugin_id,
                {
                    "plugin_id": plugin_id,
                    "name": str(vulnerability.get("plugin_name", "")),
                    "severity": severity_value,
                    "instances": 0,
                    "scans": set(),
                    "validation_counts": {
                        "confirmed": 0,
                        "false_positive": 0,
                        "unreviewed": 0,
                    },
                },
            )

            if severity_value > int(aggregated["severity"]):
                aggregated["severity"] = severity_value
            if not aggregated["name"]:
                aggregated["name"] = str(vulnerability.get("plugin_name", ""))

            aggregated["instances"] = int(aggregated["instances"]) + int(
                vulnerability.get("count", 0) or 0
            )
            aggregated["scans"].add(scan_name)
            validation_counts = aggregated["validation_counts"]
            validation_counts[finding_validation_status] = int(
                validation_counts.get(finding_validation_status, 0) or 0
            ) + 1

    return aggregated_findings


def _print_global_severity_note(
    exact_severity: int | None, minimum_severity: int | None
) -> None:
    """Print a standard severity filter note when applicable."""

    if exact_severity is not None:
        console.print()
        console.print(
            f"[dim]Note: Showing findings with severity = "
            f"{SEVERITY_LABELS[exact_severity]}[/dim]"
        )
    elif minimum_severity is not None:
        console.print()
        console.print(
            f"[dim]Note: Showing findings with severity >= "
            f"{SEVERITY_LABELS[minimum_severity]}[/dim]"
        )


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


def _print_global_summary_metrics(
    scans: list[dict[str, Any]],
    completed_runs: list[dict[str, Any]],
    aggregated_findings: dict[int, dict[str, Any]],
) -> None:
    """Render the main Global Summary metrics."""

    severity_counts = {level: 0 for level in SEVERITY_LABELS}
    for finding in aggregated_findings.values():
        severity_level = int(finding["severity"])
        if severity_level in severity_counts:
            severity_counts[severity_level] += 1

    console.print("Global Summary", highlight=False)
    console.print()
    console.print(f"Scans available : {len(scans)}", highlight=False)
    console.print(f"Scans included  : {len(completed_runs)}", highlight=False)
    console.print(f"Findings        : {len(aggregated_findings)}", highlight=False)
    console.print()

    for level in (4, 3, 2, 1, 0):
        console.print(
            f"{SEVERITY_LABELS[level]:<15}: {severity_counts[level]}",
            highlight=False,
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
            "Findings are ranked by total number of instances across all scans.",
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
        scans_affected = len(finding["scans"])
        score = (severity_weight**2) * instances

        rows.append(
            {
                "plugin_id": int(finding["plugin_id"]),
                "name": str(finding["name"]),
                "severity": severity_level,
                "instances": instances,
                "scans": scans_affected,
                "score": score,
            }
        )

    if mode == "severity":
        rows.sort(
            key=lambda row: (
                int(row["severity"]),
                int(row["instances"]),
                int(row["scans"]),
                str(row["name"]).lower(),
            ),
            reverse=True,
        )
    elif mode == "volume":
        rows.sort(
            key=lambda row: (
                int(row["instances"]),
                int(row["scans"]),
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
        aggregated_findings,
        mode,
        direction,
        limit,
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
    table.add_column("Scans", justify="right", no_wrap=True)
    table.add_column(score_label, justify="right", no_wrap=True)

    for row in rows:
        table.add_row(
            str(row["plugin_id"]),
            str(row["name"]),
            _format_severity(int(row["severity"])),
            str(int(row["instances"])),
            str(int(row["scans"])),
            str(int(row["score"])),
        )

    console.print()
    console.print(table)


def global_findings(
    severity: str | None = None,
    min_severity: str | None = None,
    output_format: str = "table",
    status: str | None = None,
    exclude_status: str | None = None,
    folder: str | None = None,
) -> None:
    """Aggregate findings across all scans using each scan's latest completed run."""

    if severity and min_severity:
        console.print("[red]Use either --severity or --min-severity, not both.[/red]")
        return

    exact_severity = _resolve_minimum_severity(severity) if severity else None
    minimum_severity = _resolve_minimum_severity(min_severity)
    resolved_format = _validate_output_format(output_format)
    resolved_status = _resolve_validation_status_filter(status)
    resolved_exclude_status = _resolve_validation_status_filter(exclude_status)
    if resolved_status is not None and resolved_exclude_status is not None:
        console.print("[red]Use either --only/--status or --exclude, not both.[/red]")
        raise typer.Exit(code=1)
    client = _build_client()
    scans, completed_runs = _load_scans_and_completed_runs(client)

    if not scans or not completed_runs:
        return

    if folder:
        completed_runs, resolved_folder = _filter_runs_by_folder(
            client, scans, completed_runs, folder
        )
        if completed_runs is None:
            return
        if not completed_runs:
            console.print(
                f"[yellow]No completed scan data available in folder "
                f"'{resolved_folder}'.[/yellow]"
            )
            return

    aggregated_findings = _aggregate_global_findings(
        completed_runs,
        exact_severity=exact_severity,
        minimum_severity=minimum_severity,
        validation_status=resolved_status,
        exclude_validation_status=resolved_exclude_status,
    )

    rows = sorted(
        aggregated_findings.values(),
        key=lambda item: (
            -int(item["severity"]),
            -int(item["instances"]),
            str(item["name"]).lower(),
        ),
    )

    if resolved_format == "csv":
        csv_rows = [
            {
                "plugin_id": int(data["plugin_id"]),
                "name": str(data["name"]),
                "severity": SEVERITY_LABELS.get(int(data["severity"]), "Unknown"),
                "instances": int(data["instances"]),
                "scan_count": len(data["scans"]),
                "scans": sorted(str(scan) for scan in data["scans"]),
            }
            for data in rows
        ]
        _write_global_findings_csv(csv_rows)
        return

    if not aggregated_findings:
        console.print("[yellow]No findings match the selected criteria.[/yellow]")
        return

    console.print("Global Findings", highlight=False)
    _print_global_severity_note(exact_severity, minimum_severity)
    if resolved_status is not None:
        console.print()
        console.print(
            f"[dim]Note: Showing findings with validation status = "
            f"{get_validation_display(resolved_status)}[/dim]"
        )
    elif resolved_exclude_status is not None:
        console.print()
        console.print(
            f"[dim]Note: Excluding findings with validation status = "
            f"{get_validation_display(resolved_exclude_status)}[/dim]"
        )

    table = Table(box=box.ROUNDED)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Instances", justify="right", no_wrap=True)
    table.add_column("Scans Affected", justify="right", no_wrap=True)
    table.add_column("Validation", style="white")

    for data in rows:
        table.add_row(
            str(int(data["plugin_id"])),
            str(data["name"]),
            _format_severity(int(data["severity"])),
            str(int(data["instances"])),
            str(len(data["scans"])),
            _build_validation_summary(data["validation_counts"]),
        )

    console.print()
    console.print(table)


def global_summary(
    min_severity: str | None = None,
    top_risks: str | None = None,
    sort: str = "desc",
    limit: int = 10,
    folder: str | None = None,
) -> None:
    """Show a summary of findings across all scans."""

    minimum_severity = _resolve_minimum_severity(min_severity)
    top_risks_mode = _validate_top_risks_mode(top_risks)
    sort_direction = _validate_sort_direction(sort)
    row_limit = _validate_limit(limit)
    client = _build_client()
    scans, completed_runs = _load_scans_and_completed_runs(client)

    if not scans or not completed_runs:
        return

    if folder:
        completed_runs, resolved_folder = _filter_runs_by_folder(
            client, scans, completed_runs, folder
        )
        if completed_runs is None:
            return
        if not completed_runs:
            console.print(
                f"[yellow]No completed scan data available in folder "
                f"'{resolved_folder}'.[/yellow]"
            )
            return

    aggregated_findings = _aggregate_global_findings(
        completed_runs,
        minimum_severity=minimum_severity,
    )

    _print_global_summary_metrics(scans, completed_runs, aggregated_findings)
    _print_global_severity_note(None, minimum_severity)

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


def global_finding(
    plugin_id: int, min_severity: str | None = None, folder: str | None = None
) -> None:
    """Show a detailed cross-scan view of a single plugin."""

    minimum_severity = _resolve_minimum_severity(min_severity)
    client = _build_client()
    scans, completed_runs = _load_scans_and_completed_runs(client)

    if not scans or not completed_runs:
        return

    if folder:
        completed_runs, resolved_folder = _filter_runs_by_folder(
            client, scans, completed_runs, folder
        )
        if completed_runs is None:
            return
        if not completed_runs:
            console.print(
                f"[yellow]No completed scan data available in folder "
                f"'{resolved_folder}'.[/yellow]"
            )
            return

    matching_scans: list[dict[str, Any]] = []
    max_severity_value: int | None = None

    try:
        plugin_metadata = client.get_plugin_metadata(plugin_id)
    except requests.RequestException:
        plugin_metadata = {}

    shared_fields: dict[str, Any] | None = None

    for completed_run in completed_runs:
        scan_id = int(completed_run["scan_id"])
        scan_name = str(completed_run["scan_name"])
        history_id = int(completed_run["history_id"])
        result_details = completed_run["result_details"]

        finding_summary = _get_finding_summary(result_details, plugin_id)
        if finding_summary is None:
            continue

        try:
            response = client.get_plugin_details(scan_id, plugin_id, history_id)
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                continue
            console.print(f"[red]Failed to retrieve plugin details:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        except requests.RequestException as exc:
            console.print(f"[red]Failed to retrieve plugin details:[/red] {exc}")
            raise typer.Exit(code=1) from exc

        extracted_fields = _extract_plugin_core_fields(
            response, finding_summary, plugin_metadata
        )
        severity_value = int(extracted_fields["severity_value"] or 0)
        if max_severity_value is None or severity_value > max_severity_value:
            max_severity_value = severity_value

        hosts, evidence_entries = _collect_evidence_entries(
            client, response, result_details, scan_id, history_id, plugin_id
        )

        matching_scans.append(
            {
                "scan_id": scan_id,
                "scan_name": scan_name,
                "history_id": history_id,
                "severity_value": severity_value,
                "hosts": hosts,
                "evidence_entries": evidence_entries,
                "validation_status": get_validation_display(
                    str(get_validation(scan_id, history_id, plugin_id).get("status") or "unreviewed")
                ),
            }
        )

        if shared_fields is None:
            shared_fields = extracted_fields

    if not matching_scans or shared_fields is None or max_severity_value is None:
        console.print(f"[yellow]ID '{plugin_id}' not found in any scan.[/yellow]")
        return

    if minimum_severity is not None and max_severity_value < minimum_severity:
        console.print("[yellow]No findings match the selected criteria.[/yellow]")
        return

    scan_host_map = {
        entry["scan_name"]: {
            "hosts": sorted(entry["hosts"]),
            "validation_status": str(entry["validation_status"]),
        }
        for entry in sorted(matching_scans, key=lambda item: item["scan_name"].lower())
    }

    unique_hosts = {host for entry in matching_scans for host in entry["hosts"]}

    console.print(
        f"Global Finding: {shared_fields['plugin_name']}",
        highlight=False,
    )
    console.print()
    console.print(f"ID        : {plugin_id}", highlight=False)
    console.print(f"Severity  : {shared_fields['severity_display']}")
    console.print(f"Scans     : {len(matching_scans)}", highlight=False)
    console.print(f"Hosts     : {len(unique_hosts)}", highlight=False)

    if minimum_severity is not None:
        console.print()
        console.print(
            f"[dim]Note: Showing findings with severity >= "
            f"{SEVERITY_LABELS[minimum_severity]}[/dim]"
        )

    _print_global_scan_groups(scan_host_map)

    if shared_fields["cves"]:
        console.print()
        console.print("CVEs:")
        for cve in shared_fields["cves"]:
            console.print(f"- {cve}", highlight=False)

    console.print()
    console.print("Description:")
    console.print(shared_fields["description"], highlight=False)

    console.print()
    console.print("Solution:")
    console.print(shared_fields["solution"], highlight=False)

    _print_global_evidence(matching_scans)


def _print_global_scan_groups(scan_host_map: dict[str, dict[str, Any]]) -> None:
    """Render affected scans grouped by scan name."""

    console.print()
    console.print("Affected Scans:")

    for scan_name in sorted(scan_host_map):
        console.print()
        console.print(scan_name, highlight=False)
        scan_entry = scan_host_map[scan_name]
        console.print(
            f"Validation Status: {scan_entry['validation_status']}",
            highlight=False,
        )
        hosts = scan_entry["hosts"]
        if hosts:
            for host in hosts:
                console.print(f"- {host}", highlight=False)
        else:
            console.print("- None listed.", highlight=False)


def _print_global_evidence(matching_scans: list[dict[str, Any]]) -> None:
    """Render evidence grouped by scan and host."""

    console.print()
    console.print("Evidence:")

    evidence_found = False
    for entry in sorted(matching_scans, key=lambda item: item["scan_name"].lower()):
        scan_name = str(entry["scan_name"])
        for evidence_entry in entry["evidence_entries"]:
            evidence_found = True
            host_label = str(evidence_entry.get("host") or "Unknown host").strip()
            console.print()
            console.print(f"[{scan_name} / {host_label}]", highlight=False)
            console.print(str(evidence_entry.get("plugin_output", "")), highlight=False)
            if evidence_entry.get("target"):
                console.print(
                    f"Target            : {evidence_entry['target']}",
                    highlight=False,
                )

    if not evidence_found:
        console.print("No plugin output available.", highlight=False)


def _filter_runs_by_scan_names(
    scans: list[dict[str, Any]],
    completed_runs: list[dict[str, Any]],
    requested: list[str],
) -> tuple[list[dict[str, Any]] | None, list[str] | None]:
    """Limit completed runs to the requested scan names.

    Returns the filtered runs and the resolved scan names, or (None, None) when a
    requested scan name does not exist.
    """

    available_names = {
        str(scan.get("name", "")).strip().lower(): str(scan.get("name", "")).strip()
        for scan in scans
    }

    resolved_names: list[str] = []
    for name in requested:
        key = str(name).strip().lower()
        if key not in available_names:
            console.print(f"[red]Scan not found:[/red] {name}")
            console.print("Use 'vulnsight scans' to list available scans.")
            return None, None
        resolved_names.append(available_names[key])

    resolved_keys = {name.lower() for name in resolved_names}
    filtered_runs = [
        run
        for run in completed_runs
        if str(run["scan_name"]).strip().lower() in resolved_keys
    ]
    return filtered_runs, sorted(set(resolved_names))


def _filter_runs_by_folder(
    client,
    scans: list[dict[str, Any]],
    completed_runs: list[dict[str, Any]],
    folder: str,
) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Limit completed runs to scans within the requested folder.

    Returns the filtered runs and the resolved folder name, or (None, None)
    when the requested folder does not exist.
    """

    folder_map = _build_folder_map(client)
    folder_id = _resolve_folder_filter(folder_map, folder)
    if folder_id is None:
        console.print(f"[red]Folder not found:[/red] {folder}")
        if folder_map:
            available = ", ".join(
                sorted(name for name in folder_map.values() if name)
            )
            console.print(f"Available folders: {available}")
        return None, None

    scan_folder = {
        int(scan.get("id", 0) or 0): scan.get("folder_id") for scan in scans
    }
    filtered_runs = [
        run
        for run in completed_runs
        if scan_folder.get(int(run["scan_id"])) is not None
        and int(scan_folder[int(run["scan_id"])]) == folder_id
    ]
    return filtered_runs, folder_map[folder_id]


def global_report(
    output_format: str | None = None,
    min_severity: str | None = None,
    severity: str | None = None,
    only: str | None = None,
    exclude: str | None = None,
    folder: str | None = None,
    scan: list[str] | None = None,
    output: str | None = None,
    toc: bool = False,
) -> None:
    """Generate an aggregated whole-estate report across all scans."""

    resolved_format = _normalise_report_format(output_format)
    if resolved_format not in SUPPORTED_REPORT_FORMATS:
        console.print(
            f"Error: Unsupported format '{output_format}'. "
            f"Supported formats: {', '.join(sorted(SUPPORTED_REPORT_FORMATS))}"
        )
        return

    if severity and min_severity:
        console.print("[red]Use either --severity or --min-severity, not both.[/red]")
        return

    resolved_only = _resolve_validation_status_filter(only)
    resolved_exclude = _resolve_validation_status_filter(exclude)
    if resolved_only is not None and resolved_exclude is not None:
        console.print("[red]Use either --only or --exclude, not both.[/red]")
        return

    if toc and resolved_format != "docx":
        console.print(
            "[yellow]Warning: --toc is only used with --format docx and will be ignored.[/yellow]"
        )
        toc = False

    exact_severity = _resolve_minimum_severity(severity) if severity else None
    minimum_severity = _resolve_minimum_severity(min_severity)

    client = _build_client()
    scans, completed_runs = _load_scans_and_completed_runs(client)
    if not scans or not completed_runs:
        return

    requested_folder: str | None = None
    if folder:
        completed_runs, requested_folder = _filter_runs_by_folder(
            client, scans, completed_runs, folder
        )
        if completed_runs is None:
            return
        if not completed_runs:
            console.print(
                f"[yellow]No completed scan data available in folder "
                f"'{requested_folder}'.[/yellow]"
            )
            return

    requested_scans: list[str] | None = None
    if scan:
        completed_runs, requested_scans = _filter_runs_by_scan_names(
            scans, completed_runs, scan
        )
        if completed_runs is None:
            return
        if not completed_runs:
            console.print(
                "[yellow]No completed scan data available for the selected scans.[/yellow]"
            )
            return

    report = build_global_report(
        client,
        completed_runs,
        {
            "severity": exact_severity,
            "min_severity": minimum_severity,
            "only_validation": resolved_only,
            "exclude_validation": resolved_exclude,
            "scans_available": len(scans),
            "requested_scans": requested_scans,
            "requested_folder": requested_folder,
        },
    )

    output_path = _resolve_output_path(output, "estate_report", resolved_format)

    if resolved_format == "csv":
        with console.status("Writing CSV report...", spinner="dots"):
            write_global_report_csv(report, output_path)
        console.print(f"[green]Report written:[/green] {output_path}")
        return

    check_pandoc_available()

    if not DEFAULT_TEMPLATE_PATH.exists():
        console.print(
            f"[red]Error: Default report template not found:[/red] {DEFAULT_TEMPLATE_PATH}"
        )
        raise typer.Exit(code=1)

    with console.status(
        "Drafting report and converting to DOCX with Pandoc (this can take a moment)...",
        spinner="dots",
    ):
        _convert_with_pandoc(
            iter_global_report_markdown(report),
            output_path,
            template_path=DEFAULT_TEMPLATE_PATH,
            toc=toc,
        )

    console.print(f"[green]Report written:[/green] {output_path}")
    if toc:
        console.print(
            "[yellow]Note:[/yellow] When opening this document in Word, you may see "
            "a field-update prompt for the table of contents. This is expected and harmless."
        )


@global_app.command("findings")
def global_findings_command(
    severity: str | None = typer.Option(
        None,
        "--severity",
        "-s",
        help="Only include one severity: info, low, medium, high, or critical.",
    ),
    min_severity: str | None = typer.Option(
        None,
        "--min-severity",
        help="Minimum severity: info, low, medium, high, or critical.",
    ),
    format: str = typer.Option(
        "table",
        "--format",
        help="Output format: table or csv. CSV is written to stdout.",
    ),
    status: str | None = typer.Option(
        None,
        "--only",
        help="Only include validation status: confirmed, false_positive, or unreviewed.",
    ),
    status_alias: str | None = typer.Option(
        None,
        "--status",
        hidden=True,
        help="Deprecated alias for --only.",
    ),
    exclude: str | None = typer.Option(
        None,
        "--exclude",
        help="Exclude validation status: confirmed, false_positive, or unreviewed.",
    ),
    folder: str | None = typer.Option(
        None,
        "--folder",
        help="Limit to scans in this folder (by folder name, case-insensitive).",
    ),
) -> None:
    """Show aggregated findings across all scans."""

    global_findings(
        severity,
        min_severity,
        format,
        status if status is not None else status_alias,
        exclude,
        folder,
    )


@global_app.command("summary")
def global_summary_command(
    min_severity: str | None = typer.Option(
        None,
        "--min-severity",
        help="Minimum severity: info, low, medium, high, or critical.",
    ),
    top_risks: str | None = typer.Option(
        None,
        "--top-risks",
        help="Top risks ranking mode: severity, volume, or weighted.",
    ),
    sort: str = typer.Option(
        "desc", "--sort", help="Top risks sort direction: asc or desc."
    ),
    limit: int = typer.Option(
        10, "--limit", help="Maximum number of Top Risks rows to display."
    ),
    folder: str | None = typer.Option(
        None,
        "--folder",
        help="Limit to scans in this folder (by folder name, case-insensitive).",
    ),
) -> None:
    """Show a summary of findings across all scans."""

    global_summary(min_severity, top_risks, sort, limit, folder)


@global_app.command("finding", no_args_is_help=True)
def global_finding_command(
    plugin_id: int = typer.Argument(..., help="Plugin ID to inspect across all scans."),
    min_severity: str | None = typer.Option(
        None,
        "--min-severity",
        help="Minimum severity: info, low, medium, high, or critical.",
    ),
    folder: str | None = typer.Option(
        None,
        "--folder",
        help="Limit to scans in this folder (by folder name, case-insensitive).",
    ),
) -> None:
    """Show detailed information for a finding across all scans."""

    global_finding(plugin_id, min_severity, folder)


@global_app.command("report")
def global_report_command(
    format: str | None = typer.Option(
        None,
        "--format",
        help="Output format: docx or csv. Defaults to docx.",
    ),
    min_severity: str | None = typer.Option(
        None,
        "--min-severity",
        help="Minimum severity: info, low, medium, high, or critical.",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        help="Only include one severity: info, low, medium, high, or critical.",
    ),
    only: str | None = typer.Option(
        None,
        "--only",
        help="Only include validation status: confirmed, false_positive, or unreviewed.",
    ),
    exclude: str | None = typer.Option(
        None,
        "--exclude",
        help="Exclude validation status: confirmed, false_positive, or unreviewed.",
    ),
    folder: str | None = typer.Option(
        None,
        "--folder",
        help="Limit the report to scans in this folder (by folder name, case-insensitive).",
    ),
    scan: list[str] | None = typer.Option(
        None,
        "--scan",
        help="Limit the report to these scans. Repeat the option for multiple scans.",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        help="Output file path. Defaults to a timestamped .docx or .csv file.",
    ),
    toc: bool = typer.Option(
        False,
        "--toc",
        help="Include a table of contents. DOCX only.",
    ),
) -> None:
    """Generate an aggregated whole-estate report across all scans."""

    global_report(
        format, min_severity, severity, only, exclude, folder, scan, output, toc
    )
