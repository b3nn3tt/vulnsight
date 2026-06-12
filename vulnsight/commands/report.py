"""Command for generating filtered report exports for the active scan context."""

from __future__ import annotations

import csv
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any

import requests
import typer
from rich.console import Console

from vulnsight.commands.finding import build_finding_data
from vulnsight.commands.history import _format_timestamp
from vulnsight.commands.hosts import _get_host_os
from vulnsight.commands.summary import _resolve_host_scope
from vulnsight.commands.findings import _get_scan_host_names, _resolve_minimum_severity
from vulnsight.commands.scans import _build_client
from vulnsight.context import load_context
from vulnsight.formatters.report import render_report_markdown
from vulnsight.validation import (
    get_validation,
    get_validation_display,
    parse_validation_status,
)


console = Console()
SUPPORTED_REPORT_FORMATS = {"docx", "csv"}
REPORT_FORMAT_EXTENSIONS = {
    "docx": ".docx",
    "csv": ".csv",
}
DEFAULT_REPORT_FORMAT = "docx"
DEFAULT_TEMPLATE_PATH = Path(__file__).resolve().parents[1] / "templates" / "report.docx"
CSV_TECHNICAL_DETAIL_COLUMNS = {
    ("Risk Information", "CVSS v3.0"): "cvss_v3",
    ("Risk Information", "CVSS v2.0"): "cvss_v2",
    ("Vulnerability Information", "CPE"): "cpe",
    ("Vulnerability Information", "Exploit Available"): "exploit_available",
    ("Vulnerability Information", "Patch Publication Date"): "patch_publication_date",
    (
        "Vulnerability Information",
        "Vulnerability Publication Date",
    ): "vulnerability_publication_date",
}

SEVERITY_LABELS = {
    0: "Info",
    1: "Low",
    2: "Medium",
    3: "High",
    4: "Critical",
}


def _normalise_report_format(value: str | None) -> str | None:
    """Normalise a requested output format."""

    if value is None:
        return DEFAULT_REPORT_FORMAT
    return str(value).strip().lower()


def _slugify_scan_name(scan_name: str) -> str:
    """Convert a scan name into a filesystem-friendly report basename."""

    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", str(scan_name or "").strip())
    slug = slug.strip("._")
    return slug or "report"


def _build_default_output_path(scan_name: str, output_format: str) -> Path:
    """Build a default report filename for the selected scan and format."""

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    basename = _slugify_scan_name(scan_name)
    return Path(f"{basename}_{timestamp}{REPORT_FORMAT_EXTENSIONS[output_format]}")


def _resolve_output_path(
    output: str | None, scan_name: str, output_format: str
) -> Path:
    """Resolve the output path, validating any explicit filename extension."""

    if not output:
        return _build_default_output_path(scan_name, output_format)

    output_path = Path(output)
    expected_extension = REPORT_FORMAT_EXTENSIONS[output_format]
    if output_path.suffix.lower() != expected_extension:
        console.print("Error: Output file extension does not match format")
        raise typer.Exit(code=1)

    return output_path


def _convert_with_pandoc(
    markdown: str | Iterable[str],
    output_path: Path,
    template_path: Path | None = None,
    toc: bool = False,
) -> None:
    """Convert Markdown content to another format via Pandoc.

    ``markdown`` may be a single string or an iterable of string chunks. The
    chunked form is written to the temporary file incrementally so large
    reports never hold the whole rendered document in memory at once.
    """

    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".md",
            delete=False,
        ) as temp_file:
            if isinstance(markdown, str):
                temp_file.write(markdown)
            else:
                for chunk in markdown:
                    temp_file.write(chunk)
            temp_path = Path(temp_file.name)

        cmd = ["pandoc", str(temp_path), "-o", str(output_path)]
        if template_path:
            cmd += ["--reference-doc", str(template_path)]
        if toc:
            cmd.append("--toc")

        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        console.print(f"Error: Pandoc conversion failed (exit code {exc.returncode}).")
        console.print(
            "[dim]First check that 'pandoc --version' runs cleanly — a broken or "
            "shimmed Pandoc install is the usual cause. You can also narrow scope "
            "with --folder / --scan / --min-severity, or export with --format csv.[/dim]"
        )
        raise typer.Exit(code=1) from exc
    except OSError as exc:
        console.print(f"Error: Could not run Pandoc: {exc}")
        console.print(
            "[dim]Check that Pandoc is installed and that 'pandoc --version' runs "
            "cleanly. You can also export with --format csv to skip Pandoc.[/dim]"
        )
        raise typer.Exit(code=1) from exc
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def check_pandoc_available() -> None:
    """Ensure Pandoc is available for DOCX export."""

    if shutil.which("pandoc"):
        return

    system = platform.system()
    message = [
        "Pandoc is required for DOCX export but was not found.",
        "",
        "Install instructions:",
        "",
    ]

    if system == "Windows":
        message.extend(
            [
                "Windows:",
                "  https://pandoc.org/installing.html",
                "  or: choco install pandoc",
                "  or: winget install --id=JohnMacFarlane.Pandoc",
            ]
        )
    else:
        message.extend(
            [
                "Kali/Linux:",
                "  sudo apt install pandoc",
            ]
        )

    message.append("")
    message.append("Then re-run the command.")

    print("\n".join(message))
    sys.exit(1)


def _join_csv_values(values: list[Any]) -> str:
    """Join multiple values into one spreadsheet-friendly cell."""

    return "\n".join(str(value).strip() for value in values if str(value).strip())


def _extract_metadata_csv_columns(finding: dict[str, Any]) -> dict[str, str]:
    """Return known technical metadata as dedicated CSV columns."""

    columns = {column: "" for column in CSV_TECHNICAL_DETAIL_COLUMNS.values()}
    remaining_rows: list[str] = []

    for section_title, fields in finding.get("metadata_sections", []):
        for label, value in fields:
            text = str(value or "").strip()
            if not text or text == "Not available.":
                continue

            column = CSV_TECHNICAL_DETAIL_COLUMNS.get((str(section_title), str(label)))
            if column:
                columns[column] = text
                continue

            remaining_rows.append(f"{section_title} - {label}: {text}")

    columns["technical_details"] = _join_csv_values(remaining_rows)
    return columns


def _format_evidence_csv(finding: dict[str, Any]) -> str:
    """Render finding evidence for a CSV cell."""

    rows: list[str] = []
    for index, entry in enumerate(finding.get("evidence", []), start=1):
        parts = [f"Entry {index}"]
        target = str(entry.get("target") or "").strip()
        host = str(entry.get("host") or "").strip()
        service = str(entry.get("service") or "").strip()
        content = str(entry.get("content") or "").strip()

        if target:
            parts.append(f"Target: {target}")
        elif host:
            parts.append(f"Host: {host}")
        if service:
            parts.append(f"Service: {service}")
        if content:
            parts.append(content)

        rows.append("\n".join(parts))

    return _join_csv_values(rows)


def _format_references_csv(finding: dict[str, Any]) -> str:
    """Render references for a CSV cell."""

    rows: list[str] = []
    for section_title, references in finding.get("reference_sections", []):
        for label, url in references:
            rows.append(f"{section_title} - {label}: {url}")
    return _join_csv_values(rows)


def _write_report_csv(report: dict[str, Any], output_path: Path) -> None:
    """Write a verbose report CSV export."""

    headers = [
        "scan_name",
        "scan_id",
        "history_id",
        "scan_date",
        "generated_at",
        "hosts_included",
        "hosts_excluded",
        "severity_scope",
        "finding_id",
        "finding_name",
        "severity",
        "validation_status",
        "host_count",
        "affected_hosts",
        "cves",
        "cvss_v3",
        "cvss_v2",
        "cpe",
        "exploit_available",
        "patch_publication_date",
        "vulnerability_publication_date",
        "technical_details",
        "description",
        "solution",
        "evidence",
        "references",
    ]

    with output_path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=headers)
        writer.writeheader()

        for finding in report.get("findings", []):
            metadata_columns = _extract_metadata_csv_columns(finding)
            writer.writerow(
                {
                    "scan_name": report["scan"]["name"],
                    "scan_id": report["scan"]["id"],
                    "history_id": report["scan"]["history_id"],
                    "scan_date": report["scan"]["scan_date"],
                    "generated_at": report["scan"]["generated_at"],
                    "hosts_included": report["scope"]["hosts_included"],
                    "hosts_excluded": report["scope"]["hosts_excluded"],
                    "severity_scope": report["scope"]["severity"],
                    "finding_id": finding.get("id", ""),
                    "finding_name": finding.get("name", ""),
                    "severity": finding.get("severity", {}).get("label", "Unknown"),
                    "validation_status": finding.get(
                        "validation_status",
                        "Unreviewed",
                    ),
                    "host_count": finding.get("host_count", 0),
                    "affected_hosts": _join_csv_values(finding.get("hosts", [])),
                    "cves": _join_csv_values(finding.get("cves", [])),
                    **metadata_columns,
                    "description": finding.get("description", ""),
                    "solution": finding.get("solution", ""),
                    "evidence": _format_evidence_csv(finding),
                    "references": _format_references_csv(finding),
                }
            )


def _get_base_host(value: str) -> str:
    """Reduce a host string to its base hostname or IP for scope matching."""

    base_value = str(value or "").strip()
    if not base_value:
        return ""

    if " (" in base_value:
        base_value = base_value.split(" (", 1)[0]

    if ":" in base_value:
        base_value = base_value.split(":", 1)[0]

    return base_value.strip()


def _host_in_scope(value: str, scoped_hosts: set[str]) -> bool:
    """Return whether a host string belongs to the current scope."""

    base_host = _get_base_host(value)
    return bool(base_host) and base_host in scoped_hosts


def _filter_finding_to_scope(
    finding_data: dict[str, Any], scoped_hosts: set[str]
) -> dict[str, Any]:
    """Filter hosts and evidence within a normalised finding to the selected scope."""

    filtered_hosts = [
        host for host in finding_data.get("hosts", []) if _host_in_scope(host, scoped_hosts)
    ]
    filtered_evidence = [
        entry
        for entry in finding_data.get("evidence", [])
        if _host_in_scope(entry.get("host", ""), scoped_hosts)
    ]

    scoped_data = dict(finding_data)
    scoped_data["hosts"] = filtered_hosts
    scoped_data["evidence"] = filtered_evidence
    scoped_data["host_count"] = len(filtered_hosts)
    return scoped_data


def _get_selected_history_entry(
    scan_details: dict[str, Any], history_id: int
) -> dict[str, Any] | None:
    """Return the selected history entry for the current scan context."""

    for entry in scan_details.get("history", []):
        if int(entry.get("history_id", 0) or 0) == history_id:
            return entry
    return None


def _build_scope_labels(
    hosts: list[str] | None,
    exclude_hosts: list[str] | None,
    exact_severity: int | None,
    minimum_severity: int | None,
) -> dict[str, str]:
    """Build report scope labels from the applied filters."""

    if hosts:
        hosts_included = ", ".join(hosts)
        hosts_excluded = "None"
    elif exclude_hosts:
        hosts_included = "ALL"
        hosts_excluded = ", ".join(exclude_hosts)
    else:
        hosts_included = "ALL"
        hosts_excluded = "None"

    if exact_severity is not None:
        severity_label = f"{SEVERITY_LABELS[exact_severity]} only"
    elif minimum_severity is not None:
        severity_label = f">= {SEVERITY_LABELS[minimum_severity]}"
    else:
        severity_label = "None"

    return {
        "hosts_included": hosts_included,
        "hosts_excluded": hosts_excluded,
        "severity": severity_label,
    }


def _build_findings_heading(
    exact_severity: int | None, minimum_severity: int | None
) -> str:
    """Return the report findings section heading."""

    if exact_severity is not None:
        return f"## Findings (Severity = {SEVERITY_LABELS[exact_severity]})"
    if minimum_severity is not None:
        return f"## Findings (Severity >= {SEVERITY_LABELS[minimum_severity]})"
    return "## Findings"


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


def build_report(
    scan_context: dict[str, Any], filters: dict[str, Any]
) -> dict[str, Any] | None:
    """Build a filtered report model for the current scan context."""

    client = _build_client()
    scan_id = int(scan_context.get("scan_id", 0))
    history_id = int(scan_context.get("history_id", 0))
    scan_name = str(scan_context.get("scan_name", ""))

    exact_severity = filters.get("severity")
    minimum_severity = filters.get("min_severity")
    include_hosts = filters.get("hosts")
    exclude_hosts = filters.get("exclude_hosts")
    only_validation = filters.get("only_validation")
    exclude_validation = filters.get("exclude_validation")

    try:
        scan_result_details = client.get_scan_result_details(scan_id, history_id)
        scan_details = client.get_scan_details(scan_id)
    except requests.RequestException as exc:
        console.print(f"[red]Failed to retrieve report data:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    scan_hosts = scan_result_details.get("hosts", [])
    host_scope = _resolve_host_scope(scan_hosts, include_hosts, exclude_hosts)
    if host_scope is None:
        return None

    all_hosts, scoped_hosts, _ = host_scope

    selected_history = _get_selected_history_entry(scan_details, history_id)
    scan_date = _format_timestamp(
        selected_history.get("creation_date") if selected_history else None
    )
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    filtered_host_rows: list[dict[str, str]] = []
    for host in scan_hosts:
        host_value = str(
            host.get("hostname") or host.get("host") or host.get("ip") or ""
        ).strip()
        if not host_value or host_value not in scoped_hosts:
            continue

        filtered_host_rows.append(
            {
                "host": host_value,
                "operating_system": _get_host_os(client, scan_id, history_id, host),
            }
        )

    filtered_host_rows.sort(key=lambda item: item["host"].lower())

    vulnerabilities = sorted(
        scan_result_details.get("vulnerabilities", []),
        key=lambda finding: (
            int(finding.get("severity", 0) or 0),
            int(finding.get("count", 0) or 0),
        ),
        reverse=True,
    )

    report_findings: list[dict[str, Any]] = []
    for vulnerability in vulnerabilities:
        plugin_id = int(vulnerability.get("plugin_id", 0) or 0)
        severity_value = int(vulnerability.get("severity", 0) or 0)

        if exact_severity is not None and severity_value != exact_severity:
            continue
        if minimum_severity is not None and severity_value < minimum_severity:
            continue

        try:
            finding_data = build_finding_data(
                client, scan_result_details, scan_id, history_id, plugin_id
            )
        except requests.HTTPError:
            continue
        except requests.RequestException:
            continue
        except ValueError:
            continue

        scoped_finding = _filter_finding_to_scope(finding_data, scoped_hosts)
        if not scoped_finding["hosts"]:
            continue

        validation = get_validation(scan_id, history_id, plugin_id)
        effective_validation_status = str(validation.get("status") or "unreviewed")
        if only_validation is not None and effective_validation_status != only_validation:
            continue
        if exclude_validation is not None and effective_validation_status == exclude_validation:
            continue

        scoped_finding["validation_status"] = get_validation_display(
            effective_validation_status
        )

        report_findings.append(scoped_finding)

    return {
        "scan": {
            "name": scan_name,
            "id": scan_id,
            "history_id": history_id,
            "scan_date": scan_date,
            "generated_at": generated_at,
        },
        "scope": _build_scope_labels(
            include_hosts,
            exclude_hosts,
            exact_severity,
            minimum_severity,
        ),
        "hosts": {
            "total": len(filtered_host_rows),
            "items": filtered_host_rows,
        },
        "findings_heading": _build_findings_heading(exact_severity, minimum_severity),
        "findings": report_findings,
        "host_names": all_hosts,
    }


def generate_report(
    min_severity: str | None = None,
    severity: str | None = None,
    host: list[str] | None = None,
    exclude_host: list[str] | None = None,
    output_format: str | None = None,
    output: str | None = None,
    toc: bool = False,
    only: str | None = None,
    exclude: str | None = None,
) -> None:
    """Generate a report for the currently selected scan context."""

    resolved_format = _normalise_report_format(output_format)
    if resolved_format not in SUPPORTED_REPORT_FORMATS:
        console.print(
            f"Error: Unsupported format '{output_format}'. "
            f"Supported formats: {', '.join(sorted(SUPPORTED_REPORT_FORMATS))}"
        )
        return

    scan_context = load_context()
    if not scan_context:
        console.print(
            "[red]No active scan context.[/red] "
            "Use 'vulnsight use <scan_name>' first."
        )
        raise typer.Exit(code=1)

    if severity and min_severity:
        console.print("[red]Use either --severity or --min-severity, not both.[/red]")
        return

    if host and exclude_host:
        console.print("[red]Use either --host or --exclude-host, not both.[/red]")
        return

    resolved_only = _resolve_validation_status_filter(only)
    resolved_exclude = _resolve_validation_status_filter(exclude)
    if resolved_only is not None and resolved_exclude is not None:
        console.print("[red]Use either --only or --exclude, not both.[/red]")
        return

    if toc and resolved_format != "docx":
        console.print("[yellow]Warning: --toc is only used with --format docx and will be ignored.[/yellow]")
        toc = False

    exact_severity = _resolve_minimum_severity(severity) if severity else None
    minimum_severity = _resolve_minimum_severity(min_severity)

    report = build_report(
        scan_context,
        {
            "severity": exact_severity,
            "min_severity": minimum_severity,
            "hosts": host,
            "exclude_hosts": exclude_host,
            "only_validation": resolved_only,
            "exclude_validation": resolved_exclude,
        },
    )
    if report is None:
        return

    output_path = _resolve_output_path(
        output,
        str(scan_context.get("scan_name", "")),
        resolved_format,
    )

    if resolved_format == "csv":
        with console.status("Writing CSV report...", spinner="dots"):
            _write_report_csv(report, output_path)
        console.print(f"[green]Report written:[/green] {output_path}")
        return

    check_pandoc_available()

    template_path: Path | None = None
    if resolved_format == "docx":
        template_path = DEFAULT_TEMPLATE_PATH
        if not template_path.exists():
            console.print(f"[red]Error: Default report template not found:[/red] {template_path}")
            raise typer.Exit(code=1)

    with console.status("Rendering report content...", spinner="dots") as status:
        markdown = render_report_markdown(report)
        status.update(
            f"Converting to {resolved_format.upper()} with Pandoc "
            "(this can take a moment)..."
        )
        _convert_with_pandoc(markdown, output_path, template_path=template_path, toc=toc)

    console.print(f"[green]Report written:[/green] {output_path}")
    if toc and resolved_format == "docx":
        console.print(
            "[yellow]Note:[/yellow] When opening this document in Word, you may see "
            "a field-update prompt for the table of contents. This is expected and harmless."
        )


GLOBAL_VALIDATION_ORDER = ("confirmed", "false_positive", "unreviewed")


def _build_global_validation_summary(validation_counts: dict[str, int]) -> str:
    """Render a compact validation summary for an aggregated estate finding."""

    parts: list[str] = []
    for status in GLOBAL_VALIDATION_ORDER:
        count = int(validation_counts.get(status, 0) or 0)
        if count < 1:
            continue
        parts.append(f"{get_validation_display(status)}: {count}")

    if not parts:
        return "Unreviewed"

    return ", ".join(parts)


def _build_global_scope_labels(
    requested_scans: list[str] | None,
    scans_included: int,
    exact_severity: int | None,
    minimum_severity: int | None,
    only_validation: str | None,
    exclude_validation: str | None,
    requested_folder: str | None = None,
) -> dict[str, str]:
    """Build estate report scope labels from the applied filters."""

    if requested_scans:
        scans_label = ", ".join(requested_scans)
    else:
        scans_label = f"ALL ({scans_included})"

    if exact_severity is not None:
        severity_label = f"{SEVERITY_LABELS[exact_severity]} only"
    elif minimum_severity is not None:
        severity_label = f">= {SEVERITY_LABELS[minimum_severity]}"
    else:
        severity_label = "None"

    if only_validation is not None:
        validation_label = f"{get_validation_display(only_validation)} only"
    elif exclude_validation is not None:
        validation_label = f"Excluding {get_validation_display(exclude_validation)}"
    else:
        validation_label = "All"

    return {
        "folder": requested_folder or "All",
        "scans": scans_label,
        "severity": severity_label,
        "validation": validation_label,
    }


def _format_global_evidence_csv(finding: dict[str, Any]) -> str:
    """Render aggregated finding evidence for a CSV cell, including scan context."""

    rows: list[str] = []
    for index, entry in enumerate(finding.get("evidence", []), start=1):
        parts = [f"Entry {index}"]
        scan = str(entry.get("scan") or "").strip()
        target = str(entry.get("target") or "").strip()
        host = str(entry.get("host") or "").strip()
        service = str(entry.get("service") or "").strip()
        content = str(entry.get("content") or "").strip()

        if scan:
            parts.append(f"Scan: {scan}")
        if target:
            parts.append(f"Target: {target}")
        elif host:
            parts.append(f"Host: {host}")
        if service:
            parts.append(f"Service: {service}")
        if content:
            parts.append(content)

        rows.append("\n".join(parts))

    return _join_csv_values(rows)


def build_global_report(
    client,
    completed_runs: list[dict[str, Any]],
    filters: dict[str, Any],
) -> dict[str, Any]:
    """Aggregate findings across completed scan runs into a whole-estate report model."""

    exact_severity = filters.get("severity")
    minimum_severity = filters.get("min_severity")
    only_validation = filters.get("only_validation")
    exclude_validation = filters.get("exclude_validation")
    scans_available = int(filters.get("scans_available", len(completed_runs)))
    requested_scans = filters.get("requested_scans")
    requested_folder = filters.get("requested_folder")

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    estate_hosts: set[str] = set()
    per_scan: dict[str, dict[str, Any]] = {}
    tasks: list[dict[str, Any]] = []

    for run in completed_runs:
        scan_id = int(run["scan_id"])
        history_id = int(run["history_id"])
        scan_name = str(run["scan_name"])
        result_details = run["result_details"]

        estate_hosts.update(_get_scan_host_names(result_details.get("hosts", [])))
        per_scan.setdefault(
            scan_name,
            {
                "scan_name": scan_name,
                "finding_plugins": set(),
                "hosts": set(),
                "severity_counts": {level: 0 for level in SEVERITY_LABELS},
            },
        )

        for vulnerability in result_details.get("vulnerabilities", []):
            plugin_id = int(vulnerability.get("plugin_id", 0) or 0)
            severity_value = int(vulnerability.get("severity", 0) or 0)

            if exact_severity is not None and severity_value != exact_severity:
                continue
            if minimum_severity is not None and severity_value < minimum_severity:
                continue

            status = str(
                get_validation(scan_id, history_id, plugin_id).get("status") or "unreviewed"
            )
            if only_validation is not None and status != only_validation:
                continue
            if exclude_validation is not None and status == exclude_validation:
                continue

            tasks.append(
                {
                    "scan_id": scan_id,
                    "history_id": history_id,
                    "scan_name": scan_name,
                    "result_details": result_details,
                    "plugin_id": plugin_id,
                    "severity_value": severity_value,
                    "status": status,
                }
            )

    aggregated: dict[int, dict[str, Any]] = {}

    total = len(tasks)
    with console.status(
        f"Building estate report from {total} finding(s)...",
        spinner="dots",
    ) as progress:
        for index, task in enumerate(tasks, start=1):
            scan_name = task["scan_name"]
            plugin_id = task["plugin_id"]
            progress.update(
                f"Processing finding {index}/{total} from {scan_name} (plugin {plugin_id})"
            )

            try:
                finding_data = build_finding_data(
                    client,
                    task["result_details"],
                    task["scan_id"],
                    task["history_id"],
                    plugin_id,
                )
            except requests.RequestException:
                continue
            except ValueError:
                continue

            aggregated_finding = aggregated.setdefault(
                plugin_id,
                {
                    "id": finding_data["id"],
                    "name": finding_data["name"],
                    "severity": finding_data["severity"],
                    "cves": finding_data["cves"],
                    "description": finding_data["description"],
                    "solution": finding_data["solution"],
                    "metadata_sections": finding_data["metadata_sections"],
                    "reference_sections": finding_data["reference_sections"],
                    "hosts_set": set(),
                    "evidence": [],
                    "scan_names": set(),
                    "validation_counts": {
                        "confirmed": 0,
                        "false_positive": 0,
                        "unreviewed": 0,
                    },
                },
            )

            new_severity = finding_data["severity"].get("value") or 0
            current_severity = aggregated_finding["severity"].get("value") or 0
            if new_severity > current_severity:
                aggregated_finding["severity"] = finding_data["severity"]
            if not aggregated_finding["name"] or aggregated_finding["name"] == "Not available.":
                aggregated_finding["name"] = finding_data["name"]

            finding_hosts = finding_data.get("hosts", [])
            aggregated_finding["hosts_set"].update(finding_hosts)
            for evidence_entry in finding_data.get("evidence", []):
                tagged_entry = dict(evidence_entry)
                tagged_entry["scan"] = scan_name
                aggregated_finding["evidence"].append(tagged_entry)
            aggregated_finding["scan_names"].add(scan_name)
            aggregated_finding["validation_counts"][task["status"]] = (
                int(aggregated_finding["validation_counts"].get(task["status"], 0) or 0) + 1
            )

            scan_stats = per_scan[scan_name]
            scan_stats["finding_plugins"].add(plugin_id)
            scan_stats["hosts"].update(finding_hosts)
            if task["severity_value"] in scan_stats["severity_counts"]:
                scan_stats["severity_counts"][task["severity_value"]] += 1

    findings: list[dict[str, Any]] = []
    for aggregated_finding in aggregated.values():
        hosts = sorted(aggregated_finding["hosts_set"])
        scan_names = sorted(aggregated_finding["scan_names"])
        findings.append(
            {
                "id": aggregated_finding["id"],
                "name": aggregated_finding["name"],
                "severity": aggregated_finding["severity"],
                "host_count": len(hosts),
                "hosts": hosts,
                "cves": aggregated_finding["cves"],
                "description": aggregated_finding["description"],
                "solution": aggregated_finding["solution"],
                "evidence": aggregated_finding["evidence"],
                "metadata_sections": aggregated_finding["metadata_sections"],
                "reference_sections": aggregated_finding["reference_sections"],
                "scan_names": scan_names,
                "scan_count": len(scan_names),
                "validation_counts": aggregated_finding["validation_counts"],
                "validation_summary": _build_global_validation_summary(
                    aggregated_finding["validation_counts"]
                ),
            }
        )

    findings.sort(
        key=lambda item: (
            -(item["severity"].get("value") or 0),
            str(item["name"]).lower(),
        )
    )

    appendix = sorted(
        (
            {
                "scan_name": stats["scan_name"],
                "finding_count": len(stats["finding_plugins"]),
                "host_count": len(stats["hosts"]),
                "severity_counts": stats["severity_counts"],
            }
            for stats in per_scan.values()
        ),
        key=lambda row: row["scan_name"].lower(),
    )

    return {
        "estate": {
            "scans_available": scans_available,
            "scans_included": len(completed_runs),
            "host_total": len(estate_hosts),
            "generated_at": generated_at,
        },
        "hosts": {"total": len(estate_hosts)},
        "scope": _build_global_scope_labels(
            requested_scans,
            len(completed_runs),
            exact_severity,
            minimum_severity,
            only_validation,
            exclude_validation,
            requested_folder,
        ),
        "findings_heading": _build_findings_heading(exact_severity, minimum_severity),
        "findings": findings,
        "appendix": appendix,
    }


def write_global_report_csv(report: dict[str, Any], output_path: Path) -> None:
    """Write a verbose whole-estate report CSV export."""

    headers = [
        "generated_at",
        "scans_included",
        "scans_available",
        "severity_scope",
        "validation_scope",
        "finding_id",
        "finding_name",
        "severity",
        "scan_count",
        "affected_scans",
        "validation_summary",
        "host_count",
        "affected_hosts",
        "cves",
        "cvss_v3",
        "cvss_v2",
        "cpe",
        "exploit_available",
        "patch_publication_date",
        "vulnerability_publication_date",
        "technical_details",
        "description",
        "solution",
        "evidence",
        "references",
    ]

    with output_path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=headers)
        writer.writeheader()

        for finding in report.get("findings", []):
            metadata_columns = _extract_metadata_csv_columns(finding)
            writer.writerow(
                {
                    "generated_at": report["estate"]["generated_at"],
                    "scans_included": report["estate"]["scans_included"],
                    "scans_available": report["estate"]["scans_available"],
                    "severity_scope": report["scope"]["severity"],
                    "validation_scope": report["scope"]["validation"],
                    "finding_id": finding.get("id", ""),
                    "finding_name": finding.get("name", ""),
                    "severity": finding.get("severity", {}).get("label", "Unknown"),
                    "scan_count": finding.get("scan_count", 0),
                    "affected_scans": _join_csv_values(finding.get("scan_names", [])),
                    "validation_summary": finding.get("validation_summary", "Unreviewed"),
                    "host_count": finding.get("host_count", 0),
                    "affected_hosts": _join_csv_values(finding.get("hosts", [])),
                    "cves": _join_csv_values(finding.get("cves", [])),
                    **metadata_columns,
                    "description": finding.get("description", ""),
                    "solution": finding.get("solution", ""),
                    "evidence": _format_global_evidence_csv(finding),
                    "references": _format_references_csv(finding),
                }
            )
