"""Command for generating filtered report exports for the active scan context."""

from __future__ import annotations

import csv
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
from vulnsight.commands.findings import _resolve_minimum_severity
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
    markdown: str,
    output_path: Path,
    template_path: Path | None = None,
    toc: bool = False,
) -> None:
    """Convert Markdown content to another format via Pandoc."""

    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".md",
            delete=False,
        ) as temp_file:
            temp_file.write(markdown)
            temp_path = Path(temp_file.name)

        cmd = ["pandoc", str(temp_path), "-o", str(output_path)]
        if template_path:
            cmd += ["--reference-doc", str(template_path)]
        if toc:
            cmd.append("--toc")

        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        console.print(f"Error: Pandoc conversion failed ({exc.returncode}).")
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
        _write_report_csv(report, output_path)
        console.print(f"[green]Report written:[/green] {output_path}")
        return

    markdown = render_report_markdown(report)
    check_pandoc_available()

    template_path: Path | None = None
    if resolved_format == "docx":
        template_path = DEFAULT_TEMPLATE_PATH
        if not template_path.exists():
            console.print(f"[red]Error: Default report template not found:[/red] {template_path}")
            raise typer.Exit(code=1)

    _convert_with_pandoc(markdown, output_path, template_path=template_path, toc=toc)

    console.print(f"[green]Report written:[/green] {output_path}")
    if toc and resolved_format == "docx":
        console.print(
            "[yellow]Note:[/yellow] When opening this document in Word, you may see "
            "a field-update prompt for the table of contents. This is expected and harmless."
        )
