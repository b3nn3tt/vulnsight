"""Markdown rendering helpers for VulnSight scan reports."""

from __future__ import annotations

import re
from typing import Any

from vulnsight.formatters.finding import clean_evidence_output, parse_target

PAGE_BREAK_BLOCK = "\n".join(
    [
        "```{=openxml}",
        '<w:p><w:r><w:br w:type="page"/></w:r></w:p>',
        "```",
    ]
)


def _escape_markdown_table(text: str) -> str:
    """Escape pipe characters for Markdown tables."""

    return text.replace("|", "\\|")


def _format_severity_scope(value: str) -> str:
    """Render severity scope wording in report-friendly language."""

    if value.startswith(">= "):
        return f"{value[3:]} and above"
    return value


def _build_executive_summary(report: dict[str, Any]) -> list[str]:
    """Build deterministic executive summary sentences from report data."""

    findings = report.get("findings", [])
    total_findings = len(findings)
    host_count = int(report["hosts"]["total"])
    severity_counts = {
        1: 0,
        2: 0,
        3: 0,
        4: 0,
    }

    for finding in findings:
        severity_value = finding.get("severity", {}).get("value")
        if severity_value in severity_counts:
            severity_counts[severity_value] += 1

    critical_count = severity_counts[4]
    high_count = severity_counts[3]
    medium_count = severity_counts[2]
    host_word = "host" if host_count == 1 else "hosts"

    if critical_count > 0:
        risk = "high risk posture"
        priority = "immediate remediation"
    elif high_count > 0:
        risk = "elevated risk posture"
        priority = "remediation in the near term"
    elif medium_count > 0:
        risk = "moderate risk posture"
        priority = "planned remediation activity"
    else:
        risk = "low risk posture"
        priority = "routine hardening"

    sentences = [
        f"The assessment identified {total_findings} findings affecting {host_count} {host_word}."
    ]

    if critical_count > 0:
        sentences.append(
            "One or more critical vulnerabilities were identified representing the most immediate risk within the assessed scope."
        )
    elif high_count > 0:
        sentences.append(
            "High-severity findings were identified representing significant security weaknesses within the assessed scope."
        )
    elif medium_count > 0:
        sentences.append(
            "Medium-severity findings were identified indicating moderate security weaknesses."
        )
    else:
        sentences.append(
            "Only low or informational findings were identified within the assessed scope."
        )

    if critical_count > 0 and high_count > 0:
        sentences.append(
            "In addition, high-severity findings indicate weaknesses in system configuration and patch management."
        )
    elif critical_count == 0 and high_count > 0:
        sentences.append(
            "These findings indicate weaknesses in system configuration and patch management."
        )
    elif medium_count == 0:
        sentences.append(
            "No medium severity issues were identified within the defined scope."
        )

    sentences.append(
        f"Overall, the assessed environment presents a {risk} and should be prioritised for {priority}."
    )

    return sentences


def _build_report_finding_header(
    name: str,
    finding_id: int,
    severity_label: str,
    affected_hosts_text: str,
    validation_status: str,
    index: int,
) -> list[str]:
    """Build the report finding heading and stable Markdown header table."""

    return [
        f"### {index}. {name}",
        "",
        "|  |  |",
        "| --- | --- |",
        f"| ID | {finding_id} |",
        f"| Severity | **{severity_label}** |",
        f"| Validation Status | {validation_status} |",
        f"| Affected Hosts | {_escape_markdown_table(affected_hosts_text)} |",
        "",
    ]


def _render_report_finding_markdown(finding: dict[str, Any], index: int) -> str:
    """Render a finding for report output with report-specific formatting."""

    affected_hosts = finding.get("hosts", [])
    affected_hosts_text = ", ".join(affected_hosts) if affected_hosts else "None listed"
    severity_label = str(finding.get("severity", {}).get("label") or "Unknown").upper()
    finding_name = str(finding.get("name", "Not available."))
    finding_id = int(finding.get("id", 0) or 0)
    validation_status = str(finding.get("validation_status") or "Unreviewed")

    lines = _build_report_finding_header(
        finding_name,
        finding_id,
        severity_label,
        affected_hosts_text,
        validation_status,
        index,
    )

    technical_details = _build_technical_details(finding)
    if technical_details:
        lines.extend(["#### Technical Details"])
        lines.extend(f"- **{label}:** {value}" for label, value in technical_details)

    if finding.get("cves"):
        lines.extend(["", "#### CVEs"])
        lines.extend(f"- {cve}" for cve in finding["cves"])

    lines.extend(
        [
            "",
            "#### Description",
            _normalise_markdown_text(str(finding.get("description") or "Not available.")),
            "",
            "#### Solution",
            _normalise_markdown_text(str(finding.get("solution") or "Not available.")),
            "",
            "#### Evidence",
        ]
    )

    evidence_entries = finding.get("evidence", [])
    if evidence_entries:
        for entry_index, entry in enumerate(evidence_entries, start=1):
            lines.extend(_render_report_evidence_entry(entry, entry_index))
    else:
        lines.extend(["", "No plugin output available."])

    for title, references in finding.get("reference_sections", []):
        lines.extend(["", f"#### {title}"])
        lines.extend(f"- {label}: {url}" for label, url in references)

    return "\n".join(lines)


def _build_technical_details(finding: dict[str, Any]) -> list[tuple[str, str]]:
    """Flatten technical metadata into one report-friendly section."""

    details: list[tuple[str, str]] = []
    for _, fields in finding.get("metadata_sections", []):
        for label, value in fields:
            cleaned_value = _normalise_markdown_text(str(value or ""))
            if not cleaned_value or cleaned_value == "Not available.":
                continue
            details.append((str(label), cleaned_value))
    return details


def _remove_target_lines(content: str) -> str:
    """Remove target lines from evidence content for report rendering."""

    lines = []
    for line in str(content or "").splitlines():
        if line.strip().lower().startswith("target:"):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def _normalise_evidence_text(text: str) -> str:
    """Left-align evidence lines while preserving line order and blank lines."""

    lines = str(text or "").splitlines()
    normalised = [line.lstrip() if line.strip() else "" for line in lines]
    return "\n".join(normalised).strip()


def _normalise_markdown_text(text: str) -> str:
    """Collapse wrapped paragraphs while preserving blank lines and bullets."""

    source = str(text or "").strip()
    if not source:
        return ""

    bullet_pattern = re.compile(r"^[-*]\s+")
    blocks: list[tuple[str, str]] = []
    paragraph_lines: list[str] = []
    pending_blank = False

    def flush_paragraph() -> None:
        nonlocal paragraph_lines
        if paragraph_lines:
            blocks.append(("paragraph", " ".join(paragraph_lines)))
            paragraph_lines = []

    def append_to_last_bullet(text_value: str) -> None:
        if not blocks or blocks[-1][0] != "bullet":
            return
        blocks[-1] = ("bullet", f"{blocks[-1][1]} {text_value}".strip())

    for raw_line in source.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            flush_paragraph()
            pending_blank = True
            continue

        if bullet_pattern.match(stripped):
            flush_paragraph()
            blocks.append(("bullet", stripped))
            pending_blank = False
            continue

        if blocks and blocks[-1][0] == "bullet" and not pending_blank:
            append_to_last_bullet(stripped)
            continue

        paragraph_lines.append(stripped)
        pending_blank = False

    flush_paragraph()

    output: list[str] = []
    previous_kind: str | None = None
    for kind, content in blocks:
        if output:
            if kind == "bullet" and previous_kind != "bullet":
                output.append("")
            elif kind == "paragraph":
                output.append("")
        output.append(content)
        previous_kind = kind

    return "\n".join(output) if output else source


def _render_report_evidence_entry(entry: dict[str, Any], entry_index: int) -> list[str]:
    """Render a single evidence entry using report-specific formatting."""

    lines = ["", f"##### Entry {entry_index}", ""]

    target = str(entry.get("target") or "")
    host, port, service = parse_target(target)
    if not host:
        host = str(entry.get("host") or "").strip()

    if host:
        lines.append(f"**Host:** {host}  ")

    service_label = ""
    if port:
        service_label = f"{port}/tcp"
        if service:
            service_label = f"{service_label} ({service})"
    elif entry.get("service"):
        service_label = str(entry.get("service") or "").strip()

    if service_label:
        lines.append(f"**Service:** {service_label}")

    evidence_content = _normalise_evidence_text(
        clean_evidence_output(_remove_target_lines(str(entry.get("content") or "")))
    )
    if not evidence_content and target and not (host or service_label):
        evidence_content = f"Target: {target}"

    if host or service_label:
        lines.append("")

    lines.extend(
        [
            "```text",
            evidence_content,
            "```",
        ]
    )
    return lines


def render_report_markdown(report: dict[str, Any]) -> str:
    """Render a structured scan report as Markdown."""

    total_hosts = int(report["hosts"]["total"])
    executive_summary = _build_executive_summary(report)
    lines: list[str] = [
        PAGE_BREAK_BLOCK,
        "",
        "## Scan Details",
        "",
        f"**Scan Name:** {report['scan']['name']}  ",
        f"**Scan ID:** {report['scan']['id']}  ",
        f"**History ID:** {report['scan']['history_id']}  ",
        f"**Scan Date:** {report['scan']['scan_date']}  ",
        f"**Generated:** {report['scan']['generated_at']}  ",
        "",
        "## Scope",
        "",
        f"- Hosts included: {report['scope']['hosts_included']}",
        f"- Hosts excluded: {report['scope']['hosts_excluded']}",
        f"- Severity: {_format_severity_scope(report['scope']['severity'])}",
        "",
        "## Executive Summary",
        "",
        *executive_summary,
    ]

    if total_hosts > 1:
        lines.extend(
            [
                "",
                "## Hosts in Scope",
                "",
                "| Host | Operating System |",
                "| --- | --- |",
            ]
        )
        for host in report["hosts"]["items"]:
            lines.append(
                f"| {_escape_markdown_table(host['host'])} | "
                f"{_escape_markdown_table(host['operating_system'])} |"
            )

    lines.extend(
        [
            "",
            PAGE_BREAK_BLOCK,
            "",
            "## Findings",
            "",
        ]
    )

    if not report["findings"]:
        lines.append("No findings matched the selected criteria.")
        return "\n".join(lines)

    finding_index = 1
    for finding in report["findings"]:
        lines.append(_render_report_finding_markdown(finding, finding_index))
        lines.extend(
            [
                "",
                PAGE_BREAK_BLOCK,
                "",
            ]
        )
        finding_index += 1

    return "\n".join(lines).rstrip() + "\n"
