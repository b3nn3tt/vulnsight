"""Shared finding formatters for CLI, Markdown, and JSON output."""

from __future__ import annotations

import re
from typing import Any

NESSUS_LINE_RE = re.compile(r"^Nessus.*?[.:]\s*$")


def normalise_finding(raw_data: dict[str, Any]) -> dict[str, Any]:
    """Normalise finding data into a consistent, reusable structure."""

    severity_value = raw_data.get("severity_value")
    severity_label = str(raw_data.get("severity_label") or "Unknown")
    severity_display = str(raw_data.get("severity_display") or severity_label)

    evidence_entries = []
    for entry in raw_data.get("evidence_entries", []):
        if not isinstance(entry, dict):
            continue

        evidence_entries.append(
            {
                "host": str(entry.get("host") or ""),
                "content": str(entry.get("plugin_output") or ""),
                "service": str(entry.get("service") or ""),
                "target": str(entry.get("target") or ""),
            }
        )

    return {
        "id": int(raw_data.get("plugin_id", 0) or 0),
        "name": str(raw_data.get("plugin_name") or "Not available."),
        "severity": {
            "value": int(severity_value or 0) if severity_value is not None else None,
            "label": severity_label,
            "display": severity_display,
        },
        "host_count": int(raw_data.get("host_count", 0) or 0),
        "hosts": [str(host) for host in raw_data.get("hosts", [])],
        "cves": [str(cve) for cve in raw_data.get("cves", [])],
        "description": str(raw_data.get("description") or "Not available."),
        "solution": str(raw_data.get("solution") or "Not available."),
        "evidence": evidence_entries,
        "metadata_sections": [
            (
                str(title),
                [(str(label), str(value)) for label, value in fields],
            )
            for title, fields in raw_data.get("metadata_sections", [])
        ],
        "reference_sections": [
            (
                str(title),
                [(str(label), str(url)) for label, url in references],
            )
            for title, references in raw_data.get("reference_sections", [])
        ],
    }


def _append_key_value_section(
    lines: list[str], title: str, fields: list[tuple[str, str]]
) -> None:
    """Append a simple key-value section to the output buffer."""

    if not fields:
        return

    lines.append("")
    lines.append(f"{title}:")
    label_width = max(len(label) for label, _ in fields)
    for label, value in fields:
        lines.append(f"  {label:<{label_width}} : {value}")


def _append_section_header(lines: list[str], title: str) -> None:
    """Append a simple section header with consistent spacing."""

    lines.append("")
    lines.append(f"{title}:")


def _append_cli_evidence(lines: list[str], evidence_entries: list[dict[str, str]]) -> None:
    """Append CLI evidence entries to the output buffer."""

    if not evidence_entries:
        lines.append("No plugin output available.")
        return

    for index, entry in enumerate(evidence_entries, start=1):
        if len(evidence_entries) > 1:
            lines.append(f"[bold][Entry {index}][/bold]")
        lines.append(entry["content"])
        if entry.get("target"):
            lines.append(f"Target            : {entry['target']}")
        if index != len(evidence_entries):
            lines.append("")


def render_finding_cli(
    data: dict[str, Any],
    validation_status: str | None = None,
    validation_note: str | None = None,
) -> str:
    """Render a normalised finding in the standard CLI format."""

    lines = [
        f"Name        : {data['name']}",
        f"ID          : {data['id']}",
        f"Severity    : {data['severity']['display']}",
        f"Hosts       : {data['host_count']}",
    ]

    if validation_status:
        lines.extend(
            [
                "",
                "Validation:",
                f"  Status    : {validation_status}",
            ]
        )
        if validation_note:
            lines.append(f"  Note      : {validation_note}")

    for title, fields in data.get("metadata_sections", []):
        _append_key_value_section(lines, title, fields)

    _append_section_header(lines, "Affected Hosts")
    if data.get("hosts"):
        lines.extend(f"- {host}" for host in data["hosts"])
    else:
        lines.append("None listed.")

    if data.get("cves"):
        _append_section_header(lines, "CVEs")
        lines.extend(f"- {cve}" for cve in data["cves"])

    _append_section_header(lines, "Description")
    lines.append(data["description"])

    _append_section_header(lines, "Recommendation")
    lines.append(data["solution"])

    _append_section_header(lines, "Evidence")
    _append_cli_evidence(lines, data.get("evidence", []))

    for title, references in data.get("reference_sections", []):
        _append_section_header(lines, title)
        lines.extend(f"- {label}: {url}" for label, url in references)

    return "\n".join(lines)


def parse_target(target_line: str) -> tuple[str, str, str]:
    """
    Parse a target string into host, port, and service.

    Expected input examples:
    - Target: 10.54.29.10:445 (cifs)
    - 10.54.29.10:445 (cifs)
    """

    target = str(target_line or "").strip()
    if target.lower().startswith("target:"):
        target = target.split(":", 1)[1].strip()

    match = re.match(
        r"^(?P<host>.+?):(?P<port>\d+)(?:\s+\((?P<service>[^)]+)\))?$",
        target,
    )
    if not match:
        return "", "", ""

    return (
        match.group("host").strip(),
        match.group("port").strip(),
        (match.group("service") or "").strip(),
    )


def _remove_target_lines(content: str) -> str:
    """Remove Target lines from raw evidence content."""

    lines = []
    for line in str(content or "").splitlines():
        if line.strip().lower().startswith("target:"):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def clean_evidence_output(text: str) -> str:
    """Remove redundant Nessus-generated intro lines from evidence output."""

    lines = str(text or "").splitlines()
    cleaned = [
        line for line in lines if not NESSUS_LINE_RE.match(line.strip())
    ]
    return "\n".join(cleaned).strip()


def _get_markdown_evidence_context(entry: dict[str, str]) -> tuple[str, str, str]:
    """Return host, port, and service context for a Markdown evidence entry."""

    host, port, service = parse_target(entry.get("target", ""))
    if host and port:
        return host, port, service

    content = str(entry.get("content") or "")
    for line in content.splitlines():
        if not line.strip().lower().startswith("target:"):
            continue

        host, port, service = parse_target(line)
        if host and port:
            return host, port, service

    return "", "", ""


def render_finding_markdown(
    data: dict[str, Any],
    validation_status: str | None = None,
    validation_note: str | None = None,
) -> str:
    """Render a normalised finding as Markdown."""

    affected_hosts = ", ".join(data["hosts"]) if data.get("hosts") else "None listed"

    lines: list[str] = [
        f"### {data['name']}",
        "",
        f"**ID:** {data['id']}  ",
        f"**Severity:** {data['severity']['label']}  ",
        f"**Affected Hosts ({data['host_count']}):** {affected_hosts}",
    ]

    if validation_status:
        lines.append(f"**Validation Status:** {validation_status}")
        if validation_note:
            lines.append(f"**Validation Note:** {validation_note}")

    for title, fields in data.get("metadata_sections", []):
        lines.extend(["", f"#### {title}"])
        lines.extend(f"- **{label}:** {value}" for label, value in fields)

    if data.get("cves"):
        lines.extend(["", "#### CVEs"])
        lines.extend(f"- {cve}" for cve in data["cves"])

    lines.extend(
        [
            "",
            "#### Description",
            data["description"],
            "",
            "#### Recommendation",
            data["solution"],
            "",
            "#### Evidence",
        ]
    )

    if data.get("evidence"):
        for index, entry in enumerate(data["evidence"], start=1):
            evidence_content = clean_evidence_output(
                _remove_target_lines(entry["content"])
            )
            host, port, service = _get_markdown_evidence_context(entry)

            lines.extend(
                [
                    "",
                    f"##### Entry {index}",
                ]
            )

            if host and port:
                service_label = f"{port}/tcp"
                if service:
                    service_label = f"{service_label} ({service})"
                lines.extend(
                    [
                        "",
                        f"**Host:** {host}  ",
                        f"**Service:** {service_label}",
                    ]
                )

            if not evidence_content and entry.get("target") and not (host and port):
                evidence_content = f"Target: {entry['target']}"

            lines.extend(
                [
                    "",
                    "```",
                    evidence_content,
                    "```",
                ]
            )
    else:
        lines.extend(["", "No plugin output available."])

    for title, references in data.get("reference_sections", []):
        lines.extend(["", f"#### {title}"])
        lines.extend(f"- {label}: {url}" for label, url in references)

    return "\n".join(lines)
