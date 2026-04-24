"""Command for displaying detailed information about a single finding."""

from __future__ import annotations

import re
import json
from typing import Any

import requests
import typer
from rich.console import Console

from vulnsight.commands.remediation import clean_recommendation
from vulnsight.commands.scans import _build_client
from vulnsight.context import load_context
from vulnsight.formatters.finding import (
    normalise_finding,
    render_finding_cli,
    render_finding_markdown,
)
from vulnsight.validation import get_validation, get_validation_display


console = Console()

SEVERITY_LABELS = {
    0: "Info",
    1: "Low",
    2: "Medium",
    3: "High",
    4: "Critical",
}

SEVERITY_STYLES = {
    "Info": "dim",
    "Low": "green",
    "Medium": "blue",
    "High": "yellow",
    "Critical": "red",
}


def _get_severity_label(severity: int | str | None) -> str:
    """Convert a numeric severity into a readable label."""

    try:
        return SEVERITY_LABELS[int(severity)]
    except (KeyError, TypeError, ValueError):
        return "Unknown"


def _format_severity(severity: int | str | None) -> str:
    """Convert a numeric severity into a colourised label."""

    label = _get_severity_label(severity)
    style = SEVERITY_STYLES.get(label)
    if style is None:
        return label
    return f"[{style}]{label}[/{style}]"


def _normalise_text(value: Any) -> str:
    """Convert a response value into readable text when possible."""

    if isinstance(value, str):
        return value.strip()

    if isinstance(value, bool):
        return str(value).lower()

    if isinstance(value, (int, float)):
        return str(value)

    if isinstance(value, dict):
        for key in ("attribute_value", "value", "text", "content"):
            nested_value = value.get(key)
            text = _normalise_text(nested_value)
            if text:
                return text
        return ""

    if isinstance(value, list):
        parts = []
        for item in value:
            text = _normalise_text(item)
            if text:
                parts.append(text)
        return "\n".join(parts).strip()

    return ""


def _get_nested_value(payload: dict[str, Any], path: tuple[str, ...]) -> Any:
    """Safely retrieve a nested value from a dictionary payload."""

    value: Any = payload
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _get_text_field(response: dict[str, Any], *paths: tuple[str, ...]) -> str:
    """Return the first non-empty text value from a set of nested paths."""

    for path in paths:
        value = _get_nested_value(response, path)
        text = _normalise_text(value)
        if text:
            return text

    return "Not available."


def _get_metadata_text(metadata: dict[str, Any], *keys: str) -> str:
    """Return the first non-empty text value from plugin metadata."""

    attributes = metadata.get("attributes", {})
    target_keys = {key.lower() for key in keys}

    for key in keys:
        text = _normalise_text(metadata.get(key))
        if text:
            return text

        if isinstance(attributes, dict):
            text = _normalise_text(attributes.get(key))
            if text:
                return text

    if isinstance(attributes, list):
        for item in attributes:
            if not isinstance(item, dict):
                continue

            item_name = str(
                item.get("attribute_name")
                or item.get("name")
                or item.get("attribute")
                or ""
            ).strip().lower()

            if item_name not in target_keys:
                continue

            text = _normalise_text(
                item.get("attribute_value")
                or item.get("value")
                or item.get("text")
                or item.get("content")
            )
            if text:
                return text

    return "Not available."


def _get_metadata_values(metadata: dict[str, Any], *keys: str) -> list[str]:
    """Return all matching metadata values for the requested keys."""

    attributes = metadata.get("attributes", {})
    target_keys = {key.lower() for key in keys}
    values: list[str] = []

    def add_value(raw_value: Any) -> None:
        text = _normalise_text(raw_value)
        if not text:
            return

        for part in text.split(","):
            item = part.strip()
            if item and item not in values:
                values.append(item)

    for key in keys:
        add_value(metadata.get(key))
        if isinstance(attributes, dict):
            add_value(attributes.get(key))

    if isinstance(attributes, list):
        for item in attributes:
            if not isinstance(item, dict):
                continue

            item_name = str(
                item.get("attribute_name")
                or item.get("name")
                or item.get("attribute")
                or ""
            ).strip().lower()

            if item_name not in target_keys:
                continue

            add_value(
                item.get("attribute_value")
                or item.get("value")
                or item.get("text")
                or item.get("content")
            )

    return values


def _format_host_entry(hostname: str, port: str) -> str:
    """Build a readable host entry including port when available."""

    if hostname and port:
        return f"{hostname}:{port}"
    return hostname


def _get_plugin_attribute_text(response: dict[str, Any], *attribute_names: str) -> str:
    """Return plugin attribute text from dict or list-shaped pluginattributes data."""

    info = response.get("info", {})
    plugin_attributes = info.get("pluginattributes") or info.get("attributes")
    target_names = {name.lower() for name in attribute_names}

    if isinstance(plugin_attributes, dict):
        for name in attribute_names:
            text = _normalise_text(plugin_attributes.get(name))
            if text:
                return text

    if isinstance(plugin_attributes, list):
        for item in plugin_attributes:
            if not isinstance(item, dict):
                continue

            item_name = str(
                item.get("attribute_name")
                or item.get("name")
                or item.get("attribute")
                or ""
            ).strip().lower()

            if item_name not in target_names:
                continue

            text = _normalise_text(
                item.get("attribute_value")
                or item.get("value")
                or item.get("text")
            )
            if text:
                return text

    return "Not available."


def _format_service_entry(port: str, protocol: str, service_name: str) -> str:
    """Build a readable service string from output fields."""

    parts = []
    if port:
        parts.append(port)
    if protocol:
        parts.append(protocol)
    if service_name:
        parts.append(service_name)
    return " / ".join(parts)


def _format_target_entry(host: str, service: str) -> str:
    """Build a self-contained target string from host and service context."""

    if not host and not service:
        return ""

    if not service:
        return host

    parts = [part.strip() for part in service.split("/") if part.strip()]
    if not parts:
        return host or service

    port = parts[0]
    protocol = parts[1] if len(parts) >= 2 else ""
    service_name = parts[-1] if len(parts) >= 3 else ""

    if host and port:
        if port == "0":
            if service_name:
                return f"{host} ({service_name})"
            if protocol:
                return f"{host} ({protocol})"
            return host
        if service_name:
            return f"{host}:{port} ({service_name})"
        return f"{host}:{port}"

    return host or service


def _extract_evidence_entries(
    outputs: list[dict[str, Any]], fallback_host: str = ""
) -> list[dict[str, str]]:
    """Build structured evidence entries from plugin output rows."""

    evidence_entries: list[dict[str, str]] = []
    seen_entries: set[tuple[str, str, str]] = set()

    for output in outputs:
        hostname = str(
            output.get("hostname")
            or output.get("host")
            or output.get("host_id")
            or fallback_host
            or ""
        ).strip()
        port = str(output.get("port") or "").strip()
        protocol = str(output.get("protocol") or "").strip()
        service_name = str(
            output.get("svc_name") or output.get("service_name") or output.get("service") or ""
        ).strip()

        plugin_output = str(output.get("plugin_output") or "").strip()
        ports_mapping = output.get("ports")

        if isinstance(ports_mapping, dict) and ports_mapping:
            for service_entry, port_hosts in ports_mapping.items():
                service_label = str(service_entry).strip()
                if not isinstance(port_hosts, list):
                    port_hosts = []

                if not port_hosts:
                    entry_host = hostname
                    entry_key = (plugin_output, entry_host, service_label)
                    if plugin_output and entry_key not in seen_entries:
                        evidence_entries.append(
                            {
                                "plugin_output": plugin_output,
                                "host": entry_host,
                                "service": service_label,
                            }
                        )
                        seen_entries.add(entry_key)
                    continue

                for port_host in port_hosts:
                    if isinstance(port_host, dict):
                        mapped_host = str(
                            port_host.get("hostname")
                            or port_host.get("host")
                            or port_host.get("ip")
                            or fallback_host
                            or ""
                        ).strip()
                    else:
                        mapped_host = str(port_host or fallback_host or "").strip()

                    entry_key = (plugin_output, mapped_host, service_label)
                    if plugin_output and entry_key not in seen_entries:
                        evidence_entries.append(
                            {
                                "plugin_output": plugin_output,
                                "host": mapped_host,
                                "service": service_label,
                            }
                        )
                        seen_entries.add(entry_key)
            continue

        host_entry = _format_host_entry(hostname, port)
        service_entry = _format_service_entry(port, protocol, service_name)
        entry_key = (plugin_output, host_entry, service_entry)
        if plugin_output and entry_key not in seen_entries:
            evidence_entries.append(
                {
                    "plugin_output": plugin_output,
                    "host": host_entry,
                    "service": service_entry,
                }
            )
            seen_entries.add(entry_key)

    return evidence_entries


def _host_has_plugin(host_details: dict[str, Any], plugin_id: int) -> bool:
    """Return whether host details contain the requested plugin."""

    for vulnerability in host_details.get("vulnerabilities", []):
        if int(vulnerability.get("plugin_id", 0) or 0) == plugin_id:
            return True
    return False


def _get_host_vulnerability_context(host_details: dict[str, Any], plugin_id: int) -> dict[str, str]:
    """Return host/service context for a matching host vulnerability entry."""

    for vulnerability in host_details.get("vulnerabilities", []):
        if int(vulnerability.get("plugin_id", 0) or 0) != plugin_id:
            continue

        port = str(vulnerability.get("port") or "").strip()
        protocol = str(vulnerability.get("protocol") or "").strip()
        service_name = str(
            vulnerability.get("svc_name")
            or vulnerability.get("service_name")
            or vulnerability.get("service")
            or ""
        ).strip()

        return {
            "port": port,
            "protocol": protocol,
            "service_name": service_name,
            "service": _format_service_entry(port, protocol, service_name),
        }

    return {"port": "", "protocol": "", "service_name": "", "service": ""}


def _find_affected_hosts(
    client,
    scan_result_details: dict[str, Any],
    scan_id: int,
    history_id: int,
    plugin_id: int,
) -> list[str]:
    """Build affected host identifiers by inspecting host-level scan results."""

    hosts: set[str] = set()

    for host in scan_result_details.get("hosts", []):
        if not isinstance(host, dict):
            continue

        host_id = host.get("host_id")
        if host_id is None:
            continue

        try:
            host_details = client.get_host_details(int(scan_id), int(host_id), int(history_id))
        except requests.RequestException:
            continue

        if not _host_has_plugin(host_details, plugin_id):
            continue

        hostname = str(
            host.get("hostname")
            or host.get("host")
            or host.get("name")
            or host.get("ip")
            or host_details.get("hostname")
            or host_details.get("host")
            or host_details.get("info", {}).get("host-ip")
            or ""
        ).strip()
        port = str(
            host.get("port")
            or host_details.get("port")
            or ""
        ).strip()

        host_entry = _format_host_entry(hostname, port)
        if host_entry:
            hosts.add(host_entry)

    return sorted(hosts)


def _collect_evidence_entries(
    client,
    response: dict[str, Any],
    scan_result_details: dict[str, Any],
    scan_id: int,
    history_id: int,
    plugin_id: int,
) -> tuple[list[str], list[dict[str, str]]]:
    """Collect evidence entries, preferring host-correlated plugin output when available."""

    hosts: set[str] = set()
    evidence_entries: list[dict[str, str]] = []
    seen_entries: set[tuple[str, str, str]] = set()

    for host in scan_result_details.get("hosts", []):
        if not isinstance(host, dict):
            continue

        host_id = host.get("host_id")
        if host_id is None:
            continue

        host_name = str(
            host.get("hostname") or host.get("host") or host.get("ip") or host.get("name") or ""
        ).strip()

        try:
            host_details = client.get_host_details(scan_id, int(host_id), history_id)
        except requests.RequestException:
            host_details = {}

        if host_details and not _host_has_plugin(host_details, plugin_id):
            continue

        try:
            host_plugin_details = client.get_host_plugin_output(
                scan_id, int(host_id), plugin_id, history_id
            )
        except requests.RequestException:
            continue

        vulnerability_context = _get_host_vulnerability_context(host_details, plugin_id)
        host_outputs = host_plugin_details.get("outputs", [])
        host_entries = _extract_evidence_entries(host_outputs, fallback_host=host_name)
        for entry in host_entries:
            if not entry["service"]:
                entry["service"] = vulnerability_context["service"]

            if not entry["host"]:
                entry["host"] = _format_host_entry(
                    host_name,
                    vulnerability_context["port"],
                )

            if entry["host"]:
                hosts.add(entry["host"])

            entry["target"] = _format_target_entry(entry["host"], entry["service"])

            entry_key = (
                entry["plugin_output"],
                entry["host"],
                entry["service"],
            )
            if entry_key in seen_entries:
                continue

            evidence_entries.append(entry)
            seen_entries.add(entry_key)

    if evidence_entries:
        return sorted(hosts), evidence_entries

    plugin_entries = _extract_evidence_entries(response.get("outputs", []))
    for entry in plugin_entries:
        if entry["host"]:
            hosts.add(entry["host"])
        entry["target"] = _format_target_entry(entry["host"], entry["service"])

    for host in response.get("hosts", []):
        if not isinstance(host, dict):
            continue

        hostname = str(
            host.get("hostname")
            or host.get("host")
            or host.get("name")
            or host.get("ip")
            or ""
        ).strip()
        port = str(host.get("port") or "").strip()
        host_entry = _format_host_entry(hostname, port)
        if host_entry:
            hosts.add(host_entry)

    if not hosts:
        hosts.update(_find_affected_hosts(client, scan_result_details, scan_id, history_id, plugin_id))

    return sorted(hosts), plugin_entries


def _get_finding_summary(
    scan_details: dict[str, Any], plugin_id: int
) -> dict[str, Any] | None:
    """Return the aggregated finding entry for a plugin from scan details."""

    for vulnerability in scan_details.get("vulnerabilities", []):
        if int(vulnerability.get("plugin_id", 0) or 0) == plugin_id:
            return vulnerability
    return None


def _extract_cves(description: str) -> list[str]:
    """Extract and deduplicate CVE identifiers from description text."""

    matches = re.findall(r"CVE-\d{4}-\d{4,7}", description)
    unique_matches = set(matches)

    def sort_key(value: str) -> tuple[int, int]:
        _, year, identifier = value.split("-")
        return int(year), int(identifier)

    return sorted(unique_matches, key=sort_key)


def _clean_description(description: str) -> str:
    """Remove low-value Nessus boilerplate from finding descriptions."""

    boilerplate_patterns = [
        (
            r"\n*Note that Nessus has not tested for these issues but has instead "
            r"relied only on the application's self-reported version number\.?\n*"
        ),
    ]

    cleaned = description
    for pattern in boilerplate_patterns:
        cleaned = re.sub(pattern, "\n\n", cleaned, flags=re.IGNORECASE)

    return cleaned.strip()


def _build_metadata_sections(
    plugin_metadata: dict[str, Any], plugin_id: int
) -> list[tuple[str, list[tuple[str, str]]]]:
    """Build display sections from plugin metadata."""

    risk_information = [
        (
            "CVSS v3.0",
            _get_metadata_text(plugin_metadata, "cvss3_base_score", "cvss3_base"),
        ),
        (
            "CVSS v2.0",
            _get_metadata_text(
                plugin_metadata, "cvss2_base_score", "cvss_base_score", "cvss2_base"
            ),
        ),
    ]

    vulnerability_information = [
        ("CPE", _get_metadata_text(plugin_metadata, "cpe")),
        (
            "Exploit Available",
            _get_metadata_text(plugin_metadata, "exploit_available", "exploitability_ease"),
        ),
        (
            "Patch Publication Date",
            _get_metadata_text(
                plugin_metadata,
                "patch_publication_date",
                "patch_pub_date",
            ),
        ),
        (
            "Vulnerability Publication Date",
            _get_metadata_text(
                plugin_metadata,
                "vuln_publication_date",
                "vuln_pub_date",
            ),
        ),
    ]

    sections = [
        ("Risk Information", risk_information),
        ("Vulnerability Information", vulnerability_information),
    ]

    return [
        (title, [(label, value) for label, value in fields if value != "Not available."])
        for title, fields in sections
        if any(value != "Not available." for _, value in fields)
    ]


def _get_reference_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract raw reference items from known Nessus response shapes."""

    candidate_paths = [
        ("info", "plugindescription", "pluginattributes", "ref_information", "ref"),
        ("info", "pluginattributes", "ref_information", "ref"),
        ("attributes", "ref_information", "ref"),
    ]

    for path in candidate_paths:
        value = _get_nested_value(payload, path)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]

    return []


def _build_reference_url(reference_name: str, reference_value: str, base_url: str) -> str:
    """Build a usable URL for a reference value."""

    name = reference_name.lower()
    value = reference_value.strip()

    if name == "cve":
        return f"https://nvd.nist.gov/vuln/detail/{value}"
    if name == "msft":
        return f"https://msrc.microsoft.com/update-guide/en-US/search?query={value}"
    if name == "mskb":
        return f"https://support.microsoft.com/en-us/help/{value}"

    if base_url:
        return f"{base_url}{value}"

    return value


def _build_reference_sections(
    response: dict[str, Any], plugin_metadata: dict[str, Any], cves: list[str]
) -> list[tuple[str, list[tuple[str, str]]]]:
    """Build grouped reference sections, with CVEs first when present."""

    grouped: dict[str, list[tuple[str, str]]] = {}
    seen: set[tuple[str, str]] = set()

    for source in (response, plugin_metadata):
        for item in _get_reference_items(source):
            name = str(item.get("name") or "other").strip().lower()
            raw_values = _get_nested_value(item, ("values", "value"))
            values: list[str]
            if isinstance(raw_values, list):
                values = [str(value).strip() for value in raw_values if str(value).strip()]
            elif raw_values is not None:
                values = [str(raw_values).strip()]
            else:
                values = []

            base_url = str(item.get("url") or "").strip()
            for value in values:
                key = (name, value)
                if key in seen:
                    continue
                seen.add(key)
                grouped.setdefault(name, []).append(
                    (value, _build_reference_url(name, value, base_url))
                )

    if "cve" not in grouped and cves:
        grouped["cve"] = [(cve, f"https://nvd.nist.gov/vuln/detail/{cve}") for cve in cves]

    sections: list[tuple[str, list[tuple[str, str]]]] = []
    if "cve" in grouped:
        sections.append(("CVE References", grouped.pop("cve")))

    for name in sorted(grouped):
        sections.append((f"{name.upper()} References", grouped[name]))

    return sections


def _build_debug_data(
    client,
    scan_result_details: dict[str, Any],
    scan_id: int,
    history_id: int,
    plugin_id: int,
) -> dict[str, Any]:
    """Collect raw host/plugin data to help inspect service-context fields."""

    debug_hosts: list[dict[str, Any]] = []

    for host in scan_result_details.get("hosts", []):
        if not isinstance(host, dict):
            continue

        host_id = host.get("host_id")
        if host_id is None:
            continue

        try:
            host_details = client.get_host_details(scan_id, int(host_id), history_id)
        except requests.RequestException:
            host_details = {}

        matched_vulnerability = None
        for vulnerability in host_details.get("vulnerabilities", []):
            if int(vulnerability.get("plugin_id", 0) or 0) == plugin_id:
                matched_vulnerability = vulnerability
                break

        try:
            host_plugin_output = client.get_host_plugin_output(
                scan_id, int(host_id), plugin_id, history_id
            )
        except requests.RequestException:
            host_plugin_output = {}

        if matched_vulnerability is None and not host_plugin_output:
            continue

        debug_hosts.append(
            {
                "host_summary": host,
                "matched_vulnerability": matched_vulnerability,
                "host_plugin_output": host_plugin_output,
            }
        )

    return {
        "scan_id": scan_id,
        "history_id": history_id,
        "plugin_id": plugin_id,
        "hosts": debug_hosts,
    }


def build_finding_data(
    client,
    scan_details: dict[str, Any],
    scan_id: int,
    history_id: int,
    plugin_id: int,
) -> dict[str, Any]:
    """Build the normalised finding payload for a plugin in a scan history."""

    response = client.get_plugin_details(scan_id, plugin_id, history_id)
    plugin_metadata = client.get_plugin_metadata(plugin_id)

    finding_summary = _get_finding_summary(scan_details, plugin_id)
    if finding_summary is None:
        raise ValueError("Plugin not found in this scan.")

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
    severity = _format_severity(severity_value)

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

    hosts, evidence_entries = _collect_evidence_entries(
        client, response, scan_details, scan_id, history_id, plugin_id
    )
    host_count = len(hosts) if hosts else int(finding_summary.get("count", 0) or 0)
    cves = _extract_cves(description)
    severity_label = _get_severity_label(severity_value)
    metadata_sections = _build_metadata_sections(plugin_metadata, plugin_id)
    reference_sections = _build_reference_sections(response, plugin_metadata, cves)

    raw_data = {
        "plugin_id": plugin_id,
        "plugin_name": plugin_name,
        "severity_value": severity_value,
        "severity_label": severity_label,
        "severity_display": severity,
        "host_count": host_count,
        "metadata_sections": metadata_sections,
        "hosts": hosts,
        "cves": cves,
        "description": description,
        "solution": solution,
        "evidence_entries": evidence_entries,
        "reference_sections": reference_sections,
    }
    return normalise_finding(raw_data)


def _get_cvss_v3_value(finding: dict[str, Any]) -> str | None:
    """Return the first available CVSS v3 value from the normalized finding."""

    for title, fields in finding.get("metadata_sections", []):
        if title != "Risk Information":
            continue

        for label, value in fields:
            if label == "CVSS v3.0":
                cleaned_value = str(value).strip()
                if cleaned_value:
                    return cleaned_value

    return None


def _print_remediation_finding(
    finding: dict[str, Any],
    validation_status: str,
    validation_note: str = "",
) -> None:
    """Render a remediation-focused view for a single finding."""

    severity_label = str(finding.get("severity", {}).get("label") or "Unknown")
    hosts = finding.get("hosts", []) or []
    cvss_v3 = _get_cvss_v3_value(finding)

    console.print(f"Name: {finding.get('name', '')}", highlight=False)
    console.print(f"ID: {finding.get('id', '')}", highlight=False)
    console.print(f"Severity: {severity_label}", highlight=False)
    console.print()
    console.print("Validation:", highlight=False)
    console.print(f"  Status: {validation_status}", highlight=False)
    if validation_note:
        console.print(f"  Note: {validation_note}", highlight=False)
    console.print()

    if cvss_v3:
        console.print("Risk Information:", highlight=False)
        console.print(f"  CVSS v3.0: {cvss_v3}", highlight=False)
        console.print()

    console.print("Affected Hosts:", highlight=False)
    if hosts:
        for host in hosts:
            console.print(f"  - {host}", highlight=False)
    else:
        console.print("  - No host information available", highlight=False)

    console.print()
    console.print("Recommendation:", highlight=False)
    console.print(
        clean_recommendation(str(finding.get("solution") or "")),
        highlight=False,
    )


def get_finding(
    plugin_id: int,
    output_format: str | None = None,
    remediation: bool = False,
) -> None:
    """Retrieve and display full details for a finding in the active scan context."""

    context = load_context()
    if not context:
        console.print(
            "[red]No active scan context.[/red] "
            "Use 'vulnsight use <scan_name>' first."
        )
        raise typer.Exit(code=1)

    scan_id = int(context.get("scan_id", 0))
    history_id = int(context.get("history_id", 0))
    client = _build_client()

    try:
        scan_details = client.get_scan_result_details(scan_id, history_id)
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            console.print("[red]Plugin not found in this scan.[/red]")
        raise typer.Exit(code=1) from exc
        console.print(f"[red]Failed to retrieve plugin details:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except requests.RequestException as exc:
        console.print(f"[red]Failed to retrieve plugin details:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if output_format == "debug":
        debug_data = _build_debug_data(
            client, scan_details, scan_id, history_id, plugin_id
        )
        console.print(json.dumps(debug_data, indent=2), highlight=False)
        return

    try:
        data = build_finding_data(client, scan_details, scan_id, history_id, plugin_id)
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            console.print("[red]Plugin not found in this scan.[/red]")
            raise typer.Exit(code=1) from exc
        console.print(f"[red]Failed to retrieve plugin details:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except requests.RequestException as exc:
        console.print(f"[red]Failed to retrieve plugin details:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except ValueError:
        console.print("[red]Plugin not found in this scan.[/red]")
        raise typer.Exit(code=1)

    validation = get_validation(scan_id, history_id, plugin_id)
    validation_status = get_validation_display(str(validation.get("status") or "unreviewed"))
    validation_note = str(validation.get("notes") or "").strip()

    if remediation:
        _print_remediation_finding(data, validation_status, validation_note)
        return

    if output_format in ["json"]:
        console.print(json.dumps(data, indent=2), highlight=False)
    elif output_format in ["markdown", "md"]:
        console.print(
            render_finding_markdown(data, validation_status, validation_note),
            highlight=False,
        )
    else:
        console.print(
            render_finding_cli(data, validation_status, validation_note),
            highlight=False,
        )
