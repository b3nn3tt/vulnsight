"""Command for comparing two scan runs for the active scan context."""

from __future__ import annotations

import csv
import sys

import requests
import typer
from rich import box
from rich.console import Console
from rich.table import Table

from vulnsight.commands.findings import (
    SEVERITY_LABELS,
    _format_hosts_display,
    _format_severity,
    _get_plugin_hosts,
    _get_scan_host_names,
    _resolve_minimum_severity,
)
from vulnsight.commands.history import _get_sorted_history_entries
from vulnsight.commands.scans import _build_client
from vulnsight.context import load_context


console = Console()


def _print_invalid_history(history_id: str) -> None:
    """Print a consistent invalid-history message."""

    console.print(f"[red]History ID '{history_id}' not found for this scan.[/red]")
    console.print("Use 'vulnsight history' to view available runs.")


def _parse_history_id(value: str, valid_history_ids: set[int]) -> int | None:
    """Parse and validate a history ID value."""

    try:
        history_id = int(value)
    except (TypeError, ValueError):
        _print_invalid_history(str(value))
        return None

    if history_id not in valid_history_ids:
        _print_invalid_history(str(value))
        return None

    return history_id


def _resolve_history_pair(
    scan_details: dict,
    current_history_id: int,
    compare: str | None,
    against: str | None,
) -> tuple[int, int, bool] | None:
    """Resolve the two history IDs that should be compared."""

    history_entries = _get_sorted_history_entries(scan_details)
    valid_history_ids = {
        int(entry.get("history_id", 0) or 0)
        for entry in history_entries
        if entry.get("history_id") is not None
    }

    if bool(compare) != bool(against):
        console.print("[red]Both --compare and --against must be provided together.[/red]")
        return None

    if compare and against:
        compare_id = _parse_history_id(compare, valid_history_ids)
        against_id = _parse_history_id(against, valid_history_ids)
        if compare_id is None or against_id is None:
            return None
        if compare_id == against_id:
            console.print(
                "[yellow]Compare and against history IDs are the same. "
                "Choose two different scan runs to diff.[/yellow]"
            )
            return None
        return compare_id, against_id, True

    if current_history_id not in valid_history_ids:
        _print_invalid_history(str(current_history_id))
        return None

    current_index = next(
        (
            index
            for index, entry in enumerate(history_entries)
            if int(entry.get("history_id", 0) or 0) == current_history_id
        ),
        None,
    )
    if current_index is None:
        _print_invalid_history(str(current_history_id))
        return None

    previous_index = current_index + 1
    if previous_index >= len(history_entries):
        console.print("[yellow]No previous scan run available to compare.[/yellow]")
        return None

    compare_id = int(history_entries[previous_index].get("history_id", 0) or 0)
    against_id = current_history_id
    return compare_id, against_id, False


def _is_reverse_diff(
    compare_id: int, against_id: int, history_lookup: dict[int, dict]
) -> bool:
    """Return True when the comparison direction is newer to older."""

    compare_entry = history_lookup.get(compare_id, {})
    against_entry = history_lookup.get(against_id, {})

    compare_created = int(compare_entry.get("creation_date", 0) or 0)
    against_created = int(against_entry.get("creation_date", 0) or 0)

    if compare_created and against_created:
        return compare_created > against_created

    return compare_id > against_id


def _build_finding_map(vulnerabilities: list[dict]) -> dict[int, dict]:
    """Return a map of plugin ID to normalized finding data."""

    findings: dict[int, dict] = {}
    for vulnerability in vulnerabilities:
        plugin_id = int(vulnerability.get("plugin_id", 0) or 0)
        findings[plugin_id] = {
            "plugin_id": plugin_id,
            "plugin_name": str(vulnerability.get("plugin_name", "")),
            "severity": int(vulnerability.get("severity", 0) or 0),
            "count": int(vulnerability.get("count", 0) or 0),
        }
    return findings


def _get_cached_plugin_hosts(
    client,
    scan_id: int,
    history_id: int,
    plugin_id: int,
    scan_hosts: list[dict],
    host_cache: dict[tuple[int, int], list[str]],
) -> list[str]:
    """Return cached plugin host mappings for a scan run."""

    cache_key = (history_id, plugin_id)
    if cache_key not in host_cache:
        try:
            host_cache[cache_key] = _get_plugin_hosts(
                client, scan_id, history_id, plugin_id, scan_hosts
            )
        except requests.RequestException:
            host_cache[cache_key] = []

    return host_cache[cache_key]


def _sort_standard_rows(rows: list[dict]) -> list[dict]:
    """Sort diff rows by severity descending, then plugin name."""

    return sorted(
        rows,
        key=lambda row: (-int(row["severity"]), str(row["name"]).lower()),
    )


def _sort_changed_rows(rows: list[dict]) -> list[dict]:
    """Sort changed rows by newer severity descending, then plugin name."""

    return sorted(
        rows,
        key=lambda row: (-int(row["new_severity"]), str(row["name"]).lower()),
    )


def _count_hosts(hosts: list[str]) -> int:
    """Return the number of unique hosts in a host list."""

    return len(set(hosts))


def _format_severity_change(old_severity: int, new_severity: int) -> str:
    """Render a severity value or change."""

    old_label = SEVERITY_LABELS.get(old_severity, "Unknown")
    new_label = SEVERITY_LABELS.get(new_severity, "Unknown")

    if old_severity == new_severity:
        return new_label

    return f"{old_label} -> {new_label}"


def _format_numeric_change(old_value: int, new_value: int) -> str:
    """Render a numeric value or change with delta."""

    if old_value == new_value:
        return str(new_value)

    return f"{old_value} -> {new_value} ({new_value - old_value:+d})"


def _format_instance_change(old_value: int, new_value: int) -> str:
    """Render an instance-count change with directional colour."""

    value = _format_numeric_change(old_value, new_value)
    if new_value > old_value:
        return f"[red]{value}[/red]"
    if new_value < old_value:
        return f"[green]{value}[/green]"
    return value


def _validate_output_format(output_format: str) -> str:
    """Validate the requested output format."""

    value = str(output_format or "table").strip().lower()
    if value not in {"table", "csv"}:
        console.print("[red]Invalid format.[/red] Use one of: table, csv.")
        raise typer.Exit(code=1)
    return value


def _severity_label(value: int | str | None) -> str:
    """Return a plain severity label."""

    try:
        return SEVERITY_LABELS[int(value)]
    except (KeyError, TypeError, ValueError):
        return "Unknown"


def _build_diff_csv_row(
    *,
    plugin_id: int,
    name: str,
    status: str,
    severity_old: str = "",
    severity_new: str = "",
    count_old: str = "",
    count_new: str = "",
    host_count_old: str = "",
    host_count_new: str = "",
) -> dict[str, str]:
    """Build one CSV row for diff output."""

    return {
        "id": str(plugin_id),
        "name": name,
        "status": status,
        "severity_old": severity_old,
        "severity_new": severity_new,
        "count_old": count_old,
        "count_new": count_new,
        "host_count_old": host_count_old,
        "host_count_new": host_count_new,
    }


def _write_diff_csv(rows: list[dict[str, str]]) -> None:
    """Write diff rows as CSV to stdout."""

    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(
        [
            "id",
            "name",
            "status",
            "severity_old",
            "severity_new",
            "count_old",
            "count_new",
            "host_count_old",
            "host_count_new",
        ]
    )

    for row in rows:
        writer.writerow(
            [
                row["id"],
                row["name"],
                row["status"],
                row["severity_old"],
                row["severity_new"],
                row["count_old"],
                row["count_new"],
                row["host_count_old"],
                row["host_count_new"],
            ]
        )


def _build_plugin_diff_csv_row(
    plugin_id: int,
    compare_finding: dict | None,
    against_finding: dict | None,
    compare_hosts: list[str],
    against_hosts: list[str],
    minimum_severity: int | None,
    host: str | None,
) -> dict[str, str] | None:
    """Build a CSV row for plugin-focused diff output."""

    if compare_finding is None and against_finding is None:
        return None

    relevant_hosts = sorted(set(compare_hosts) | set(against_hosts))
    if host and host not in relevant_hosts:
        return None

    if compare_finding is None:
        severity_new = int(against_finding["severity"])
        if minimum_severity is not None and severity_new < minimum_severity:
            return None

        return _build_diff_csv_row(
            plugin_id=plugin_id,
            name=str(against_finding["plugin_name"]),
            status="new",
            severity_new=_severity_label(severity_new),
            count_new=str(int(against_finding["count"])),
            host_count_new=str(_count_hosts(against_hosts)),
        )

    if against_finding is None:
        severity_old = int(compare_finding["severity"])
        if minimum_severity is not None and severity_old < minimum_severity:
            return None

        return _build_diff_csv_row(
            plugin_id=plugin_id,
            name=str(compare_finding["plugin_name"]),
            status="resolved",
            severity_old=_severity_label(severity_old),
            count_old=str(int(compare_finding["count"])),
            host_count_old=str(_count_hosts(compare_hosts)),
        )

    old_severity = int(compare_finding["severity"])
    new_severity = int(against_finding["severity"])
    old_count = int(compare_finding["count"])
    new_count = int(against_finding["count"])
    old_host_count = _count_hosts(compare_hosts)
    new_host_count = _count_hosts(against_hosts)

    if minimum_severity is not None and new_severity < minimum_severity:
        return None

    if (
        old_severity == new_severity
        and old_count == new_count
        and old_host_count == new_host_count
    ):
        return None

    return _build_diff_csv_row(
        plugin_id=plugin_id,
        name=str(against_finding["plugin_name"] or compare_finding["plugin_name"]),
        status="changed",
        severity_old=_severity_label(old_severity),
        severity_new=_severity_label(new_severity),
        count_old=str(old_count),
        count_new=str(new_count),
        host_count_old=str(old_host_count),
        host_count_new=str(new_host_count),
    )


def _print_diff_header(
    scan_name: str, scan_id: int, compare_id: int, against_id: int, reverse_diff: bool
) -> None:
    """Render the standard diff header."""

    console.print(f"Diff: {scan_name or scan_id}", highlight=False)
    console.print()
    console.print("Comparing:", highlight=False)
    console.print(f"  Compare  : {compare_id}", highlight=False)
    console.print(f"  Against  : {against_id}", highlight=False)

    if reverse_diff:
        console.print()
        console.print(
            "[yellow]Warning: Comparing a newer scan against an older one (reverse diff)[/yellow]"
        )


def _build_standard_table(rows: list[dict]) -> Table:
    """Build a table for new or resolved findings."""

    table = Table(box=box.ROUNDED)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Count", justify="right", no_wrap=True)
    table.add_column("Hosts", style="white")

    for row in rows:
        table.add_row(
            str(row["plugin_id"]),
            str(row["name"]),
            _format_severity(row["severity"]),
            str(row["count"]),
            _format_hosts_display(row["hosts"]),
        )

    return table


def _build_changed_table(rows: list[dict]) -> Table:
    """Build a table for changed findings."""

    table = Table(box=box.ROUNDED)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Instances", justify="right", no_wrap=True)
    table.add_column("Hosts", justify="right", no_wrap=True)

    for row in rows:
        table.add_row(
            str(row["plugin_id"]),
            str(row["name"]),
            _format_severity_change(
                int(row["old_severity"]),
                int(row["new_severity"]),
            ),
            _format_instance_change(
                int(row["old_count"]),
                int(row["new_count"]),
            ),
            _format_numeric_change(
                int(row["old_host_count"]),
                int(row["new_host_count"]),
            ),
        )

    return table


def _render_plugin_diff(
    plugin_id: int,
    compare_finding: dict | None,
    against_finding: dict | None,
    compare_hosts: list[str],
    against_hosts: list[str],
    minimum_severity: int | None,
    host: str | None,
) -> bool:
    """Render a focused diff view for a single plugin."""

    if compare_finding is None and against_finding is None:
        console.print(
            f"[red]Plugin ID '{plugin_id}' not found in either selected scan run.[/red]"
        )
        return True

    relevant_hosts = sorted(set(compare_hosts) | set(against_hosts))
    if host and host not in relevant_hosts:
        return False

    if compare_finding is None:
        status = "New"
        severity_value = int(against_finding["severity"])
        severity_line = None
        instance_line = None
        host_line = None
    elif against_finding is None:
        status = "Resolved"
        severity_value = int(compare_finding["severity"])
        severity_line = None
        instance_line = None
        host_line = None
    else:
        compare_severity = int(compare_finding["severity"])
        against_severity = int(against_finding["severity"])
        compare_count = int(compare_finding["count"])
        against_count = int(against_finding["count"])
        compare_host_count = _count_hosts(compare_hosts)
        against_host_count = _count_hosts(against_hosts)
        severity_value = against_severity
        severity_line = None
        instance_line = None
        host_line = None

        if compare_severity != against_severity:
            severity_line = _format_severity_change(compare_severity, against_severity)

        if compare_count != against_count:
            instance_line = _format_numeric_change(compare_count, against_count)

        if compare_host_count != against_host_count:
            host_line = _format_numeric_change(compare_host_count, against_host_count)

        if severity_line or instance_line or host_line:
            status = "Changed"
        else:
            status = "Unchanged"

    if minimum_severity is not None and severity_value < minimum_severity:
        return False

    name = ""
    if against_finding is not None:
        name = str(against_finding["plugin_name"])
    elif compare_finding is not None:
        name = str(compare_finding["plugin_name"])

    console.print(f"ID        : {plugin_id}", highlight=False)
    console.print(f"Name      : {name}", highlight=False)
    console.print()
    console.print(f"Status    : {status}", highlight=False)

    if severity_line is not None:
        console.print(f"Severity  : {severity_line}", highlight=False)
    if instance_line is not None:
        console.print(
            "Instances : "
            f"{_format_instance_change(compare_count, against_count)}",
            highlight=False,
        )
    if host_line is not None:
        console.print(f"Hosts     : {host_line}", highlight=False)

    return True


def diff_scan(
    compare: str | None = None,
    against: str | None = None,
    host: str | None = None,
    min_severity: str | None = None,
    plugin: int | None = None,
    output_format: str = "table",
) -> None:
    """Compare two scan runs for the active scan context."""

    context = load_context()
    if not context:
        console.print(
            "[red]No active scan context.[/red] "
            "Use 'vulnsight use <scan_name>' first."
        )
        raise typer.Exit(code=1)

    resolved_format = _validate_output_format(output_format)
    minimum_severity = _resolve_minimum_severity(min_severity)
    client = _build_client()
    scan_id = int(context.get("scan_id", 0))
    current_history_id = int(context.get("history_id", 0))
    scan_name = str(context.get("scan_name", ""))

    try:
        scan_details = client.get_scan_details(scan_id)
    except requests.RequestException as exc:
        console.print(f"[red]Failed to retrieve scan history:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    resolved_pair = _resolve_history_pair(
        scan_details, current_history_id, compare, against
    )
    if resolved_pair is None:
        return

    compare_id, against_id, explicit_selection = resolved_pair
    history_lookup = {
        int(entry.get("history_id", 0) or 0): entry
        for entry in scan_details.get("history", [])
        if entry.get("history_id") is not None
    }
    reverse_diff = explicit_selection and _is_reverse_diff(
        compare_id, against_id, history_lookup
    )

    try:
        compare_details = client.get_scan_result_details(scan_id, compare_id)
        against_details = client.get_scan_result_details(scan_id, against_id)
    except requests.RequestException as exc:
        console.print(f"[red]Failed to retrieve diff data:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    compare_scan_hosts = compare_details.get("hosts", [])
    against_scan_hosts = against_details.get("hosts", [])
    available_hosts = sorted(
        set(_get_scan_host_names(compare_scan_hosts))
        | set(_get_scan_host_names(against_scan_hosts))
    )

    if host is not None:
        host = host.strip()
        if host not in available_hosts:
            console.print(f"[red]Host '{host}' not found in this scan.[/red]")
            console.print("Use 'vulnsight hosts' to list valid hosts.")
            return

    compare_findings = _build_finding_map(compare_details.get("vulnerabilities", []))
    against_findings = _build_finding_map(against_details.get("vulnerabilities", []))

    host_cache: dict[tuple[int, int], list[str]] = {}

    if resolved_format == "table":
        _print_diff_header(scan_name, scan_id, compare_id, against_id, reverse_diff)

        if minimum_severity is not None:
            console.print()
            console.print(
                f"[dim]Note: Showing findings with severity >= "
                f"{SEVERITY_LABELS[minimum_severity]}[/dim]"
            )

    if plugin is not None:
        compare_finding = compare_findings.get(plugin)
        against_finding = against_findings.get(plugin)
        compare_hosts = []
        against_hosts = []

        if compare_finding is not None:
            compare_hosts = _get_cached_plugin_hosts(
                client,
                scan_id,
                compare_id,
                plugin,
                compare_scan_hosts,
                host_cache,
            )
        if against_finding is not None:
            against_hosts = _get_cached_plugin_hosts(
                client,
                scan_id,
                against_id,
                plugin,
                against_scan_hosts,
                host_cache,
            )

        if resolved_format == "csv":
            row = _build_plugin_diff_csv_row(
                plugin,
                compare_finding,
                against_finding,
                compare_hosts,
                against_hosts,
                minimum_severity,
                host,
            )
            _write_diff_csv([] if row is None else [row])
            return

        console.print()
        rendered = _render_plugin_diff(
            plugin,
            compare_finding,
            against_finding,
            compare_hosts,
            against_hosts,
            minimum_severity,
            host,
        )
        if not rendered:
            console.print("[yellow]No differences found between the selected scan runs.[/yellow]")
        return

    new_rows: list[dict] = []
    resolved_rows: list[dict] = []
    changed_rows: list[dict] = []

    compare_plugin_ids = set(compare_findings)
    against_plugin_ids = set(against_findings)

    for plugin_id in against_plugin_ids - compare_plugin_ids:
        finding = against_findings[plugin_id]
        severity = int(finding["severity"])
        if minimum_severity is not None and severity < minimum_severity:
            continue

        plugin_hosts = _get_cached_plugin_hosts(
            client, scan_id, against_id, plugin_id, against_scan_hosts, host_cache
        )
        if host and host not in plugin_hosts:
            continue

        new_rows.append(
            {
                "plugin_id": plugin_id,
                "name": finding["plugin_name"],
                "severity": severity,
                "count": int(finding["count"]),
                "hosts": plugin_hosts,
            }
        )

    for plugin_id in compare_plugin_ids - against_plugin_ids:
        finding = compare_findings[plugin_id]
        severity = int(finding["severity"])
        if minimum_severity is not None and severity < minimum_severity:
            continue

        plugin_hosts = _get_cached_plugin_hosts(
            client, scan_id, compare_id, plugin_id, compare_scan_hosts, host_cache
        )
        if host and host not in plugin_hosts:
            continue

        resolved_rows.append(
            {
                "plugin_id": plugin_id,
                "name": finding["plugin_name"],
                "severity": severity,
                "count": int(finding["count"]),
                "hosts": plugin_hosts,
            }
        )

    for plugin_id in compare_plugin_ids & against_plugin_ids:
        compare_finding = compare_findings[plugin_id]
        against_finding = against_findings[plugin_id]
        old_severity = int(compare_finding["severity"])
        new_severity = int(against_finding["severity"])

        compare_hosts = _get_cached_plugin_hosts(
            client, scan_id, compare_id, plugin_id, compare_scan_hosts, host_cache
        )
        against_hosts = _get_cached_plugin_hosts(
            client, scan_id, against_id, plugin_id, against_scan_hosts, host_cache
        )
        old_count = int(compare_finding["count"])
        new_count = int(against_finding["count"])
        old_host_count = _count_hosts(compare_hosts)
        new_host_count = _count_hosts(against_hosts)

        if (
            old_severity == new_severity
            and old_count == new_count
            and old_host_count == new_host_count
        ):
            continue

        if minimum_severity is not None and new_severity < minimum_severity:
            continue

        combined_hosts = sorted(set(compare_hosts) | set(against_hosts))

        if host and host not in combined_hosts:
            continue

        changed_rows.append(
            {
                "plugin_id": plugin_id,
                "name": against_finding["plugin_name"] or compare_finding["plugin_name"],
                "old_severity": old_severity,
                "new_severity": new_severity,
                "old_count": old_count,
                "new_count": new_count,
                "old_host_count": old_host_count,
                "new_host_count": new_host_count,
            }
        )

    new_rows = _sort_standard_rows(new_rows)
    resolved_rows = _sort_standard_rows(resolved_rows)
    changed_rows = _sort_changed_rows(changed_rows)

    if resolved_format == "csv":
        csv_rows: list[dict[str, str]] = []

        for row in new_rows:
            csv_rows.append(
                _build_diff_csv_row(
                    plugin_id=int(row["plugin_id"]),
                    name=str(row["name"]),
                    status="new",
                    severity_new=_severity_label(row["severity"]),
                    count_new=str(int(row["count"])),
                    host_count_new=str(_count_hosts(row["hosts"])),
                )
            )

        for row in resolved_rows:
            csv_rows.append(
                _build_diff_csv_row(
                    plugin_id=int(row["plugin_id"]),
                    name=str(row["name"]),
                    status="resolved",
                    severity_old=_severity_label(row["severity"]),
                    count_old=str(int(row["count"])),
                    host_count_old=str(_count_hosts(row["hosts"])),
                )
            )

        for row in changed_rows:
            csv_rows.append(
                _build_diff_csv_row(
                    plugin_id=int(row["plugin_id"]),
                    name=str(row["name"]),
                    status="changed",
                    severity_old=_severity_label(row["old_severity"]),
                    severity_new=_severity_label(row["new_severity"]),
                    count_old=str(int(row["old_count"])),
                    count_new=str(int(row["new_count"])),
                    host_count_old=str(int(row["old_host_count"])),
                    host_count_new=str(int(row["new_host_count"])),
                )
            )

        _write_diff_csv(csv_rows)
        return

    if not new_rows and not resolved_rows and not changed_rows:
        console.print()
        console.print("[yellow]No differences found between the selected scan runs.[/yellow]")
        return

    if new_rows:
        console.print()
        console.print("New Findings", highlight=False)
        console.print(_build_standard_table(new_rows))

    if resolved_rows:
        console.print()
        console.print("Resolved Findings", highlight=False)
        console.print(_build_standard_table(resolved_rows))

    if changed_rows:
        console.print()
        console.print("Changed Findings", highlight=False)
        console.print(_build_changed_table(changed_rows))
