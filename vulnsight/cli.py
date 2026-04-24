"""Typer application entry point for VulnSight."""

from __future__ import annotations

import importlib

import typer
from rich.console import Console

from vulnsight.commands.current import show_current
from vulnsight.commands.doctor import run_doctor
from vulnsight.commands.diff import diff_scan
from vulnsight.commands.finding import get_finding
from vulnsight.commands.findings import list_findings
from vulnsight.commands.history import show_history
from vulnsight.commands.hosts import list_hosts
from vulnsight.commands.report import generate_report
from vulnsight.commands.scans import get_scan, list_scans, ping
from vulnsight.commands.setup import run_setup
from vulnsight.commands.status import show_status
from vulnsight.commands.summary import show_summary
from vulnsight.commands.use_history import use_history
from vulnsight.commands.use import use_scan
from vulnsight.commands.validation import run_validate, show_validation
from vulnsight.presets import apply_preset


console = Console()
app = typer.Typer(
    help="VulnSight CLI for simple Nessus scan reporting.",
    no_args_is_help=True,
)
global_module = importlib.import_module("vulnsight.commands.global")
app.add_typer(global_module.global_app, name="global")


def print_unexpected_input_help(unexpected_input: str) -> None:
    """Show a friendly message when input is provided in the wrong place."""

    console.print(f"[red]Unexpected input:[/red] {unexpected_input}")
    console.print('It looks like you may have entered a scan name without a command.')
    console.print(f'Try: [cyan]python .\\main.py scan "{unexpected_input}"[/cyan]')
    console.print("Use [cyan]python .\\main.py --help[/cyan] to see available commands.")


@app.command()
def scans() -> None:
    """List all available scans."""

    list_scans()


@app.command("ping")
def ping_command() -> None:
    """Test basic Nessus connectivity."""

    ping()


@app.command("scan")
def scan_command(name: str = typer.Argument(..., help="Scan name to resolve.")) -> None:
    """Resolve a scan by name and print its ID."""

    get_scan(name)


@app.command()
def use(name: str = typer.Argument(..., help="Scan name to use.")) -> None:
    """Select a scan and store its latest completed run as local context."""

    use_scan(name)


@app.command()
def current() -> None:
    """Show the currently selected scan context."""

    show_current()


@app.command()
def status() -> None:
    """Show a quick operational snapshot for the current CLI context."""

    show_status()


@app.command()
def doctor() -> None:
    """Validate the local runtime environment and Nessus connectivity."""

    run_doctor()


@app.command("validate")
def validate_command(
    plugin_id: int = typer.Argument(..., help="Plugin ID to validate."),
    status: str = typer.Option(
        ...,
        "--status",
        help="Validation status: confirmed, false_positive, or unreviewed.",
    ),
    note: str | None = typer.Option(None, "--note", help="Optional analyst note."),
) -> None:
    """Store validation state for a finding in the current scan run."""

    run_validate(plugin_id, status, note)


@app.command("validation")
def validation_command(
    status: str | None = typer.Option(
        None,
        "--status",
        help="Filter by validation status.",
    ),
) -> None:
    """Show validation state for findings in the current scan run."""

    show_validation(status)


@app.command()
def setup(
    reconfigure: bool = typer.Option(
        False,
        "--reconfigure",
        help="Overwrite an existing VulnSight configuration.",
    ),
) -> None:
    """Configure or reconfigure the Nessus connection settings."""

    run_setup(reconfigure)


@app.command()
def history() -> None:
    """Show history entries for the current scan."""

    show_history()


@app.command()
def diff(
    compare: str | None = typer.Option(None, "--compare", help="Baseline history ID."),
    against: str | None = typer.Option(None, "--against", help="Target history ID."),
    host: str | None = typer.Option(None, "--host", "-h", help="Filter diff results to a specific host."),
    min_severity: str | None = typer.Option(None, "--min-severity", help="Minimum severity to include."),
    plugin: int | None = typer.Option(None, "--plugin", help="Limit diff output to a single plugin ID."),
    preset: str | None = typer.Option(None, "--preset", help="Apply preset configuration"),
    format: str = typer.Option(
        "table",
        "--format",
        help="Output format: table or csv",
    ),
) -> None:
    """Compare two scan runs for the current scan context."""

    args = {
        "compare": compare,
        "against": against,
        "host": host,
        "min_severity": min_severity,
        "plugin": plugin,
    }
    if preset:
        args = apply_preset(preset, args)

    compare = args["compare"]
    against = args["against"]
    host = args["host"]
    min_severity = args["min_severity"]
    plugin = args["plugin"]

    diff_scan(compare, against, host, min_severity, plugin, format)


@app.command()
def findings(
    severity: str | None = typer.Option(None, "--severity", "-s", help="Only display this exact severity."),
    host: str | None = typer.Option(None, "--host", "-h", help="Filter findings to a specific host."),
    min_severity: str | None = typer.Option(None, "--min-severity", help="Minimum severity to display."),
    validation: str | None = typer.Option(
        None,
        "--validation",
        "--only",
        help="Only include findings with this validation status.",
    ),
    exclude_validation: str | None = typer.Option(
        None,
        "--exclude",
        help="Exclude findings with this validation status.",
    ),
    exclude_false_positives: bool = typer.Option(
        False,
        "--exclude-false-positives",
        help="Exclude findings marked as False Positive.",
    ),
    preset: str | None = typer.Option(None, "--preset", help="Apply preset configuration"),
    recommendations: bool = typer.Option(
        False,
        "--recommendations",
        "--remediation",
        help="Show recommendation-focused output.",
    ),
    format: str = typer.Option(
        "table",
        "--format",
        help="Output format: table or csv",
    ),
) -> None:
    """Show aggregated findings for the current scan context."""

    args = {
        "severity": severity,
        "host": host,
        "min_severity": min_severity,
    }
    if preset:
        args = apply_preset(preset, args)

    severity = args["severity"]
    host = args["host"]
    min_severity = args["min_severity"]

    list_findings(
        severity,
        host,
        min_severity,
        recommendations,
        format,
        validation,
        exclude_validation,
        exclude_false_positives,
    )


@app.command()
def hosts() -> None:
    """Show hosts in the current scan context."""

    list_hosts()


@app.command()
def summary(
    host: list[str] | None = typer.Option(None, "--host", "-h", help="Include only these hosts."),
    exclude_host: list[str] | None = typer.Option(None, "--exclude-host", help="Exclude these hosts."),
    min_severity: str | None = typer.Option(None, "--min-severity", help="Minimum severity to include."),
    preset: str | None = typer.Option(None, "--preset", help="Apply preset configuration"),
    top_risks: str | None = typer.Option(
        None,
        "--top-risks",
        help="Top risks mode: severity, volume, or weighted. Weighted is the default recommended ranking mode.",
    ),
    sort: str = typer.Option(
        "desc", "--sort", help="Sort direction for Top Risks: asc or desc."
    ),
    limit: int = typer.Option(
        10, "--limit", help="Number of Top Risks rows to display."
    ),
) -> None:
    """Show a severity summary for the current scan context."""

    args = {
        "host": host,
        "exclude_host": exclude_host,
        "min_severity": min_severity,
        "top_risks": top_risks,
        "sort": sort,
        "limit": limit,
    }
    if preset:
        args = apply_preset(preset, args)

    host = args["host"]
    exclude_host = args["exclude_host"]
    min_severity = args["min_severity"]
    top_risks = args["top_risks"]
    sort = args["sort"]
    limit = args["limit"]

    show_summary(host, exclude_host, min_severity, top_risks, sort, limit)


@app.command("use-history")
def use_history_command(
    history_id: str = typer.Argument(..., help="History ID to use, or 'latest'.")
) -> None:
    """Select a specific scan run for the current scan."""

    use_history(history_id)


@app.command("report")
def generate_report_command(
    format: str | None = typer.Option(
        None,
        "--format",
        help="Output format: docx or pdf. Defaults to docx.",
    ),
    min_severity: str | None = typer.Option(None, "--min-severity", help="Minimum severity to include."),
    severity: str | None = typer.Option(None, "--severity", help="Only include this exact severity."),
    host: list[str] | None = typer.Option(None, "--host", help="Include only these hosts."),
    exclude_host: list[str] | None = typer.Option(None, "--exclude-host", help="Exclude these hosts."),
    only: str | None = typer.Option(
        None,
        "--only",
        help="Only include findings with this validation status.",
    ),
    exclude: str | None = typer.Option(
        None,
        "--exclude",
        help="Exclude findings with this validation status.",
    ),
    preset: str | None = typer.Option(None, "--preset", help="Apply preset configuration"),
    output: str | None = typer.Option(
        None,
        "--output",
        help="Output file path. Defaults to an auto-generated filename.",
    ),
    toc: bool = typer.Option(
        False,
        "--toc",
        help="Include a table of contents (docx only).",
    ),
) -> None:
    """Generate a filtered DOCX or PDF report for the current scan context."""

    args = {
        "format": format,
        "min_severity": min_severity,
        "severity": severity,
        "host": host,
        "exclude_host": exclude_host,
        "output": output,
        "toc": True if toc else None,
    }
    if preset:
        args = apply_preset(preset, args)

    format = args["format"]
    min_severity = args["min_severity"]
    severity = args["severity"]
    host = args["host"]
    exclude_host = args["exclude_host"]
    output = args["output"]
    toc = bool(args["toc"])

    generate_report(
        min_severity,
        severity,
        host,
        exclude_host,
        format,
        output,
        toc,
        only,
        exclude,
    )


@app.command()
def finding(
    plugin_id: int = typer.Argument(..., help="Plugin ID to inspect."),
    format: str | None = typer.Option(None, "--format", "-f", help="Output format."),
    recommendations: bool = typer.Option(
        False,
        "--recommendations",
        "--remediation",
        help="Show recommendation-focused output.",
    ),
) -> None:
    """Show detailed information for a finding in the current scan context."""

    get_finding(plugin_id, format, recommendations)
