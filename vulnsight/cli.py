"""Typer application entry point for VulnSight."""

from __future__ import annotations

import importlib

import click
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


class AlphabeticalTyperGroup(typer.core.TyperGroup):
    """Render help command lists alphabetically."""

    def list_commands(self, ctx: click.Context) -> list[str]:
        """Return command names sorted for predictable help output."""

        return sorted(self.commands)


app = typer.Typer(
    cls=AlphabeticalTyperGroup,
    help=(
        "VulnSight CLI for Nessus scan triage, validation, comparison, "
        "and report export."
    ),
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
def scans(
    details: bool = typer.Option(
        False,
        "--details",
        help="Also fetch slower per-scan run counts and credential status.",
    ),
) -> None:
    """List Nessus scans visible to the configured API keys."""

    list_scans(details)


@app.command("ping")
def ping_command() -> None:
    """Test basic Nessus connectivity."""

    ping()


@app.command("scan", no_args_is_help=True)
def scan_command(
    name: str = typer.Argument(
        ...,
        help="Exact scan name to resolve.",
    ),
) -> None:
    """Resolve an exact scan name and print its Nessus scan ID."""

    get_scan(name)


@app.command(no_args_is_help=True)
def use(
    scan_name: str | None = typer.Argument(
        None,
        help="Scan name to select. You may use this, --name, or --id.",
    ),
    name: str | None = typer.Option(
        None,
        "--name",
        help="Scan name to select.",
    ),
    scan_id: int | None = typer.Option(
        None,
        "--id",
        help="Scan ID to select.",
    ),
) -> None:
    """Select a scan and store its latest completed run as local context."""

    use_scan(scan_name, name, scan_id)


@app.command()
def current() -> None:
    """Show the active scan ID, history ID, and scan name."""

    show_current()


@app.command()
def status() -> None:
    """Show current context, environment checks, and suggested next actions."""

    show_status()


@app.command()
def doctor() -> None:
    """Check configuration, Nessus connectivity, Pandoc, and local state."""

    run_doctor()


@app.command("validate", no_args_is_help=True)
def validate_command(
    ctx: typer.Context,
    plugin_id: int = typer.Argument(
        ...,
        help="Nessus plugin ID to validate in the active scan run.",
    ),
    status: str | None = typer.Option(
        None,
        "--status",
        help="Required. Validation status: confirmed, false_positive, or unreviewed.",
    ),
    note: str | None = typer.Option(
        None,
        "--note",
        help="Optional analyst note stored with the validation record.",
    ),
) -> None:
    """Store validation state for a finding in the current scan run."""

    if status is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(code=2)

    run_validate(plugin_id, status, note)


@app.command("validation")
def validation_command(
    status: str | None = typer.Option(
        None,
        "--status",
        help="Filter by validation status: confirmed, false_positive, or unreviewed.",
    ),
) -> None:
    """Show validation state for findings in the current scan run."""

    show_validation(status)


@app.command()
def setup(
    reconfigure: bool = typer.Option(
        False,
        "--reconfigure",
        help="Overwrite an existing .env configuration.",
    ),
) -> None:
    """Create or update local Nessus API connection settings."""

    run_setup(reconfigure)


@app.command()
def history() -> None:
    """Show available scan runs for the active scan."""

    show_history()


@app.command()
def diff(
    compare: str | None = typer.Option(
        None,
        "--compare",
        help="Baseline history ID. Must be used with --against.",
    ),
    against: str | None = typer.Option(
        None,
        "--against",
        help="Target history ID. Must be used with --compare.",
    ),
    host: str | None = typer.Option(
        None,
        "--host",
        "-h",
        help="Only include diff rows affecting this host.",
    ),
    min_severity: str | None = typer.Option(
        None,
        "--min-severity",
        help="Minimum severity: info, low, medium, high, or critical.",
    ),
    plugin: int | None = typer.Option(
        None,
        "--plugin",
        help="Limit diff output to one plugin ID.",
    ),
    preset: str | None = typer.Option(
        None,
        "--preset",
        help="Apply preset defaults: management, technical, or high-risk.",
    ),
    format: str = typer.Option(
        "table",
        "--format",
        help="Output format: table or csv.",
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
    severity: str | None = typer.Option(
        None,
        "--severity",
        "-s",
        help="Only include one severity: info, low, medium, high, or critical.",
    ),
    host: str | None = typer.Option(
        None,
        "--host",
        "-h",
        help="Only include findings affecting this host.",
    ),
    min_severity: str | None = typer.Option(
        None,
        "--min-severity",
        help="Minimum severity: info, low, medium, high, or critical.",
    ),
    validation: str | None = typer.Option(
        None,
        "--validation",
        "--only",
        help="Only include validation status: confirmed, false_positive, or unreviewed.",
    ),
    exclude_validation: str | None = typer.Option(
        None,
        "--exclude",
        help="Exclude validation status: confirmed, false_positive, or unreviewed.",
    ),
    exclude_false_positives: bool = typer.Option(
        False,
        "--exclude-false-positives",
        help="Exclude findings marked as False Positive.",
    ),
    preset: str | None = typer.Option(
        None,
        "--preset",
        help="Apply preset defaults: management, technical, or high-risk.",
    ),
    recommendations: bool = typer.Option(
        False,
        "--recommendations",
        "--remediation",
        help="Show recommendation-focused output instead of the findings table.",
    ),
    format: str = typer.Option(
        "table",
        "--format",
        help="Output format: table or csv. CSV is written to stdout.",
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
    """Show hosts and best-effort operating systems for the active scan run."""

    list_hosts()


@app.command()
def summary(
    host: list[str] | None = typer.Option(
        None,
        "--host",
        "-h",
        help="Include only these hosts. Repeat the option for multiple hosts.",
    ),
    exclude_host: list[str] | None = typer.Option(
        None,
        "--exclude-host",
        help="Exclude these hosts. Repeat the option for multiple hosts.",
    ),
    min_severity: str | None = typer.Option(
        None,
        "--min-severity",
        help="Minimum severity: info, low, medium, high, or critical.",
    ),
    preset: str | None = typer.Option(
        None,
        "--preset",
        help="Apply preset defaults: management, technical, or high-risk.",
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


@app.command("use-history", no_args_is_help=True)
def use_history_command(
    history_id: str = typer.Argument(
        ...,
        help="History ID to select for the active scan, or 'latest'.",
    )
) -> None:
    """Select a scan run for the active scan context."""

    use_history(history_id)


@app.command("report")
def generate_report_command(
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
    host: list[str] | None = typer.Option(
        None,
        "--host",
        help="Include only these hosts. Repeat the option for multiple hosts.",
    ),
    exclude_host: list[str] | None = typer.Option(
        None,
        "--exclude-host",
        help="Exclude these hosts. Repeat the option for multiple hosts.",
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
    preset: str | None = typer.Option(
        None,
        "--preset",
        help="Apply preset defaults: management, technical, or high-risk.",
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
    """Generate a filtered report for the current scan context."""

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


@app.command(no_args_is_help=True)
def finding(
    plugin_id: int = typer.Argument(
        ...,
        help="Nessus plugin ID to inspect in the active scan run.",
    ),
    format: str | None = typer.Option(
        None,
        "--format",
        "-f",
        help="Output format: cli, markdown, md, json, or debug. Defaults to cli.",
    ),
    recommendations: bool = typer.Option(
        False,
        "--recommendations",
        "--remediation",
        help="Show recommendation-focused output for this finding.",
    ),
) -> None:
    """Show detailed information for a finding in the current scan context."""

    get_finding(plugin_id, format, recommendations)
