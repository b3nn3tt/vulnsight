"""Executable entry point for the VulnSight CLI."""

from __future__ import annotations

import sys

import click
import typer
from rich.console import Console

from vulnsight.cli import app, print_unexpected_input_help
from vulnsight.validation import ValidationStorageError


console = Console()

# Finite-value options whose error messages should enumerate the valid values,
# so a missing or bad value tells the user their choices without a help lookup.
OPTION_VALUE_HINTS = {
    "--severity": "info, low, medium, high, critical",
    "-s": "info, low, medium, high, critical",
    "--min-severity": "info, low, medium, high, critical",
    "--status": "confirmed, false_positive, unreviewed",
    "--validation": "confirmed, false_positive, unreviewed",
    "--only": "confirmed, false_positive, unreviewed",
    "--exclude": "confirmed, false_positive, unreviewed",
    "--top-risks": "severity, volume, weighted",
    "--sort": "asc, desc",
}


KNOWN_COMMANDS = {
    "current",
    "doctor",
    "diff",
    "finding",
    "findings",
    "global",
    "history",
    "hosts",
    "ping",
    "report",
    "scan",
    "scans",
    "setup",
    "status",
    "summary",
    "use",
    "use-history",
    "validate",
    "validation",
}
HELP_FLAGS = {"-h", "--help"}


def _handle_unexpected_root_input() -> None:
    """Catch common CLI mistakes before handing off to Typer."""

    args = sys.argv[1:]
    if not args:
        return

    first_arg = args[0]
    if first_arg in KNOWN_COMMANDS or first_arg in HELP_FLAGS:
        return

    if first_arg.startswith("-"):
        return

    print_unexpected_input_help(first_arg)
    raise SystemExit(2)


def _value_hint_for_usage_error(exc: click.UsageError) -> str | None:
    """Return a 'valid values' hint when a finite-value option is at fault."""

    option = getattr(exc, "option_name", None)
    if option and option in OPTION_VALUE_HINTS:
        return f"Valid values for {option}: {OPTION_VALUE_HINTS[option]}"

    message = exc.format_message()
    for flag, values in OPTION_VALUE_HINTS.items():
        if f"'{flag}'" in message:
            return f"Valid values for {flag}: {values}"
    return None


def _render_click_error(exc: click.ClickException) -> None:
    """Render a Click error using Typer's rich formatting where available."""

    try:
        from typer import rich_utils

        rich_utils.rich_format_error(exc)
    except Exception:
        exc.show()


if __name__ == "__main__":
    _handle_unexpected_root_input()
    command = typer.main.get_command(app)
    try:
        command(standalone_mode=False)
    except click.UsageError as exc:
        hint = _value_hint_for_usage_error(exc)
        if hint:
            exc.message = f"{exc.message}\n\n{hint}"
        _render_click_error(exc)
        raise SystemExit(2 if exc.exit_code is None else exc.exit_code)
    except click.ClickException as exc:
        _render_click_error(exc)
        raise SystemExit(exc.exit_code)
    except click.exceptions.Abort:
        console.print("Aborted!")
        raise SystemExit(1)
    except click.exceptions.Exit as exc:
        raise SystemExit(exc.exit_code)
    except ValidationStorageError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise SystemExit(1)
