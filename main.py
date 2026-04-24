"""Executable entry point for the VulnSight CLI."""

from __future__ import annotations

import sys

from vulnsight.cli import app, print_unexpected_input_help


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


if __name__ == "__main__":
    _handle_unexpected_root_input()
    app()
