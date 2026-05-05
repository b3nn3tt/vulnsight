"""Command for validating the VulnSight runtime environment."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile

import requests
import typer
from rich import box
from rich.console import Console
from rich.table import Table

from vulnsight.client import NessusClient
from vulnsight.commands.report import DEFAULT_TEMPLATE_PATH
from vulnsight.config import ENV_FILE, get_settings
from vulnsight.context import CONTEXT_FILE


console = Console()

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"

STATUS_STYLES = {
    PASS: "green",
    WARN: "yellow",
    FAIL: "red",
}


def _add_check(results: list[dict[str, str]], name: str, status: str, message: str) -> None:
    """Append a doctor check result."""

    results.append({"name": name, "status": status, "message": message})


def _format_status(status: str) -> str:
    """Render a styled doctor status label."""

    style = STATUS_STYLES.get(status, "white")
    return f"[{style}]{status}[/{style}]"


def _run_api_probe(client: NessusClient) -> tuple[str, int | None, str]:
    """Perform a lightweight API probe and return status details."""

    try:
        response = client.session.get(
            f"{client.base_url}/scans",
            timeout=client.timeout,
        )
    except requests.RequestException as exc:
        return FAIL, None, str(exc)

    if response.status_code in (401, 403):
        return PASS, response.status_code, "API reachable but authentication failed."

    if response.ok:
        return PASS, response.status_code, "API reachable."

    return FAIL, response.status_code, f"Unexpected response: HTTP {response.status_code}."


def _check_environment_variables(results: list[dict[str, str]]) -> None:
    """Check required environment variables for Nessus access."""

    missing = [
        name for name in ("ACCESS_KEY", "SECRET_KEY") if not os.getenv(name, "").strip()
    ]
    if missing:
        _add_check(
            results,
            "Environment Variables",
            FAIL,
            f"Missing required values: {', '.join(missing)}. Run `python main.py setup`.",
        )
        return

    configured_url = os.getenv("NESSUS_URL", "").strip()
    if configured_url and ENV_FILE.exists():
        message = "Required values are present in the local .env file."
    elif configured_url:
        message = "Required values are present in the current environment."
    elif ENV_FILE.exists():
        message = "Required values are present. Using the default NESSUS_URL."
    else:
        message = "Required values are present, but no local .env file was found."

    _add_check(results, "Environment Variables", PASS, message)


def _check_context_file(results: list[dict[str, str]]) -> None:
    """Check that the local context file exists and contains valid JSON."""

    if not CONTEXT_FILE.exists():
        _add_check(results, "Context File", WARN, "Context file not found.")
        return

    try:
        json.loads(CONTEXT_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _add_check(results, "Context File", FAIL, f"Invalid JSON: {exc.msg}.")
        return
    except OSError as exc:
        _add_check(results, "Context File", FAIL, str(exc))
        return

    _add_check(results, "Context File", PASS, "Context file is present and valid.")


def _check_output_directory(results: list[dict[str, str]]) -> None:
    """Check that the current working directory is writable for report output."""

    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=Path.cwd(),
            prefix=".vulnsight_doctor_",
            suffix=".tmp",
            delete=False,
        ) as temp_file:
            temp_file.write("ok")
            temp_path = Path(temp_file.name)
    except OSError as exc:
        _add_check(results, "Output Directory", FAIL, str(exc))
        return
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()

    _add_check(results, "Output Directory", PASS, f"Writable: {Path.cwd()}")


def run_doctor() -> None:
    """Run environment and connectivity checks for VulnSight."""

    results: list[dict[str, str]] = []
    settings = get_settings()

    _check_environment_variables(results)

    client = NessusClient(settings)
    api_status, status_code, api_message = _run_api_probe(client)
    _add_check(results, "API Connectivity", api_status, api_message)

    auth_result = next(
        (
            result
            for result in results
            if result["name"] == "Environment Variables"
        ),
        None,
    )
    missing_credentials = auth_result is not None and auth_result["status"] == FAIL

    if status_code in (401, 403):
        auth_message = (
            "API keys were rejected. Configuration may have drifted or access may "
            "have been suspended. Run `python main.py setup --reconfigure`."
        )
        if missing_credentials:
            auth_message = "API keys are missing or invalid. Run `python main.py setup`."
        _add_check(results, "Authentication", FAIL, auth_message)
    elif api_status == PASS:
        _add_check(results, "Authentication", PASS, "API keys accepted.")
    else:
        _add_check(results, "Authentication", WARN, "Authentication could not be validated.")

    pandoc_path = shutil.which("pandoc")
    if pandoc_path:
        _add_check(results, "Pandoc", PASS, f"Found at {pandoc_path}.")
    else:
        _add_check(results, "Pandoc", WARN, "Pandoc is not installed or not on PATH.")

    if DEFAULT_TEMPLATE_PATH.exists():
        _add_check(results, "Report Template", PASS, f"Found at {DEFAULT_TEMPLATE_PATH}.")
    else:
        _add_check(results, "Report Template", WARN, f"Missing: {DEFAULT_TEMPLATE_PATH}.")

    _check_context_file(results)
    _check_output_directory(results)

    table = Table(title="VulnSight Doctor", box=box.ROUNDED)
    table.add_column("Check", style="cyan", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Message", style="white")

    for result in results:
        table.add_row(
            result["name"],
            _format_status(result["status"]),
            result["message"],
        )

    pass_count = sum(1 for result in results if result["status"] == PASS)
    warn_count = sum(1 for result in results if result["status"] == WARN)
    fail_count = sum(1 for result in results if result["status"] == FAIL)

    console.print(table)
    console.print()
    console.print(
        f"Summary: PASS={pass_count}  WARN={warn_count}  FAIL={fail_count}",
        highlight=False,
    )

    if settings.verify_ssl is False:
        console.print(
            "[dim]Info: SSL certificate verification is disabled (verify=False).[/dim]"
        )

    if fail_count:
        raise typer.Exit(code=1)
