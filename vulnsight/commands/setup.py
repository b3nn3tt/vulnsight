"""Command for configuring the local VulnSight environment."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import requests
import typer
from rich.console import Console

from vulnsight.client import NessusClient
from vulnsight.config import ENV_FILE, Settings, get_settings, save_settings


console = Console()
DEFAULT_NESSUS_PORT = 8834


def _validate_port(port: int) -> int:
    """Validate a Nessus port value."""

    if 1 <= port <= 65535:
        return port

    console.print("[red]Port must be between 1 and 65535.[/red]")
    raise typer.Exit(code=1)


def _parse_host_input(value: str) -> tuple[str, int]:
    """Normalise a host input into a host and port."""

    raw_value = value.strip()
    if not raw_value:
        console.print("[red]A Nessus host or IP is required.[/red]")
        raise typer.Exit(code=1)

    if raw_value.startswith(("http://", "https://")):
        parsed = urlparse(raw_value)
        host = (parsed.hostname or "").strip()
        port = _validate_port(parsed.port or DEFAULT_NESSUS_PORT)
        if not host:
            console.print("[red]Invalid Nessus URL.[/red]")
            raise typer.Exit(code=1)
        return host, port

    if raw_value.startswith("[") and "]" in raw_value:
        host_part, _, port_part = raw_value.partition("]")
        host = host_part[1:].strip()
        if not host:
            console.print("[red]Invalid Nessus host.[/red]")
            raise typer.Exit(code=1)

        if port_part.startswith(":") and port_part[1:].isdigit():
            return host, _validate_port(int(port_part[1:]))

        return host, DEFAULT_NESSUS_PORT

    if raw_value.count(":") == 1:
        host, port_text = raw_value.rsplit(":", 1)
        if port_text.isdigit():
            host = host.strip()
            if not host:
                console.print("[red]Invalid Nessus host.[/red]")
                raise typer.Exit(code=1)
            return host, _validate_port(int(port_text))

    return raw_value, DEFAULT_NESSUS_PORT


def _looks_like_invalid_ip(host: str) -> bool:
    """Return True when host text resembles an invalid IP address."""

    if not host:
        return False

    allowed = {".", ":"}
    return all(character.isdigit() or character in allowed for character in host)


def _format_host_for_url(host: str) -> str:
    """Format a host for URL output, including IPv6 bracket handling."""

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host

    if isinstance(ip, ipaddress.IPv6Address):
        return f"[{host}]"

    return host


def _validate_and_resolve_host(host: str) -> str:
    """Validate an input host and confirm it resolves before connecting."""

    try:
        ipaddress.ip_address(host)
    except ValueError:
        if _looks_like_invalid_ip(host):
            console.print(f"[red]'{host}' is not a valid IP address.[/red]")
            raise typer.Exit(code=1)

        with console.status(f"Resolving hostname '{host}'...", spinner="dots"):
            try:
                address_info = socket.getaddrinfo(host, None)
            except socket.gaierror:
                console.print(f"[red]Hostname '{host}' could not be resolved.[/red]")
                raise typer.Exit(code=1) from None

        resolved_addresses = sorted(
            {
                entry[4][0]
                for entry in address_info
                if entry[4] and entry[4][0]
            }
        )
        if not resolved_addresses:
            console.print(f"[red]Hostname '{host}' resolved without any usable addresses.[/red]")
            raise typer.Exit(code=1)

        console.print(
            f"[green]Hostname resolved:[/green] {host} -> {', '.join(resolved_addresses[:3])}"
        )
        return host

    console.print(f"[green]IP address validated:[/green] {host}")
    return host


def _build_base_url(host: str, port: int) -> str:
    """Build the Nessus base URL from a host and port."""

    return f"https://{_format_host_for_url(host)}:{port}".rstrip("/")


def _probe_base_url(base_url: str) -> tuple[bool, str]:
    """Check whether the Nessus endpoint is reachable."""

    with console.status(f"Attempting connection to {base_url}...", spinner="dots"):
        try:
            response = requests.get(f"{base_url}/scans", timeout=(5, 10), verify=False)
        except requests.RequestException as exc:
            return False, str(exc)

    return True, f"Nessus responded on {base_url} (HTTP {response.status_code})."


def _resolve_base_url() -> str:
    """Prompt for a reachable Nessus base URL."""

    host_input = typer.prompt("Nessus host or IP")
    host, port = _parse_host_input(host_input)
    host = _validate_and_resolve_host(host)

    while True:
        base_url = _build_base_url(host, port)
        reachable, message = _probe_base_url(base_url)
        if reachable:
            console.print(f"[green]{message}[/green]")
            return base_url

        console.print(f"[yellow]Unable to reach Nessus at {base_url}.[/yellow]")
        console.print(message)

        if typer.confirm("Is Nessus running on a different port?", default=False):
            port = typer.prompt("Nessus port", default=str(port))
            try:
                port = _validate_port(int(port))
            except ValueError:
                console.print("[red]Port must be a number.[/red]")
                raise typer.Exit(code=1)
            continue

        console.print(
            "[red]Nessus could not be reached.[/red] "
            "Check the target host, port, service state, and any intermediary firewalls."
        )
        raise typer.Exit(code=1)


def _validate_credentials(
    base_url: str, access_key: str, secret_key: str
) -> tuple[str, str]:
    """Validate Nessus API keys against the selected base URL."""

    settings = Settings(
        base_url=base_url,
        access_key=access_key.strip(),
        secret_key=secret_key.strip(),
        verify_ssl=False,
    )
    client = NessusClient(settings)

    with console.status("Validating API credentials with Nessus...", spinner="dots"):
        try:
            scan_count = client.check_connection()
        except requests.HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else None
            if status_code in (401, 403):
                return (
                    "denied",
                    "Access was denied. The saved details may have drifted, the keys may be "
                    "incorrect, or your Nessus access may have been suspended.",
                )
            return (
                "error",
                f"Nessus returned HTTP {status_code or 'unknown'} while validating credentials.",
            )
        except requests.RequestException as exc:
            return ("error", str(exc))

    return ("ok", f"Authenticated successfully. {scan_count} scan(s) visible.")


def _prompt_for_credentials(base_url: str) -> tuple[str, str]:
    """Prompt until valid Nessus API credentials are provided or the user exits."""

    while True:
        access_key = typer.prompt("Access key", hide_input=True).strip()
        secret_key = typer.prompt("Secret key", hide_input=True).strip()

        if not access_key or not secret_key:
            console.print("[red]Both the access key and secret key are required.[/red]")
            if not typer.confirm("Try entering the Nessus API keys again?", default=True):
                raise typer.Exit(code=1)
            continue

        status, message = _validate_credentials(base_url, access_key, secret_key)
        if status == "ok":
            console.print(f"[green]{message}[/green]")
            return access_key, secret_key

        if status == "denied":
            console.print(f"[yellow]{message}[/yellow]")
        else:
            console.print(f"[red]{message}[/red]")

        if not typer.confirm("Would you like to enter different API keys?", default=True):
            raise typer.Exit(code=1)


def run_setup(reconfigure: bool = False) -> None:
    """Interactively configure or reconfigure the local Nessus settings."""

    settings = get_settings()
    config_present = ENV_FILE.exists() or bool(settings.access_key and settings.secret_key)

    if config_present and not reconfigure:
        console.print("[yellow]Existing VulnSight configuration detected.[/yellow]")
        if not typer.confirm("Would you like to reconfigure it now?", default=True):
            console.print("No changes made.")
            return

    base_url = _resolve_base_url()
    access_key, secret_key = _prompt_for_credentials(base_url)
    save_settings(base_url, access_key, secret_key)

    console.print()
    console.print("[green]VulnSight configuration saved.[/green]")
    console.print(f"Nessus URL : {base_url}")
    console.print(f"Config File: {ENV_FILE}")
