"""Static CLI presets for VulnSight commands."""

from __future__ import annotations

import typer
from rich.console import Console


console = Console()

PRESETS = {
    "management": {
        "min_severity": "high",
        "format": "docx",
        "toc": True
    },
    "technical": {
        "min_severity": "low",
        "format": "docx",
        "toc": True
    },
    "high-risk": {
        "min_severity": "high"
    }
}


def apply_preset(preset_name: str, args: dict) -> dict:
    """Apply a named preset to missing argument values only."""

    resolved_name = preset_name.strip().lower()
    preset = PRESETS.get(resolved_name)
    if preset is None:
        console.print(f"[red]Unknown preset:[/red] {preset_name}")
        console.print(
            "Available presets: "
            f"{', '.join(sorted(PRESETS))}"
        )
        raise typer.Exit(code=1)

    resolved_args = dict(args)
    for key, value in preset.items():
        if key in resolved_args and resolved_args[key] is None:
            resolved_args[key] = value

    return resolved_args
