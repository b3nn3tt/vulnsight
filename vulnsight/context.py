"""Helpers for storing and loading local VulnSight context."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


CONTEXT_FILE = Path(__file__).resolve().parent.parent / ".vulnsight_context.json"


def save_context(scan_id: int, history_id: int, scan_name: str) -> None:
    """Save the active scan context to the project root."""

    payload = {
        "scan_id": scan_id,
        "history_id": history_id,
        "scan_name": scan_name,
    }
    CONTEXT_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_context() -> dict[str, Any]:
    """Load the active scan context from the project root."""

    if not CONTEXT_FILE.exists():
        return {}

    return json.loads(CONTEXT_FILE.read_text(encoding="utf-8"))
