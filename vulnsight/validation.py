"""Helpers for storing analyst validation overlays."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any


VALIDATION_DIR = Path(__file__).resolve().parent.parent / ".vulnsight" / "validation"
VALIDATION_DISPLAY = {
    "confirmed": "Confirmed",
    "false_positive": "False Positive",
    "unreviewed": "Unreviewed",
}
VALIDATION_ALIASES = {
    "confirmed": "confirmed",
    "false_positive": "false_positive",
    "false_positives": "false_positive",
    "unreviewed": "unreviewed",
}


def _get_validation_path(scan_id: int) -> Path:
    """Return the validation file path for a scan."""

    return VALIDATION_DIR / f"{scan_id}.json"


def _load_scan_validation(scan_id: int) -> dict[str, Any]:
    """Load the validation payload for a scan if it exists."""

    validation_path = _get_validation_path(scan_id)
    if not validation_path.exists():
        return {}

    return json.loads(validation_path.read_text(encoding="utf-8"))


def _save_scan_validation(scan_id: int, payload: dict[str, Any]) -> None:
    """Write the validation payload for a scan."""

    VALIDATION_DIR.mkdir(parents=True, exist_ok=True)
    validation_path = _get_validation_path(scan_id)
    validation_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _normalise_status_value(status: str | None) -> str:
    """Normalise a validation status into its stored form."""

    value = str(status or "").strip().lower().replace("-", "_").replace(" ", "_")
    resolved_value = VALIDATION_ALIASES.get(value)
    if resolved_value in VALIDATION_DISPLAY:
        return resolved_value
    raise ValueError("Invalid validation status.")


def parse_validation_status(status: str | None, *, required: bool = False) -> str | None:
    """Parse a validation status from CLI input."""

    if status is None:
        if required:
            raise ValueError("Validation status is required.")
        return None

    return _normalise_status_value(status)


def get_validation_display(status: str) -> str:
    """Return the display label for a validation status."""

    return VALIDATION_DISPLAY.get(status, VALIDATION_DISPLAY["unreviewed"])


def load_validation(scan_id: int, history_id: int) -> dict[str, dict[str, Any]]:
    """Load stored validations for one scan history."""

    payload = _load_scan_validation(scan_id)
    history = payload.get("history", {})
    history_entry = history.get(str(history_id), {})
    findings = history_entry.get("findings", {})
    if not isinstance(findings, dict):
        return {}
    return findings


def get_validation(scan_id: int, history_id: int, finding_id: int) -> dict[str, str]:
    """Return the effective validation record for one finding."""

    findings = load_validation(scan_id, history_id)
    record = findings.get(str(finding_id), {})

    try:
        status = _normalise_status_value(record.get("status"))
    except ValueError:
        status = "unreviewed"

    return {
        "status": status,
        "notes": str(record.get("notes") or ""),
        "validated_at": str(record.get("validated_at") or ""),
    }


def _cleanup_empty_validation(payload: dict[str, Any], history_id: int) -> dict[str, Any]:
    """Remove empty validation containers after a delete operation."""

    history = payload.get("history", {})
    history_entry = history.get(str(history_id), {})
    findings = history_entry.get("findings", {})

    if isinstance(findings, dict) and not findings:
        history.pop(str(history_id), None)

    return payload


def _get_timestamp() -> str:
    """Return a UTC timestamp in ISO format."""

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_validation(
    scan_id: int,
    scan_name: str,
    history_id: int,
    finding_id: int,
    status: str,
    notes: str | None = None,
) -> None:
    """Write or clear a validation record for one finding."""

    resolved_status = _normalise_status_value(status)
    payload = _load_scan_validation(scan_id)

    if resolved_status == "unreviewed":
        if not payload:
            return

        history = payload.get("history", {})
        history_entry = history.get(str(history_id), {})
        findings = history_entry.get("findings", {})
        if isinstance(findings, dict):
            findings.pop(str(finding_id), None)

        payload = _cleanup_empty_validation(payload, history_id)
        if not payload.get("history"):
            validation_path = _get_validation_path(scan_id)
            if validation_path.exists():
                validation_path.unlink()
            return

        _save_scan_validation(scan_id, payload)
        return

    if not payload:
        payload = {
            "scan_id": scan_id,
            "scan_name": scan_name,
            "history": {},
        }

    payload["scan_id"] = scan_id
    payload["scan_name"] = scan_name

    history = payload.setdefault("history", {})
    history_entry = history.setdefault(str(history_id), {"findings": {}})
    findings = history_entry.setdefault("findings", {})
    findings[str(finding_id)] = {
        "status": resolved_status,
        "notes": str(notes or ""),
        "validated_at": _get_timestamp(),
    }

    _save_scan_validation(scan_id, payload)
