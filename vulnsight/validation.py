"""Helpers for storing analyst validation overlays."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from typing import Any

from vulnsight.config import get_validation_dir


VALIDATION_DIR = get_validation_dir()
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


# Per-process cache of parsed validation payloads keyed by scan ID. Read-heavy
# aggregations (reports, global views) call get_validation() once per finding;
# without this they would re-read and re-parse the same file thousands of times.
_VALIDATION_CACHE: dict[int, dict[str, Any]] = {}


class ValidationStorageError(Exception):
    """Raised when the configured validation storage cannot be reached."""


def _is_shared_storage() -> bool:
    """Return True when validation storage points at a configured shared path."""

    return bool(os.getenv("VULNSIGHT_VALIDATION_DIR", "").strip())


def _storage_unreachable_message() -> str:
    """Return a clear, actionable message for unreachable validation storage."""

    if _is_shared_storage():
        return (
            f"Shared validation directory is unreachable:\n  {VALIDATION_DIR}\n"
            "Validation cannot be read or saved right now. Check that the share "
            "is online and you have access, or run 'setup' to switch back to "
            "local storage."
        )
    return (
        f"Validation storage is not accessible:\n  {VALIDATION_DIR}\n"
        "Check the directory permissions and available disk space."
    )


def _ensure_storage_reachable() -> None:
    """Fail loudly when a configured shared validation directory is unreachable.

    Local (default) storage is created on demand, so its absence is fine. A
    configured shared path that cannot be reached is treated as an error rather
    than silently falling back to local — silent fallback would fragment a
    team's overlay and orphan writes made during the outage.
    """

    if not _is_shared_storage():
        return

    try:
        # Walk up until an existing ancestor is found. If any is reachable the
        # share is online and missing subdirectories can be created.
        for candidate in (VALIDATION_DIR, *VALIDATION_DIR.parents):
            if candidate.exists():
                return
    except OSError as exc:
        raise ValidationStorageError(_storage_unreachable_message()) from exc

    raise ValidationStorageError(_storage_unreachable_message())


def _get_validation_path(scan_id: int) -> Path:
    """Return the validation file path for a scan."""

    return VALIDATION_DIR / f"{scan_id}.json"


def _read_scan_validation_from_disk(scan_id: int) -> dict[str, Any]:
    """Read a scan's validation payload directly from disk, refreshing the cache.

    Writes use this rather than the cache so that, on shared storage, a change
    merges into the latest on-disk state instead of a stale per-process copy.
    """

    _ensure_storage_reachable()

    validation_path = _get_validation_path(scan_id)
    try:
        if validation_path.exists():
            payload: dict[str, Any] = json.loads(
                validation_path.read_text(encoding="utf-8")
            )
        else:
            payload = {}
    except OSError as exc:
        raise ValidationStorageError(_storage_unreachable_message()) from exc

    _VALIDATION_CACHE[scan_id] = payload
    return payload


def _load_scan_validation(scan_id: int) -> dict[str, Any]:
    """Load the validation payload for a scan, caching the result per process."""

    if scan_id in _VALIDATION_CACHE:
        return _VALIDATION_CACHE[scan_id]

    return _read_scan_validation_from_disk(scan_id)


def _save_scan_validation(scan_id: int, payload: dict[str, Any]) -> None:
    """Write a scan's validation payload atomically and refresh the cache."""

    _ensure_storage_reachable()

    try:
        VALIDATION_DIR.mkdir(parents=True, exist_ok=True)
        validation_path = _get_validation_path(scan_id)

        # Stage to a unique temp file in the same directory, then atomically
        # replace the target. This avoids torn reads and lets concurrent writers
        # on a shared drive each stage their own temp file without colliding.
        fd, tmp_name = tempfile.mkstemp(dir=str(VALIDATION_DIR), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
                tmp_file.write(json.dumps(payload, indent=2))
            os.replace(tmp_name, validation_path)
        except BaseException:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
            raise
    except OSError as exc:
        raise ValidationStorageError(_storage_unreachable_message()) from exc

    _VALIDATION_CACHE[scan_id] = payload


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
    # Read the latest on-disk state (not the cache) so a write merges into any
    # changes other users have made to the same scan on shared storage.
    payload = _read_scan_validation_from_disk(scan_id)

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
            _VALIDATION_CACHE.pop(scan_id, None)
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
