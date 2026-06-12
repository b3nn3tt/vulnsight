"""Tests for usable run-status handling, including imported scans."""

import pytest

from vulnsight.client import USABLE_RUN_STATUSES
from vulnsight.commands.use import _get_latest_completed_history


def _details(*statuses):
    """Build a scan-details dict with one history entry per status."""

    return {
        "history": [
            {"status": status, "history_id": index + 1, "creation_date": 1000 + index}
            for index, status in enumerate(statuses)
        ]
    }


def test_usable_run_statuses_membership():
    assert "completed" in USABLE_RUN_STATUSES
    assert "imported" in USABLE_RUN_STATUSES
    assert "running" not in USABLE_RUN_STATUSES


def test_imported_run_is_selected():
    history = _get_latest_completed_history(_details("imported"))
    assert history["status"] == "imported"
    assert history["history_id"] == 1


def test_completed_run_is_selected():
    history = _get_latest_completed_history(_details("completed"))
    assert history["status"] == "completed"


def test_latest_usable_run_wins():
    # Both usable; the higher (creation_date, history_id) entry must win.
    history = _get_latest_completed_history(_details("completed", "imported"))
    assert history["history_id"] == 2


def test_no_usable_runs_raises():
    with pytest.raises(ValueError):
        _get_latest_completed_history(_details("running", "canceled"))


def test_empty_history_raises():
    with pytest.raises(ValueError):
        _get_latest_completed_history({"history": []})
