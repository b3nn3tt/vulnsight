"""Tests for the analyst validation overlay, including the per-process cache."""

import pytest

from vulnsight import validation
from vulnsight.validation import (
    _normalise_status_value,
    get_validation,
    get_validation_display,
    parse_validation_status,
    write_validation,
)


@pytest.fixture
def temp_validation_dir(tmp_path, monkeypatch):
    """Redirect validation storage to a temp dir and reset the cache."""

    monkeypatch.setattr(validation, "VALIDATION_DIR", tmp_path / "validation")
    validation._VALIDATION_CACHE.clear()
    yield
    validation._VALIDATION_CACHE.clear()


def test_normalise_status_aliases():
    assert _normalise_status_value("false-positive") == "false_positive"
    assert _normalise_status_value("False Positive") == "false_positive"
    assert _normalise_status_value("false_positives") == "false_positive"
    assert _normalise_status_value("CONFIRMED") == "confirmed"


def test_normalise_status_invalid():
    with pytest.raises(ValueError):
        _normalise_status_value("bogus")


def test_parse_validation_status_optional_and_required():
    assert parse_validation_status(None) is None
    assert parse_validation_status("confirmed") == "confirmed"
    with pytest.raises(ValueError):
        parse_validation_status(None, required=True)


def test_get_validation_display_fallback():
    assert get_validation_display("confirmed") == "Confirmed"
    assert get_validation_display("nonsense") == "Unreviewed"


def test_write_and_read_round_trip(temp_validation_dir):
    write_validation(1, "Scan One", 10, 100, "confirmed", notes="looks real")
    record = get_validation(1, 10, 100)
    assert record["status"] == "confirmed"
    assert record["notes"] == "looks real"
    assert record["validated_at"]


def test_clear_to_unreviewed_removes_record(temp_validation_dir):
    write_validation(1, "Scan One", 10, 100, "confirmed")
    assert get_validation(1, 10, 100)["status"] == "confirmed"
    write_validation(1, "Scan One", 10, 100, "unreviewed")
    assert get_validation(1, 10, 100)["status"] == "unreviewed"


def test_cache_reflects_latest_write(temp_validation_dir):
    # First read populates the cache for a scan with no file yet.
    assert get_validation(2, 20, 200)["status"] == "unreviewed"
    # A later write must be reflected, not served stale from the cache.
    write_validation(2, "Scan Two", 20, 200, "false_positive")
    assert get_validation(2, 20, 200)["status"] == "false_positive"
    # Clearing must invalidate the cache again.
    write_validation(2, "Scan Two", 20, 200, "unreviewed")
    assert get_validation(2, 20, 200)["status"] == "unreviewed"


def test_distinct_findings_isolated(temp_validation_dir):
    write_validation(3, "Scan Three", 30, 300, "confirmed")
    write_validation(3, "Scan Three", 30, 301, "false_positive")
    assert get_validation(3, 30, 300)["status"] == "confirmed"
    assert get_validation(3, 30, 301)["status"] == "false_positive"
    assert get_validation(3, 30, 999)["status"] == "unreviewed"
