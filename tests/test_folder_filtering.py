"""Tests for folder name resolution used by --folder filters."""

from vulnsight.commands.scans import _resolve_folder_filter, _resolve_folder_name


FOLDER_MAP = {2: "My Scans", 3: "TEST", 4: "Prod"}


def test_resolve_folder_filter_case_insensitive():
    assert _resolve_folder_filter(FOLDER_MAP, "test") == 3
    assert _resolve_folder_filter(FOLDER_MAP, "  PROD ") == 4


def test_resolve_folder_filter_unknown():
    assert _resolve_folder_filter(FOLDER_MAP, "nope") is None
    assert _resolve_folder_filter({}, "test") is None


def test_resolve_folder_name_known():
    assert _resolve_folder_name(FOLDER_MAP, {"folder_id": 3}) == "TEST"


def test_resolve_folder_name_unknown_or_missing():
    assert _resolve_folder_name(FOLDER_MAP, {"folder_id": 99}) == "-"
    assert _resolve_folder_name(FOLDER_MAP, {}) == "-"
    assert _resolve_folder_name({}, {"folder_id": 3}) == "-"
