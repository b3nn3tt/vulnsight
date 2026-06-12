"""Tests for severity resolution and host-name extraction."""

import pytest
import typer

from vulnsight.commands.findings import (
    SEVERITY_LABELS,
    _get_scan_host_names,
    _resolve_minimum_severity,
)


def test_resolve_minimum_severity_valid():
    assert _resolve_minimum_severity("info") == 0
    assert _resolve_minimum_severity("high") == 3
    assert _resolve_minimum_severity("CRITICAL") == 4
    assert _resolve_minimum_severity(None) is None


def test_resolve_minimum_severity_invalid():
    with pytest.raises(typer.Exit):
        _resolve_minimum_severity("bogus")


def test_severity_labels_mapping():
    assert SEVERITY_LABELS[4] == "Critical"
    assert SEVERITY_LABELS[0] == "Info"


def test_get_scan_host_names_dedup_and_sort():
    hosts = [
        {"hostname": "bravo"},
        {"host": "alpha"},
        {"hostname": ""},
        {},
        {"hostname": "bravo"},
    ]
    assert _get_scan_host_names(hosts) == ["alpha", "bravo"]
