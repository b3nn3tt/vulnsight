"""Tests for pure helpers in the scans command (formatting, credential signals)."""

import re

from vulnsight.commands.scans import (
    _count_plugin_signals,
    _format_date,
    _format_status,
    _get_host_credential_status,
)


def test_format_date_valid_and_invalid():
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", _format_date(1781258940))
    assert _format_date(None) == "-"
    assert _format_date(0) == "-"
    assert _format_date("not-a-number") == "-"


def test_format_status_known_and_unknown():
    rendered = _format_status("completed")
    assert "completed" in rendered
    assert "green" in rendered
    assert _format_status("weird") == "weird"


def test_host_credential_status():
    assert _get_host_credential_status([{"credentialed": True}]) == "Yes"
    assert _get_host_credential_status([{"credentialed": False}]) == "No"
    assert _get_host_credential_status([]) is None
    assert _get_host_credential_status([{}]) is None


def test_host_credential_status_prefers_yes():
    hosts = [{"credentialed": False}, {"credentialed": True}]
    assert _get_host_credential_status(hosts) == "Yes"


def test_count_plugin_signals():
    assert _count_plugin_signals([{"plugin_id": 141118}]) == (1, 0)
    assert _count_plugin_signals([{"plugin_id": 104410}]) == (0, 1)
    mixed = [
        {"plugin_id": 141118},
        {"plugin_id": 104410},
        {"plugin_id": 99999},
    ]
    assert _count_plugin_signals(mixed) == (1, 1)
