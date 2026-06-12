"""Tests for report scope labels and Markdown rendering helpers."""

from vulnsight.commands.report import _build_global_scope_labels
from vulnsight.formatters.report import (
    _build_executive_summary,
    _escape_markdown_table,
    _format_severity_scope,
    iter_global_report_markdown,
)


def test_escape_markdown_table():
    assert _escape_markdown_table("a|b|c") == "a\\|b\\|c"
    assert _escape_markdown_table("plain") == "plain"


def test_format_severity_scope():
    assert _format_severity_scope(">= High") == "High and above"
    assert _format_severity_scope("Critical only") == "Critical only"
    assert _format_severity_scope("None") == "None"


def test_scope_labels_defaults():
    scope = _build_global_scope_labels(None, 5, None, None, None, None)
    assert scope == {
        "folder": "All",
        "scans": "ALL (5)",
        "severity": "None",
        "validation": "All",
    }


def test_scope_labels_with_filters():
    scope = _build_global_scope_labels(
        ["Alpha", "Beta"], 2, None, 3, "confirmed", None, "TEST"
    )
    assert scope["folder"] == "TEST"
    assert scope["scans"] == "Alpha, Beta"
    assert scope["severity"] == ">= High"
    assert scope["validation"] == "Confirmed only"


def test_scope_labels_exact_severity_and_exclude():
    scope = _build_global_scope_labels(None, 1, 4, None, None, "false_positive")
    assert scope["severity"] == "Critical only"
    assert scope["validation"] == "Excluding False Positive"
    assert scope["folder"] == "All"


def test_executive_summary_first_sentence():
    report = {
        "findings": [
            {"severity": {"value": 4}},
            {"severity": {"value": 2}},
        ],
        "hosts": {"total": 3},
    }
    summary = _build_executive_summary(report)
    assert summary[0] == "The assessment identified 2 findings affecting 3 hosts."


def test_iter_global_report_markdown_empty_findings():
    report = {
        "estate": {
            "scans_included": 1,
            "scans_available": 4,
            "host_total": 0,
            "generated_at": "2026-06-12 10:00:00",
        },
        "hosts": {"total": 0},
        "scope": {
            "folder": "TEST",
            "scans": "ALL (1)",
            "severity": "None",
            "validation": "All",
        },
        "findings_heading": "## Findings",
        "findings": [],
        "appendix": [],
    }
    markdown = "".join(iter_global_report_markdown(report))
    assert "## Estate Details" in markdown
    assert "- Folder: TEST" in markdown
    assert "No findings matched the selected criteria." in markdown
