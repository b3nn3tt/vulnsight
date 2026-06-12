"""Tests for enumerating valid values in finite-option usage errors."""

import click

import main


def test_hint_for_missing_validation_argument():
    # The exact case: `findings --only` with no value.
    exc = click.BadOptionUsage("--only", "Option '--only' requires an argument.")
    hint = main._value_hint_for_usage_error(exc)
    assert hint == "Valid values for --only: confirmed, false_positive, unreviewed"


def test_hint_for_severity_via_message_scan():
    exc = click.UsageError("Invalid value for '--severity': 'bogus'")
    hint = main._value_hint_for_usage_error(exc)
    assert hint == "Valid values for --severity: info, low, medium, high, critical"


def test_no_hint_for_open_valued_option():
    exc = click.BadOptionUsage("--host", "Option '--host' requires an argument.")
    assert main._value_hint_for_usage_error(exc) is None
