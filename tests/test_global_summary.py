"""Tests for the global summary estate matrix and validation derivation."""

import importlib

glob = importlib.import_module("vulnsight.commands.global")


def test_derive_plugin_status_unreviewed_dominates():
    # Any unreviewed instance means triage is incomplete -> unreviewed.
    assert (
        glob._derive_plugin_status(
            {"confirmed": 2, "unreviewed": 1, "false_positive": 0}
        )
        == "unreviewed"
    )


def test_derive_plugin_status_confirmed_then_false_positive():
    assert glob._derive_plugin_status({"confirmed": 3}) == "confirmed"
    assert glob._derive_plugin_status({"false_positive": 2}) == "false_positive"
    assert glob._derive_plugin_status({}) == "unreviewed"


def test_build_global_severity_validation_matrix():
    findings = {
        1: {"severity": 4, "validation_counts": {"confirmed": 1}},
        2: {"severity": 4, "validation_counts": {"unreviewed": 2}},
        3: {"severity": 3, "validation_counts": {"false_positive": 1}},
    }

    matrix = glob._build_global_severity_validation_matrix(findings)

    assert matrix[4] == {
        "total": 2,
        "confirmed": 1,
        "false_positive": 0,
        "unreviewed": 1,
    }
    assert matrix[3] == {
        "total": 1,
        "confirmed": 0,
        "false_positive": 1,
        "unreviewed": 0,
    }
    assert matrix[2]["total"] == 0


def test_write_global_summary_csv(capsys):
    matrix = {
        4: {"total": 2, "confirmed": 1, "false_positive": 0, "unreviewed": 1},
        3: {"total": 1, "confirmed": 0, "false_positive": 0, "unreviewed": 1},
        2: {"total": 0, "confirmed": 0, "false_positive": 0, "unreviewed": 0},
        1: {"total": 0, "confirmed": 0, "false_positive": 0, "unreviewed": 0},
        0: {"total": 0, "confirmed": 0, "false_positive": 0, "unreviewed": 0},
    }

    glob._write_global_summary_csv(matrix, "Production")

    lines = capsys.readouterr().out.strip().splitlines()
    assert lines[0] == "scope,severity,total,confirmed,false_positive,unreviewed"
    assert lines[1] == "Production,Critical,2,1,0,1"


def test_write_global_per_host_csv(capsys):
    empty = {
        level: {"total": 0, "confirmed": 0, "false_positive": 0, "unreviewed": 0}
        for level in (4, 3, 2, 1, 0)
    }
    crit = dict(empty)
    crit[4] = {"total": 1, "confirmed": 0, "false_positive": 0, "unreviewed": 1}
    per_scan = {"WEB_PROD": {"10.0.0.5": crit}}

    glob._write_global_per_host_csv(per_scan)

    lines = capsys.readouterr().out.strip().splitlines()
    assert lines[0] == "scan,host,severity,total,confirmed,false_positive,unreviewed"
    assert lines[1] == "WEB_PROD,10.0.0.5,Critical,1,0,0,1"
    assert len(lines) == 6  # header + 5 severities
