"""Tests for the summary severity-by-validation matrix and CSV export."""

from vulnsight.commands import summary


def test_build_severity_validation_matrix(monkeypatch):
    findings = {
        100: {"plugin_id": 100, "severity": 4},
        101: {"plugin_id": 101, "severity": 4},
        102: {"plugin_id": 102, "severity": 3},
    }
    statuses = {100: "confirmed", 101: "unreviewed", 102: "false_positive"}
    monkeypatch.setattr(
        summary,
        "get_validation",
        lambda scan_id, history_id, pid: {"status": statuses[pid]},
    )

    matrix = summary._build_severity_validation_matrix(findings, 1, 10)

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


def _sample_matrix():
    return {
        4: {"total": 2, "confirmed": 0, "false_positive": 0, "unreviewed": 2},
        3: {"total": 7, "confirmed": 1, "false_positive": 0, "unreviewed": 6},
        2: {"total": 5, "confirmed": 0, "false_positive": 0, "unreviewed": 5},
        1: {"total": 0, "confirmed": 0, "false_positive": 0, "unreviewed": 0},
        0: {"total": 83, "confirmed": 0, "false_positive": 0, "unreviewed": 83},
    }


def test_write_summary_csv_single_host(capsys):
    summary._write_summary_csv(_sample_matrix(), {"10.54.29.207"})

    lines = capsys.readouterr().out.strip().splitlines()
    assert lines[0] == "host,severity,total,confirmed,false_positive,unreviewed"
    assert lines[1] == "10.54.29.207,Critical,2,0,0,2"
    assert lines[2] == "10.54.29.207,High,7,1,0,6"
    assert lines[-1] == "10.54.29.207,Info,83,0,0,83"


def test_write_summary_csv_multi_host_uses_all(capsys):
    summary._write_summary_csv(_sample_matrix(), {"10.0.0.1", "10.0.0.2"})

    lines = capsys.readouterr().out.strip().splitlines()
    assert lines[1] == "ALL,Critical,2,0,0,2"


def test_build_per_host_matrices(monkeypatch):
    findings = {
        100: {"plugin_id": 100, "severity": 4, "hosts": ["10.0.0.1", "10.0.0.2"]},
        101: {"plugin_id": 101, "severity": 3, "hosts": ["10.0.0.1"]},
    }
    monkeypatch.setattr(
        summary, "get_validation", lambda s, h, p: {"status": "unreviewed"}
    )

    matrices = summary._build_per_host_matrices(
        findings, {"10.0.0.1", "10.0.0.2"}, 1, 10
    )

    # A finding spanning two hosts is counted under each host.
    assert matrices["10.0.0.1"][4]["total"] == 1
    assert matrices["10.0.0.1"][3]["total"] == 1
    assert matrices["10.0.0.2"][4]["total"] == 1
    assert matrices["10.0.0.2"][3]["total"] == 0


def test_write_per_host_summary_csv(capsys):
    empty = {
        level: {"total": 0, "confirmed": 0, "false_positive": 0, "unreviewed": 0}
        for level in (4, 3, 2, 1, 0)
    }
    matrices = {"10.0.0.1": _sample_matrix(), "10.0.0.2": empty}

    summary._write_per_host_summary_csv(matrices)

    lines = capsys.readouterr().out.strip().splitlines()
    assert lines[0] == "host,severity,total,confirmed,false_positive,unreviewed"
    assert lines[1] == "10.0.0.1,Critical,2,0,0,2"
    assert "10.0.0.2,Critical,0,0,0,0" in lines
    assert len(lines) == 11  # header + 5 severities x 2 hosts
