# Summary

`summary` gives a severity-by-validation overview of the active scan, plus optional top-risk ranking.

## Severity by Validation

```bash
python3 main.py summary
```

Each severity row is broken down by validation status (Confirmed / False Positive / Unreviewed), with a `Total` column that preserves the raw severity count. The header also lists the in-scope hosts, so it is always clear which hosts the figures cover.

## Host Scope

```bash
python3 main.py summary --host 10.0.0.5
python3 main.py summary --exclude-host 10.0.0.5
python3 main.py summary --min-severity high
```

Repeat `--host` / `--exclude-host` to provide multiple hosts.

## Per-Host Breakdown

```bash
python3 main.py summary --by-host
```

Adds a per-host matrix beneath the scan-wide one. A finding affecting several hosts is counted once per host, so per-host totals can exceed the aggregate.

## Chart-Ready CSV

```bash
python3 main.py summary --format csv > scan-stats.csv
python3 main.py summary --by-host --format csv > scan-host-stats.csv
```

CSV is written to stdout for charting. Columns are `host,severity,total,confirmed,false_positive,unreviewed`; the `host` column is the single in-scope host, or `ALL` for the aggregate. With `--by-host` each row carries its specific host.

## Top Risks

```bash
python3 main.py summary --top-risks severity
python3 main.py summary --top-risks weighted --limit 20
```

Ranking modes are `severity`, `volume`, and `weighted`.
