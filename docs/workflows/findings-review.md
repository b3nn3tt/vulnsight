# Findings Review

Use `findings` for a scan-level overview and `finding` for one plugin's details.

## List Findings

```bash
python3 main.py findings
```

Useful filters:

```bash
python3 main.py findings --min-severity high
python3 main.py findings --severity critical
python3 main.py findings --host 10.0.0.5
python3 main.py findings --exclude-false-positives
```

Severity values are:

- `info`
- `low`
- `medium`
- `high`
- `critical`

## Recommendation-Focused Output

```bash
python3 main.py findings --recommendations
python3 main.py findings --remediation
```

This shows remediation guidance rather than the normal findings table.

## Inspect One Finding

```bash
python3 main.py finding 19506
```

Output formats:

```bash
python3 main.py finding 19506 --format markdown
python3 main.py finding 19506 --format json
python3 main.py finding 19506 --format debug
```

`debug` is intended for development and troubleshooting raw Nessus response shapes.

## Compact CSV

```bash
python3 main.py findings --format csv > findings.csv
```

This is a compact triage export. For verbose report-ready CSV, use `report --format csv`.
