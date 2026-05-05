# Reporting and CSV Export

Reports are generated from the active scan context.

## DOCX Report

```bash
python3 main.py report
python3 main.py report --format docx
python3 main.py report --format docx --toc
```

DOCX output uses Pandoc and the bundled reference document template.

## Verbose CSV Report

```bash
python3 main.py report --format csv
python3 main.py report --format csv --output report.csv
```

Report CSV is written to a file and includes verbose finding data, including:

- scan metadata
- scope metadata
- finding ID and name
- severity
- validation status
- affected hosts
- CVEs
- CVSS values
- CPEs
- exploit availability
- publication dates
- description
- solution
- evidence
- references

## Filters

Report filters match the rest of the CLI:

```bash
python3 main.py report --min-severity high
python3 main.py report --severity critical
python3 main.py report --host 10.0.0.5
python3 main.py report --exclude-host 10.0.0.5
python3 main.py report --only confirmed
python3 main.py report --exclude false_positive
```

Repeat `--host` or `--exclude-host` to provide multiple hosts.

## Presets

```bash
python3 main.py report --preset management
python3 main.py report --preset technical
python3 main.py report --preset high-risk
```

Presets supply default filters and output options where the user has not already provided a value.
