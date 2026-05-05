# Command Reference

Run `python3 main.py --help` for the current command list. Run any command with `--help` for command-specific help.

## Root Commands

- `current`: show active scan context
- `diff`: compare scan runs
- `doctor`: check configuration, connectivity, Pandoc, and local state
- `finding`: inspect one finding in the active scan run
- `findings`: list aggregated findings in the active scan run
- `global`: cross-scan views using latest completed runs
- `history`: list available runs for the active scan
- `hosts`: list hosts and best-effort operating systems
- `ping`: test basic Nessus connectivity
- `report`: generate DOCX or verbose CSV reports
- `scan`: resolve an exact scan name to a scan ID
- `scans`: list scans
- `setup`: create or update `.env`
- `status`: show context, environment, and next actions
- `summary`: show severity summary and optional top-risk ranking
- `use`: select an active scan by name or ID
- `use-history`: select a scan run for the active scan
- `validate`: set validation state for a finding
- `validation`: list validation state

## Global Subcommands

```bash
python3 main.py global findings
python3 main.py global summary
python3 main.py global finding <plugin_id>
```

Global commands use the latest completed run from each visible scan.

## Common Values

Severity:

- `info`
- `low`
- `medium`
- `high`
- `critical`

Validation:

- `confirmed`
- `false_positive`
- `unreviewed`

Formats:

- tables: default for command views
- `csv`: available for findings, diff, global findings, and report
- `docx`: available for report
