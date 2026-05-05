# VulnSight

## Introduction

This tool was built to fill a very specific gap in my workflow.

As a user of Tenable’s Nessus Professional, I found that sharing findings beyond a manually written report was consistently slow and painful. Extracting useful data from scans, shaping it into something readable, and then tailoring it for different audiences turned me — the tester — into the bottleneck.

The obvious answer is to move up to a more feature-rich platform like Tenable Vulnerability Management (formerly Tenable.io) or Tenable Security Center, where dashboards, user access, and remediation workflows are built in. But that comes with significant cost, and in practice, I often still end up walking stakeholders through findings anyway.

For many use cases, a single Nessus Professional licence is perfectly sufficient — if you can get the data out efficiently.

That’s where this tool comes in.

Nessus exposes a comprehensive API, but in practice it is not especially intuitive to work with directly. I wanted a simple, fast way to interrogate scan data, pivot between views, and export findings in a clean, consistent format without constantly working with raw API responses.

So I built a CLI.

The original goal was straightforward: speed up triage and reporting.

As is often the case, it grew into something more.

## 1. Overview

VulnSight is a Python CLI for working directly with the Nessus Professional API. It is built for testers and analysts who need to triage findings, validate outcomes, compare scan runs, and produce usable outputs without working through raw API responses by hand.

The tool is designed for internal, practitioner-led use. It is not trying to replace a full vulnerability management platform. The focus is a CLI-first workflow that is fast, explicit, and easy to use during assessment, review, and reporting.

## Typical Workflow

1. Select a scan
2. Explore findings
3. Validate findings (confirm / false positive)
4. Compare with previous scans (diff)
5. Export results (CSV or report)

## Documentation

Early user documentation lives in [docs/README.md](docs/README.md). It includes setup notes, scan context workflows, findings review, validation, diffing, reporting, global views, command reference, and troubleshooting.

## 2. Key Features

- Scan selection and context management.
- Findings exploration with severity, host, and validation-based filtering.
- Detailed finding inspection with evidence, metadata, and recommendation output.
- Diffing between scan runs, including new, resolved, and drift-aware changed findings.
- Remediation-focused output with `--remediation`.
- CSV export for structured analysis and spreadsheet use.
- Validation overlay with `Confirmed`, `False Positive`, and `Unreviewed`.
- Markdown to DOCX reporting via Pandoc.

## 3. Installation

Clone the repository and create a Python virtual environment:

```bash
git clone <repo_url>
cd vulnsight
python3 -m venv .venv
```

Activate the environment and install dependencies:

```bash
# Windows
.\.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
```

VulnSight uses a local `.env` file for Nessus connection settings and API keys. If the tool is run without a valid `.env`, it stops cleanly and advises the user to run `python3 main.py setup`.

## 4. Configuration

Configuration is stored in a local `.env` file.

You can create or update it by running:

```bash
python3 main.py setup
```

The setup flow collects the Nessus host details and API credentials, validates connectivity, and writes the required values to `.env`.

Nessus API authentication uses `X-ApiKeys` values:
- `ACCESS_KEY`
- `SECRET_KEY`

The Nessus URL is stored as:
- `NESSUS_URL`

The API timeout defaults to 90 seconds and can be overridden with:
- `NESSUS_TIMEOUT`

The tool supports self-signed Nessus environments by running with `verify=False`.

## 5. Usage

### 5.1 Scan Context

These commands manage the active scan and history context used by the rest of the CLI.

```bash
scans
scans --details
scan <name>
use <scan_name>
use --name <scan_name>
use --id <scan_id>
use-history <id|latest>
current
history
```

Use `scans` to list available scans, `scans --details` to include slower per-scan run and credential checks, `scan <name>` to resolve a scan by name, and `use <scan_name>`, `use --name <scan_name>`, or `use --id <scan_id>` to set the working scan. `use-history` selects a specific run for that scan. `current` and `history` show the active context and available scan runs.

### 5.2 Findings

These commands are used for scan-local finding review and filtering.

```bash
findings
findings --min-severity high
findings --host <ip>
finding <id>
```

`findings` shows aggregated findings for the active scan run. Filters can be applied by severity, host, and validation state. `finding <id>` shows detailed information for a single plugin ID, including evidence and recommendation data.

### 5.3 Diffing

These commands compare two scan runs for the active scan.

```bash
diff
diff --compare <id> --against <id>
diff --plugin <id>
```

The default diff compares the current selected run to the immediately previous run. Output is grouped into new, resolved, and changed findings. Changed findings include severity drift, instance drift, and host drift.

### 5.4 Validation

Validation is a local overlay applied to findings in a specific scan run. It is tied to `scan_id + history_id + finding_id`.

Supported states are:
- `Confirmed`
- `False Positive`
- `Unreviewed`

```bash
validate <id> --status confirmed
validate <id> --status false_positive
validation
validation --status confirmed
```

`Unreviewed` is implicit when no validation record exists. Validation is local to the workspace, applies per scan run, and does not carry between runs.

### 5.5 Reporting

DOCX reports are generated from Markdown and converted with Pandoc. CSV reports are written directly from the report model.

```bash
report
report --format csv
```

Output includes structured findings, evidence, recommendation content, and validation status.

Validation-based subsets can also be generated when needed, for example:

```bash
report --exclude false_positive
report --only confirmed
```

### 5.6 CSV Export

CSV output is available from existing command views.

```bash
findings --format csv
report --format csv
global findings --format csv
diff --format csv
```

Command-view CSV is written to stdout, so it can be redirected to a file:

```bash
findings --format csv > findings.csv
```

Report CSV is written to a timestamped `.csv` file by default, or to a path supplied with `--output`.

This is intended for Excel, pivot tables, and other analysis workflows. Scan-level findings CSV includes `validation_status`.

## 6. Design Principles

- CLI-first workflow.
- Minimal dependencies.
- Separation of concerns between CLI logic, data extraction, rendering, and templates.
- Validation as an overlay rather than mutation of source data.
- Incremental development.

## 7. Limitations

- Requires Nessus Professional API access.
- Output depends on the quality and completeness of the underlying scan data.
- Validation is local only.
- It is not a full vulnerability management platform.

## 8. Future Work

- Enhanced diff intelligence.
- Improved reporting profiles.
- Optional classification or prioritisation.
- Further UX improvements.
