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

## Overview

VulnSight is a Python CLI for working directly with the Nessus Professional API. It is built for testers and analysts who need to triage findings, validate outcomes, compare scan runs, and produce usable outputs without working through raw API responses by hand.

The tool is designed for internal, practitioner-led use. It is not trying to replace a full vulnerability management platform. The focus is a CLI-first workflow that is fast, explicit, and easy to use during assessment, review, and reporting.

## Key Features

- Scan selection and context management.
- Findings exploration with severity, host, and validation-based filtering.
- Detailed finding inspection with evidence, metadata, and recommendation output.
- Diffing between scan runs, including new, resolved, and drift-aware changed findings.
- Remediation-focused output with `--remediation`.
- CSV export for structured analysis and spreadsheet use.
- Validation overlay with `Confirmed`, `False Positive`, and `Unreviewed`.
- Markdown to DOCX reporting via Pandoc.

## Quick Start

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

Create or update the local Nessus API configuration:

```bash
python3 main.py setup
```

Then follow the usual flow:

```bash
python3 main.py scans
python3 main.py use --id <scan_id>
python3 main.py findings
python3 main.py finding <plugin_id>
python3 main.py report
```

Use the built-in help for command-specific options:

```bash
python3 main.py --help
python3 main.py findings --help
python3 main.py report --help
```

DOCX reporting requires Pandoc. CSV exports do not require Pandoc.

## Design Principles

- CLI-first workflow.
- Minimal dependencies.
- Separation of concerns between CLI logic, data extraction, rendering, and templates.
- Validation as an overlay rather than mutation of source data.
- Incremental development.

## Limitations

- Requires Nessus Professional API access.
- Output depends on the quality and completeness of the underlying scan data.
- Validation is local only.
- It is not a full vulnerability management platform.

## Documentation

The growing user documentation lives in [the VulnSight documentation](docs/README.md). It covers installation, configuration, scan context, findings review, validation, diffing, reporting, global views, command reference, and troubleshooting.
