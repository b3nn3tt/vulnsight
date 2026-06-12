# Troubleshooting

## Show Help Instead of Guessing

Every command supports `--help`:

```bash
python3 main.py --help
python3 main.py findings --help
python3 main.py report --help
python3 main.py global --help
```

Commands that require a subcommand or argument show their relative help when run without enough input.

## Check Configuration

```bash
python3 main.py doctor
python3 main.py status
python3 main.py ping
```

If credentials are missing or rejected, run:

```bash
python3 main.py setup --reconfigure
```

## Slow Nessus Responses

Some Nessus endpoints are heavier than others. `scans` is lightweight, while `scans --details`, `use`, `findings`, and `report` may fetch larger scan details.

Increase the API timeout in `.env` if needed:

```env
NESSUS_TIMEOUT=120
```

If one scan is much slower than others, check the scan in the Nessus UI. A corrupt or unusually large scan history can slow API calls.

## Pandoc Issues

DOCX reports require Pandoc. If a report fails during conversion, first confirm Pandoc runs on its own:

```bash
pandoc --version
```

If that errors, the problem is the Pandoc install, not VulnSight. A common cause on Windows is a broken or "shimmed" install from a package manager (the error mentions a `.NET` / shim failure). Reinstall Pandoc as a native binary:

```bash
# Linux
sudo apt install pandoc

# Windows
winget install --id JohnMacFarlane.Pandoc
```

CSV reports do not require Pandoc:

```bash
python3 main.py report --format csv
```

## Shared Validation Storage

If `VULNSIGHT_VALIDATION_DIR` points at a shared location that is offline, commands that read or write validation (`findings`, `report`, `validation`, and the `global` forms) stop with a clear error rather than silently falling back to local storage. Reconnect the share, or run `setup` to switch back to local storage. Commands that do not use validation (`scans`, `use`, `summary`, etc.) are unaffected.

## CSV Redirects

Command-view CSV writes to stdout:

```bash
python3 main.py findings --format csv > findings.csv
python3 main.py diff --format csv > diff.csv
```

Report CSV writes to a file directly:

```bash
python3 main.py report --format csv --output report.csv
```
