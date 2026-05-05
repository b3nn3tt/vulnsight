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

DOCX reports require Pandoc:

```bash
sudo apt install pandoc
```

CSV reports do not require Pandoc:

```bash
python3 main.py report --format csv
```

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
