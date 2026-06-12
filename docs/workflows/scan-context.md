# Scan Context

Most VulnSight commands operate on an active scan context. The context includes:

- scan ID
- scan name
- history ID

## List Scans

Fast scan list:

```bash
python3 main.py scans
```

Detailed scan list:

```bash
python3 main.py scans --details
```

`--details` fetches slower per-scan run counts and credential status.

The scan list includes a **Folder** column. Limit it to a single Nessus folder with `--folder` (matched case-insensitively):

```bash
python3 main.py scans --folder "Production"
```

## Resolve a Scan Name

```bash
python3 main.py scan "WEYLAND AUTH"
```

This prints the Nessus scan ID for an exact scan name.

## Select a Scan

You can select by positional name:

```bash
python3 main.py use "WEYLAND AUTH"
```

Or by option:

```bash
python3 main.py use --name "WEYLAND AUTH"
python3 main.py use --id 9
```

The latest usable run is selected automatically. Imported scans (uploaded `.nessus` files) are supported alongside live scans.

## Select a History Run

Show available runs:

```bash
python3 main.py history
```

Select a run:

```bash
python3 main.py use-history 13
python3 main.py use-history latest
```

Show current context:

```bash
python3 main.py current
```
