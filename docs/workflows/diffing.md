# Diffing Scan Runs

Use `diff` to compare two runs for the active scan.

## Default Diff

```bash
python3 main.py diff
```

By default, VulnSight compares the current selected run against the immediately previous run.

## Explicit Run Comparison

```bash
python3 main.py history
python3 main.py diff --compare 12 --against 13
```

`--compare` is the baseline history ID. `--against` is the target history ID.

## Filters

```bash
python3 main.py diff --min-severity high
python3 main.py diff --host 10.0.0.5
python3 main.py diff --plugin 19506
```

## Output

Table output is the default:

```bash
python3 main.py diff
```

CSV output is written to stdout:

```bash
python3 main.py diff --format csv > diff.csv
```

Diff output groups findings into new, resolved, and changed findings. Changed findings include severity, instance count, and host count drift.
