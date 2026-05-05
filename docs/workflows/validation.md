# Validation

Validation is a local analyst overlay. It does not modify Nessus data.

Validation is scoped to:

- scan ID
- history ID
- finding plugin ID

## Supported States

- `confirmed`
- `false_positive`
- `unreviewed`

`unreviewed` is the implicit default when no validation record exists.

## Set Validation

```bash
python3 main.py validate 19506 --status confirmed
python3 main.py validate 19506 --status false_positive
```

Add an analyst note:

```bash
python3 main.py validate 19506 --status confirmed --note "Confirmed on host 10.0.0.5"
```

Clear validation:

```bash
python3 main.py validate 19506 --status unreviewed
```

## Review Validation

```bash
python3 main.py validation
python3 main.py validation --status confirmed
python3 main.py findings --validation confirmed
python3 main.py findings --exclude false_positive
```

Validation appears in findings, reports, and CSV exports.
