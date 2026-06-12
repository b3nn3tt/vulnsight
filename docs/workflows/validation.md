# Validation

Validation is a local analyst overlay. It does not modify Nessus data.

Validation is scoped to:

- scan ID
- history ID
- finding plugin ID

Validation always targets the **active scan context**, so select a scan first with
`python3 main.py use --id <scan_id>`.

## Quick Reference

| Action | Command |
| --- | --- |
| Mark confirmed | `python3 main.py validate <id> --status confirmed` |
| Mark false positive | `python3 main.py validate <id> --status false_positive` |
| Add a note | `python3 main.py validate <id> --status confirmed --note "..."` |
| Clear to unreviewed | `python3 main.py validate <id> --status unreviewed` |
| View all states | `python3 main.py validation` |
| View one state | `python3 main.py validation --only confirmed` |
| Findings: only a state | `python3 main.py findings --only confirmed` |
| Findings: exclude a state | `python3 main.py findings --exclude false_positive` |
| Report only a state | `python3 main.py report --only confirmed` |

Note the flag split: **setting** state uses `--status` (on `validate`); **filtering** any
view (`validation`, `findings`, `report`, and their `global` forms) uses `--only` /
`--exclude`. The two jobs use different flags on purpose — one assigns a status, the
other filters by it.

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
python3 main.py validation --only confirmed
python3 main.py findings --only confirmed
python3 main.py findings --exclude false_positive
```

Validation appears in findings, reports, and CSV exports.

## Shared Storage (team use)

By default, validation is stored locally under `.vulnsight/validation`, so a single
analyst can keep state without a database. To share one overlay across a team, point it
at a network path — `setup` prompts for this, or set it directly in `.env`:

```bash
VULNSIGHT_VALIDATION_DIR=\\fileserver\share\vulnsight\validation
```

Writes merge into the latest on-disk state, so analysts validating different findings in
the same scan do not overwrite each other. If a shared location is configured but
unreachable, validation-dependent commands fail with a clear error rather than silently
falling back to local storage (which would fragment the team's overlay).
