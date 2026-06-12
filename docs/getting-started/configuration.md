# Configuration

VulnSight stores local Nessus connection settings in `.env` at the repository root.

## Interactive Setup

Run:

```bash
python3 main.py setup
```

To replace an existing configuration:

```bash
python3 main.py setup --reconfigure
```

Setup validates the Nessus host and API keys, then prompts for an optional shared validation directory (see [Validation Storage](#validation-storage)).

## Settings

The main values are:

- `NESSUS_URL`: Nessus API URL, for example `https://10.54.29.242:8834`
- `ACCESS_KEY`: Nessus API access key
- `SECRET_KEY`: Nessus API secret key
- `NESSUS_TIMEOUT`: optional API timeout in seconds, default `90`
- `VULNSIGHT_VALIDATION_DIR`: optional path for shared validation storage (see below)

The tool currently connects with certificate verification disabled to support self-signed Nessus deployments.

## Validation Storage

Analyst validation state (`Confirmed`, `False Positive`, `Unreviewed`) is stored as a local overlay under `.vulnsight/validation` by default, so a single analyst can keep state without a database.

To share validation across a team, point it at a common location (for example a file-server path). `setup` prompts for this, or set it directly in `.env`:

```bash
VULNSIGHT_VALIDATION_DIR=\\fileserver\share\vulnsight\validation
```

Writes merge into the latest on-disk state, so analysts validating different findings in the same scan do not overwrite each other. If a shared path is configured but unreachable, validation-dependent commands fail with a clear error rather than silently falling back to local storage. Leave it unset to keep validation local.

## Health Checks

Use:

```bash
python3 main.py doctor
python3 main.py status
python3 main.py ping
```

`doctor` checks the local environment and API connectivity. `status` shows current context and report dependencies. `ping` performs a lightweight Nessus API test.
