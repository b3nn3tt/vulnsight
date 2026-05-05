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

## Settings

The main values are:

- `NESSUS_URL`: Nessus API URL, for example `https://10.54.29.242:8834`
- `ACCESS_KEY`: Nessus API access key
- `SECRET_KEY`: Nessus API secret key
- `NESSUS_TIMEOUT`: optional API timeout in seconds, default `90`

The tool currently connects with certificate verification disabled to support self-signed Nessus deployments.

## Health Checks

Use:

```bash
python3 main.py doctor
python3 main.py status
python3 main.py ping
```

`doctor` checks the local environment and API connectivity. `status` shows current context and report dependencies. `ping` performs a lightweight Nessus API test.
