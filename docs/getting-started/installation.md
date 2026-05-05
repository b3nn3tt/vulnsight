# Installation

VulnSight is a Python CLI for working with the Nessus Professional API.

## Create a Virtual Environment

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows:

```powershell
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## Run the CLI

With the virtual environment active:

```bash
python3 main.py --help
```

If the command loads help, the Python environment is ready.

## Optional Tools

DOCX reporting requires Pandoc:

```bash
sudo apt install pandoc
```

CSV exports do not require Pandoc.
