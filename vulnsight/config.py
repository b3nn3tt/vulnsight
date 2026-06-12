"""Configuration helpers for VulnSight."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv, set_key, unset_key


ENV_FILE = Path(__file__).resolve().parent.parent / ".env"
DEFAULT_NESSUS_URL = "https://10.54.29.242:8834"
DEFAULT_NESSUS_TIMEOUT = 90
DEFAULT_VALIDATION_DIR = (
    Path(__file__).resolve().parent.parent / ".vulnsight" / "validation"
)


def reload_env() -> None:
    """Reload configuration values from the local .env file."""

    load_dotenv(dotenv_path=ENV_FILE, override=True)


reload_env()


@dataclass(frozen=True)
class Settings:
    """Application settings loaded from environment variables."""

    base_url: str
    access_key: str
    secret_key: str
    timeout: int = DEFAULT_NESSUS_TIMEOUT
    verify_ssl: bool = False


def _get_timeout() -> int:
    """Return the configured Nessus API timeout in seconds."""

    raw_value = os.getenv("NESSUS_TIMEOUT", "").strip()
    if not raw_value:
        return DEFAULT_NESSUS_TIMEOUT

    try:
        timeout = int(raw_value)
    except ValueError:
        return DEFAULT_NESSUS_TIMEOUT

    if timeout < 1:
        return DEFAULT_NESSUS_TIMEOUT

    return timeout


def get_settings() -> Settings:
    """Load and return application settings."""

    reload_env()
    return Settings(
        base_url=os.getenv("NESSUS_URL", DEFAULT_NESSUS_URL).rstrip("/"),
        access_key=os.getenv("ACCESS_KEY", "").strip(),
        secret_key=os.getenv("SECRET_KEY", "").strip(),
        timeout=_get_timeout(),
        verify_ssl=False,
    )


def get_validation_dir() -> Path:
    """Return the directory used to store the validation overlay.

    Defaults to a local ``.vulnsight/validation`` directory. Set
    ``VULNSIGHT_VALIDATION_DIR`` (for example to a shared file-server path) to
    point the overlay at central storage so a team can share validation state.
    """

    reload_env()
    configured = os.getenv("VULNSIGHT_VALIDATION_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()
    return DEFAULT_VALIDATION_DIR


def save_settings(base_url: str, access_key: str, secret_key: str) -> None:
    """Persist Nessus connection settings to the local .env file."""

    ENV_FILE.touch(exist_ok=True)
    set_key(str(ENV_FILE), "NESSUS_URL", base_url.strip())
    set_key(str(ENV_FILE), "ACCESS_KEY", access_key.strip())
    set_key(str(ENV_FILE), "SECRET_KEY", secret_key.strip())

    os.environ["NESSUS_URL"] = base_url.strip()
    os.environ["ACCESS_KEY"] = access_key.strip()
    os.environ["SECRET_KEY"] = secret_key.strip()


def save_validation_dir(validation_dir: str | None) -> None:
    """Persist or clear the shared validation directory in the local .env file.

    A blank or None value clears the setting, reverting to local storage.
    """

    ENV_FILE.touch(exist_ok=True)
    value = (validation_dir or "").strip()

    if value:
        set_key(str(ENV_FILE), "VULNSIGHT_VALIDATION_DIR", value)
        os.environ["VULNSIGHT_VALIDATION_DIR"] = value
    else:
        unset_key(str(ENV_FILE), "VULNSIGHT_VALIDATION_DIR")
        os.environ.pop("VULNSIGHT_VALIDATION_DIR", None)
