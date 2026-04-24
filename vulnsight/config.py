"""Configuration helpers for VulnSight."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv, set_key


ENV_FILE = Path(__file__).resolve().parent.parent / ".env"
DEFAULT_NESSUS_URL = "https://10.54.29.242:8834"


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
    verify_ssl: bool = False


def get_settings() -> Settings:
    """Load and return application settings."""

    reload_env()
    return Settings(
        base_url=os.getenv("NESSUS_URL", DEFAULT_NESSUS_URL).rstrip("/"),
        access_key=os.getenv("ACCESS_KEY", "").strip(),
        secret_key=os.getenv("SECRET_KEY", "").strip(),
        verify_ssl=False,
    )


def save_settings(base_url: str, access_key: str, secret_key: str) -> None:
    """Persist Nessus connection settings to the local .env file."""

    ENV_FILE.touch(exist_ok=True)
    set_key(str(ENV_FILE), "NESSUS_URL", base_url.strip())
    set_key(str(ENV_FILE), "ACCESS_KEY", access_key.strip())
    set_key(str(ENV_FILE), "SECRET_KEY", secret_key.strip())

    os.environ["NESSUS_URL"] = base_url.strip()
    os.environ["ACCESS_KEY"] = access_key.strip()
    os.environ["SECRET_KEY"] = secret_key.strip()
