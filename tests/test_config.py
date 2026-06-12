"""Tests for configuration resolution, including the shared validation dir."""

from vulnsight import config


def test_validation_dir_defaults(monkeypatch):
    monkeypatch.delenv("VULNSIGHT_VALIDATION_DIR", raising=False)
    assert config.get_validation_dir() == config.DEFAULT_VALIDATION_DIR


def test_validation_dir_env_override(monkeypatch, tmp_path):
    target = tmp_path / "shared" / "validation"
    monkeypatch.setenv("VULNSIGHT_VALIDATION_DIR", str(target))
    assert config.get_validation_dir() == target
