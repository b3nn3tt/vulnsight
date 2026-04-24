"""Helpers for remediation-focused command output."""

from __future__ import annotations

import re

NO_RECOMMENDATION_TEXT = "No recommendation guidance provided by scanner."
NO_RECOMMENDATION_VALUES = {
    "",
    "n/a",
    "na",
    "not available.",
}


def clean_recommendation(text: str) -> str:
    """Return a cleaned recommendation string from Nessus solution text."""

    value = str(text or "").strip()
    if value.lower() in NO_RECOMMENDATION_VALUES:
        return NO_RECOMMENDATION_TEXT

    value = re.sub(r"\n\s*\n+", "\n\n", value)
    return value.strip()


def has_recommendation(text: str) -> bool:
    """Return whether the cleaned recommendation contains actionable guidance."""

    return clean_recommendation(text) != NO_RECOMMENDATION_TEXT
