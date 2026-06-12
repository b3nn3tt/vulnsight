"""Minimal Nessus API client used by the VulnSight CLI."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import requests
import urllib3

from vulnsight.config import Settings


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Run statuses whose history entries carry usable result data. Imported scans
# (uploaded .nessus files) report "imported" rather than "completed" but still
# expose full vulnerability and host data.
USABLE_RUN_STATUSES = frozenset({"completed", "imported"})


def select_latest_usable_run(
    history: Iterable[dict[str, Any]],
) -> dict[str, Any] | None:
    """Return the most recent usable history entry, or None if there are none.

    A run is usable when its status is in :data:`USABLE_RUN_STATUSES`. Entries
    are ranked by creation date, then history ID.
    """

    usable = [
        entry
        for entry in history
        if str(entry.get("status", "")).strip().lower() in USABLE_RUN_STATUSES
    ]
    if not usable:
        return None

    return max(
        usable,
        key=lambda entry: (
            int(entry.get("creation_date", 0) or 0),
            int(entry.get("history_id", 0) or 0),
        ),
    )


class NessusClient:
    """Small wrapper around the Nessus API."""

    def __init__(self, settings: Settings) -> None:
        """Initialise the client with Nessus connection settings."""

        self.base_url = settings.base_url
        self.timeout = settings.timeout
        self.session = requests.Session()
        self.session.verify = settings.verify_ssl
        self.session.headers.update(
            {
                "Accept": "application/json",
                "X-ApiKeys": (
                    f"accessKey={settings.access_key}; secretKey={settings.secret_key}"
                ),
            }
        )

    def _get(self, path: str) -> dict[str, Any]:
        """Perform a GET request and return the JSON payload."""

        response = self.session.get(f"{self.base_url}{path}", timeout=self.timeout)
        response.raise_for_status()
        return response.json()

    def list_scans(self) -> list[dict[str, Any]]:
        """Return the list of scans from Nessus."""

        payload = self._get("/scans")
        return payload.get("scans", [])

    def list_folders(self) -> list[dict[str, Any]]:
        """Return the list of scan folders from Nessus."""

        payload = self._get("/folders")
        return payload.get("folders", [])

    def get_scan_details(self, scan_id: int) -> dict[str, Any]:
        """Return the full details for a specific scan."""

        return self._get(f"/scans/{scan_id}")

    def get_latest_completed_history(self, scan_id: int) -> dict[str, Any]:
        """Return the most recent usable history entry for a scan."""

        details = self.get_scan_details(scan_id)
        run = select_latest_usable_run(details.get("history", []))
        if run is None:
            raise ValueError("No usable scan runs found.")
        return run

    def get_plugin_details(
        self, scan_id: int, plugin_id: int, history_id: int
    ) -> dict[str, Any]:
        """Return full details for a plugin within a specific scan history."""

        return self._get(f"/scans/{scan_id}/plugins/{plugin_id}?history_id={history_id}")

    def get_scan_result_details(self, scan_id: int, history_id: int) -> dict[str, Any]:
        """Return the details for a specific scan history."""

        return self._get(f"/scans/{scan_id}?history_id={history_id}")

    def get_host_details(self, scan_id: int, host_id: int, history_id: int) -> dict[str, Any]:
        """Return details for a host within a specific scan history."""

        return self._get(f"/scans/{scan_id}/hosts/{host_id}?history_id={history_id}")

    def get_host_plugin_output(
        self, scan_id: int, host_id: int, plugin_id: int, history_id: int
    ) -> dict[str, Any]:
        """Return plugin output for a host within a specific scan history."""

        return self._get(
            f"/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}?history_id={history_id}"
        )

    def get_plugin_metadata(self, plugin_id: int) -> dict[str, Any]:
        """Return global metadata for a plugin."""

        return self._get(f"/plugins/plugin/{plugin_id}")

    def check_connection(self) -> int:
        """Verify API connectivity and return the number of visible scans."""

        return len(self.list_scans())

    def find_scan_by_name(self, name: str) -> dict[str, Any] | None:
        """Find a scan by name using a case-insensitive comparison."""

        target = name.strip().lower()
        for scan in self.list_scans():
            scan_name = str(scan.get("name", "")).strip().lower()
            if scan_name == target:
                return scan
        return None
