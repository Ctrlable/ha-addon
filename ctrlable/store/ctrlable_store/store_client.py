"""Portal Store client — reuses the ctrlable agent's device identity.

Credentials are read FRESH on each call (the agent can re-enroll / rotate its
device token at any time), so the Store never gets stuck on a stale token.
"""
from __future__ import annotations

import hashlib
import logging
import os
from typing import Any, Optional

import aiohttp
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import CREDS_PATHS, DEFAULT_API_BASE

_LOGGER = logging.getLogger(__name__)


def read_agent_creds() -> dict[str, str]:
    """Parse the ctrlable agent's conf (shell KEY=VALUE / KEY="VALUE")."""
    for path in CREDS_PATHS:
        if not os.path.isfile(path):
            continue
        creds: dict[str, str] = {}
        try:
            with open(path) as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, _, v = line.partition("=")
                    creds[k.strip()] = v.strip().strip('"').strip("'")
        except OSError as exc:  # noqa: BLE001
            _LOGGER.warning("Could not read %s: %s", path, exc)
            continue
        if creds.get("DEVICE_TOKEN"):
            return creds
    return {}


async def async_build_client(hass: HomeAssistant, instance_id: str) -> "StoreClient":
    """Build a StoreClient from the CURRENT on-disk agent creds (executor read)."""
    creds = await hass.async_add_executor_job(read_agent_creds)
    api_base = creds.get("API_BASE") or DEFAULT_API_BASE
    if not api_base.rstrip("/").endswith("/api/v1"):
        api_base = DEFAULT_API_BASE
    return StoreClient(
        async_get_clientsession(hass), creds.get("DEVICE_TOKEN", ""), instance_id, api_base
    )


class StoreError(Exception):
    """Store client error."""


class StoreClient:
    """Talks to portal.ctrlable.com /api/v1/store with the device token."""

    def __init__(self, session: aiohttp.ClientSession, device_token: str,
                 instance_id: str, api_base: str = DEFAULT_API_BASE) -> None:
        self._session = session
        self._token = device_token
        self._instance_id = instance_id
        self._base = api_base.rstrip("/")

    @property
    def configured(self) -> bool:
        return bool(self._token)

    def _headers(self) -> dict[str, str]:
        return {"X-Device-Token": self._token}

    async def get_catalog(self) -> dict[str, Any]:
        """Returns {provisioned: bool, products: [...]}."""
        url = f"{self._base}/store/catalog"
        async with self._session.get(url, headers=self._headers(),
                                     params={"instance_id": self._instance_id}) as resp:
            if resp.status != 200:
                raise StoreError(f"catalog HTTP {resp.status}")
            return await resp.json()

    async def download(self, product: str, version: str, sha256: Optional[str] = None) -> bytes:
        url = f"{self._base}/store/download/{product}/{version}"
        async with self._session.get(url, headers=self._headers(),
                                     params={"instance_id": self._instance_id}) as resp:
            if resp.status == 403:
                raise StoreError("not licensed for this product")
            if resp.status != 200:
                raise StoreError(f"download HTTP {resp.status}")
            blob = await resp.read()
        if sha256:
            got = hashlib.sha256(blob).hexdigest()
            if got != sha256:
                raise StoreError(f"sha256 mismatch (expected {sha256[:12]}, got {got[:12]})")
        return blob
