"""Ctrlable Store — private, license-gated installer for Ctrlable components.

Single config entry (appliance infra). Reads the device identity written by the
ctrlable agent add-on, shows the entitled catalog from portal.ctrlable.com, and
installs/updates components into custom_components/ (HACS-safe). The Store panel
can be shown/hidden in the sidebar (switch or the Configure page).
"""
from __future__ import annotations

import logging
from datetime import timedelta
from pathlib import Path

from homeassistant.components import frontend
from homeassistant.components.http import StaticPathConfig
from homeassistant.config_entries import SOURCE_IMPORT, ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.instance_id import async_get as async_get_instance_id
from homeassistant.helpers.storage import Store
from homeassistant.helpers.typing import ConfigType
from homeassistant.loader import async_get_integration
from homeassistant.helpers.event import async_track_time_interval

from . import websocket_api
from .installer import install_zip, uninstall
from .store_client import async_build_client
from .const import (
    DOMAIN,
    PANEL_ELEMENT,
    PANEL_FOLDER,
    PANEL_ICON,
    PANEL_JS,
    PANEL_STATIC_URL,
    PANEL_TITLE,
    PANEL_URL_PATH,
    SIDEBAR_STORE_KEY,
    PROVISIONED_STORE_KEY,
    REFRESH_INTERVAL_MIN,
)

_LOGGER = logging.getLogger(__name__)
_HERE = Path(__file__).resolve().parent
PLATFORMS = [Platform.SWITCH]


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """YAML presence (baked image / config.yaml) → create the config entry."""
    if DOMAIN in config and not hass.config_entries.async_entries(DOMAIN):
        hass.async_create_task(
            hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_IMPORT}, data={})
        )
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    data = hass.data.setdefault(DOMAIN, {})
    data["instance_id"] = await async_get_instance_id(hass)
    data["cc_dir"] = hass.config.path("custom_components")
    data["entry_id"] = entry.entry_id
    # Version the panel module URL so a component update loads the new panel
    # instead of a browser-cached copy.
    integration = await async_get_integration(hass, DOMAIN)
    data["_module_url"] = f"{PANEL_STATIC_URL}/{PANEL_JS}?v={integration.version}"

    # Register WS + panel static path once per HA run (entry may reload).
    if not data.get("_ws_registered"):
        websocket_api.async_register(hass)
        data["_ws_registered"] = True
    if not data.get("_static_registered"):
        await hass.http.async_register_static_paths(
            [StaticPathConfig(PANEL_STATIC_URL, str(_HERE / PANEL_FOLDER), False)]
        )
        data["_static_registered"] = True

    data["_sidebar_show"] = await _load_sidebar_show(hass)
    data["_provisioned"] = await _load_provisioned(hass)
    _update_sidebar_panel(hass)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Interval actions must be @callback so HA runs them ON the event loop. A
    # plain lambda is classified as a sync job and run in an executor thread —
    # calling hass.async_create_task from there trips HA's thread-safety guard
    # (RuntimeError: async_create_task from a thread other than the event loop).
    @callback
    def _tick_refresh_provisioned(_now) -> None:
        hass.async_create_task(_refresh_provisioned(hass))

    @callback
    def _tick_poll_jobs(_now) -> None:
        hass.async_create_task(_poll_jobs(hass))

    # Check assignment/provisioning now + periodically (reveals the Store once the
    # appliance is assigned to a client/location, without a restart).
    hass.async_create_task(_refresh_provisioned(hass))
    entry.async_on_unload(async_track_time_interval(
        hass, _tick_refresh_provisioned,
        timedelta(minutes=REFRESH_INTERVAL_MIN)))

    # Poll for remote install/remove jobs queued from the portal.
    hass.async_create_task(_poll_jobs(hass))
    entry.async_on_unload(async_track_time_interval(
        hass, _tick_poll_jobs,
        timedelta(seconds=90)))
    return True


async def _poll_jobs(hass: HomeAssistant) -> None:
    """Pull queued remote install/remove jobs from the portal and apply them."""
    data = hass.data.setdefault(DOMAIN, {})
    cc = data.get("cc_dir")
    try:
        client = await async_build_client(hass, data.get("instance_id", ""))
        if not client.configured:
            return
        jobs = await client.get_jobs()
    except Exception:  # noqa: BLE001
        return
    if not jobs:
        return
    restart_needed = False
    for job in jobs:
        jid, product = job["id"], job["product"]
        action = job.get("action", "install")
        try:
            if action == "remove":
                await hass.async_add_executor_job(uninstall, cc, product)
            else:
                cat = await client.get_catalog()
                entry = next((p for p in cat.get("products", []) if p["product"] == product), None)
                if entry is None:
                    raise RuntimeError("product not in catalog")
                ver = job.get("target_version") or entry["version"]
                sha = entry.get("sha256") if ver == entry["version"] else None
                blob = await client.download(product, ver, sha)
                await hass.async_add_executor_job(install_zip, cc, product, blob)
            await client.report_job(jid, "applied", f"{action} {product} ok")
            restart_needed = True
            _LOGGER.info("Ctrlable Store: remote %s %s applied", action, product)
        except Exception as err:  # noqa: BLE001
            _LOGGER.exception("Ctrlable Store: remote %s %s failed", action, product)
            try:
                await client.report_job(jid, "failed", str(err))
            except Exception:  # noqa: BLE001
                pass
    if restart_needed:
        await hass.services.async_call("homeassistant", "restart", blocking=False)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


# ── Sidebar show/hide ────────────────────────────────────────────────────────
async def _load_sidebar_show(hass: HomeAssistant) -> bool:
    store = Store(hass, 1, SIDEBAR_STORE_KEY)
    data = await store.async_load() or {}
    return bool(data.get("show", False))  # default: hidden — user opts in via the switch/Configure


async def _save_sidebar_show(hass: HomeAssistant, show: bool) -> None:
    await Store(hass, 1, SIDEBAR_STORE_KEY).async_save({"show": bool(show)})


async def _load_provisioned(hass: HomeAssistant) -> bool:
    data = await Store(hass, 1, PROVISIONED_STORE_KEY).async_load() or {}
    return bool(data.get("provisioned", False))


async def _save_provisioned(hass: HomeAssistant, val: bool) -> None:
    await Store(hass, 1, PROVISIONED_STORE_KEY).async_save({"provisioned": bool(val)})


async def _refresh_provisioned(hass: HomeAssistant) -> None:
    """Ask the portal whether this appliance is assigned (provisioned). Cache it
    (survives offline) and update the sidebar. Never downgrades on a fetch error."""
    data = hass.data.setdefault(DOMAIN, {})
    try:
        client = await async_build_client(hass, data.get("instance_id", ""))
        if not client.configured:
            return
        res = await client.get_catalog()
    except Exception:  # noqa: BLE001
        return
    prov = bool(res.get("provisioned"))
    if prov != data.get("_provisioned"):
        data["_provisioned"] = prov
        await _save_provisioned(hass, prov)
        _update_sidebar_panel(hass)


@callback
def async_set_sidebar(hass: HomeAssistant, show: bool) -> None:
    hass.data.setdefault(DOMAIN, {})["_sidebar_show"] = bool(show)
    _update_sidebar_panel(hass)


@callback
def _update_sidebar_panel(hass: HomeAssistant) -> None:
    """(Re)register the panel. The URL is always served; the sidebar entry
    appears only when show is True."""
    data = hass.data.setdefault(DOMAIN, {})
    show = bool(data.get("_sidebar_show")) and bool(data.get("_provisioned"))
    if data.get("_panel_registered") and data.get("_sidebar_shown") == show:
        return
    if data.get("_panel_registered"):
        try:
            frontend.async_remove_panel(hass, PANEL_URL_PATH)
        except Exception:  # noqa: BLE001
            pass
    try:
        frontend.async_register_built_in_panel(
            hass,
            component_name="custom",
            sidebar_title=PANEL_TITLE if show else None,
            sidebar_icon=PANEL_ICON if show else None,
            frontend_url_path=PANEL_URL_PATH,
            require_admin=True,
            config={
                "_panel_custom": {
                    "name": PANEL_ELEMENT,
                    "embed_iframe": False,
                    "trust_external": False,
                    "module_url": data.get("_module_url") or f"{PANEL_STATIC_URL}/{PANEL_JS}",
                }
            },
        )
        data["_panel_registered"] = True
        data["_sidebar_shown"] = show
    except Exception as exc:  # noqa: BLE001
        _LOGGER.warning("Could not register Ctrlable Store panel: %s", exc)
