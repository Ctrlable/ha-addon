"""Config flow for the Ctrlable Store (single instance + a Configure page)."""
from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import callback

from . import _load_sidebar_show, _save_sidebar_show, async_set_sidebar
from .const import DOMAIN


class CtrlableStoreConfigFlow(ConfigFlow, domain=DOMAIN):
    """Single-instance flow — added via the UI or auto-imported from YAML."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()
        return self.async_create_entry(title="Ctrlable Store", data={})

    async def async_step_import(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        return await self.async_step_user(user_input)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        return CtrlableStoreOptionsFlow()


class CtrlableStoreOptionsFlow(OptionsFlow):
    """Configure page — show/hide the Store in the sidebar."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            show = bool(user_input["show_in_sidebar"])
            await _save_sidebar_show(self.hass, show)
            async_set_sidebar(self.hass, show)
            return self.async_create_entry(title="", data={})
        current = await _load_sidebar_show(self.hass)
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema({vol.Required("show_in_sidebar", default=current): bool}),
        )
