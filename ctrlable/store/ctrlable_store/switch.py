"""'Show in sidebar' switch for the Ctrlable Store."""
from __future__ import annotations

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import _save_sidebar_show, async_set_sidebar
from .const import DOMAIN, PANEL_TITLE


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    async_add_entities([SidebarSwitch(hass, entry)])


class SidebarSwitch(SwitchEntity):
    _attr_has_entity_name = True
    _attr_name = "Show in sidebar"
    _attr_icon = "mdi:dock-left"

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self._hass = hass
        self._attr_unique_id = f"{entry.entry_id}_show_in_sidebar"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=PANEL_TITLE,
            manufacturer="Ctrlable",
            configuration_url="homeassistant://ctrlable-store",
        )

    @property
    def is_on(self) -> bool:
        return bool(self._hass.data.get(DOMAIN, {}).get("_sidebar_show"))

    async def async_turn_on(self, **kwargs) -> None:
        await _save_sidebar_show(self._hass, True)
        async_set_sidebar(self._hass, True)
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs) -> None:
        await _save_sidebar_show(self._hass, False)
        async_set_sidebar(self._hass, False)
        self.async_write_ha_state()
