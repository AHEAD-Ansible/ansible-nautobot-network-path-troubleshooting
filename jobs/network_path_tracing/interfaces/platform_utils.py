"""Helpers for determining device platform characteristics and NAPALM behaviors."""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from .nautobot import DeviceRecord


_NXOS_DRIVERS = {"nxos", "nxos_ssh"}
_PALO_ALTO_INDICATORS = {"palo", "panos", "palo_alto"}
_F5_INDICATORS = {"f5", "bigip"}


def is_palo_alto(device: DeviceRecord) -> bool:
    """Return True if the device appears to be Palo Alto based on platform hints."""
    platform_slug = (device.platform_slug or "").lower()
    platform_name = (device.platform_name or "").lower()
    return any(
        indicator in platform_slug or indicator in platform_name
        for indicator in _PALO_ALTO_INDICATORS
    )


def is_f5_bigip(device: DeviceRecord) -> bool:
    """Return True if the device appears to be an F5 BIG-IP."""
    platform_slug = (device.platform_slug or "").lower()
    platform_name = (device.platform_name or "").lower()
    return any(
        indicator in platform_slug or indicator in platform_name
        for indicator in _F5_INDICATORS
    )


def select_napalm_driver(device: DeviceRecord) -> str:
    """Determine the appropriate NAPALM driver name for a device."""
    driver_map = {
        "ios": "ios",
        "cisco_ios": "ios",
        "iosxe": "ios",
        "cisco_iosxe": "ios",
        "nxos": "nxos",
        "nxos_ssh": "nxos_ssh",
        "cisco_nxos": "nxos",
        "eos": "eos",
        "arista_eos": "eos",
        "junos": "junos",
        "panos": "panos",
        "palo_alto_panos": "panos",
    }

    if device.napalm_driver:
        normalized = device.napalm_driver.lower()
        return driver_map.get(normalized, device.napalm_driver)

    for candidate in (device.platform_slug, device.platform_name):
        if isinstance(candidate, str):
            normalized = candidate.lower()
            if normalized in driver_map:
                return driver_map[normalized]

    return "ios"


def napalm_driver_attempts(initial: str) -> List[str]:
    """Return the list of NAPALM driver names to try, including fallbacks."""
    attempts = [initial]
    if initial == "nxos":
        attempts.append("nxos_ssh")
    elif initial == "nxos_ssh":
        attempts.append("nxos")
    return attempts


def napalm_optional_args(driver_name: str) -> Dict[str, object]:
    """Return driver-specific optional arguments for NAPALM sessions."""
    if driver_name == "nxos":
        return {"port": 443, "verify": False}
    if driver_name == "nxos_ssh":
        return {"port": 22}
    if driver_name in {"ios", "eos", "junos", "arista_eos", "cisco_ios"}:
        return {"port": 22}
    return {}


def napalm_requires_enable(driver_name: str) -> bool:
    """Return True if the driver typically expects an enable/secret password."""
    return driver_name in {"ios", "cisco_ios"}


def nxos_drivers() -> Iterable[str]:
    """Expose the set of NAPALM driver names used for NX-OS (for downstream checks)."""
    return set(_NXOS_DRIVERS)
