"""Junos helpers aligned with the WP-001 extraction spec."""

from __future__ import annotations

import json
from typing import Dict, Iterable, Optional

from ..nautobot import DeviceRecord

_JUNOS_INDICATORS = {"juniper_junos", "junos", "juniper", "srx"}


def is_junos_device(device: DeviceRecord) -> bool:
    """Return True when the device uses the NAPALM Junos driver."""
    napalm_driver = (device.napalm_driver or "").lower()
    if napalm_driver:
        return napalm_driver == "junos"

    for candidate in (device.platform_name, device.platform_slug):
        if not isinstance(candidate, str):
            continue
        normalized = candidate.lower()
        if any(indicator in normalized for indicator in _JUNOS_INDICATORS):
            return True
    return False


def napalm_optional_args(device: DeviceRecord | None = None) -> dict[str, object]:
    """NETCONF connection defaults for Junos (NAPALM expects port 830)."""
    return {"port": 830}


def napalm_optional_args_for_junos(device: DeviceRecord | None = None) -> dict[str, object]:
    """Alias for clarity when Junos handling is explicit."""
    return napalm_optional_args(device)


def _run_cli_json(device_conn, command: str, logger=None) -> Optional[dict]:
    """Execute a Junos CLI command and return parsed JSON payload if available."""

    cli = getattr(device_conn, "cli", None)
    if not callable(cli):
        return None
    try:
        response = cli([command])
    except Exception as exc:  # pragma: no cover - defensive logging
        if logger:
            logger.debug(
                f"Junos CLI execution failed for '{command}': {exc}",
                extra={"grouping": "layer2-discovery"},
            )
        return None

    raw_payload = response.get(command) if isinstance(response, dict) else None
    if raw_payload is None:
        return None

    if isinstance(raw_payload, dict):
        return raw_payload

    if isinstance(raw_payload, str):
        try:
            return json.loads(raw_payload)
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive logging
            if logger:
                logger.debug(
                    f"Failed to decode Junos CLI JSON for '{command}': {exc}",
                    extra={"grouping": "layer2-discovery"},
                )
            return None
    return None


def _first_value(entry: dict, *keys: str) -> Optional[str]:
    """Return the first non-empty value for the provided keys."""
    for key in keys:
        value = entry.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            candidate = value.strip()
            if candidate:
                return candidate
        elif isinstance(value, (int, float)):
            return str(value)
    return None


def junos_cli_arp_entry(
    device_conn,
    ip_address: str,
    *,
    routing_instance: Optional[str] = None,
    logger=None,
) -> Optional[Dict[str, str]]:
    """Return a normalized ARP entry for ``ip_address`` using Junos CLI JSON."""

    base_command = "show arp no-resolve | display json"
    if routing_instance:
        base_command = f"show arp routing-instance {routing_instance} no-resolve | display json"

    payload = _run_cli_json(device_conn, base_command, logger=logger)
    if not payload:
        return None

    arp_info = payload.get("arp-table-information") or {}
    entries_raw = arp_info.get("arp-table-entry") or []
    if isinstance(entries_raw, dict):
        entries_raw = [entries_raw]
    if not isinstance(entries_raw, Iterable):
        return None

    for entry in entries_raw:
        if not isinstance(entry, dict):
            continue
        if _first_value(entry, "ip-address") != ip_address:
            continue
        mac = _first_value(entry, "mac-address")
        iface = _first_value(entry, "interface-name", "hostname")
        vlan = _first_value(entry, "arp-vlan", "vlan")
        age = _first_value(entry, "time-to-live", "ttl", "age")
        result: Dict[str, Optional[str]] = {
            "ip": ip_address,
            "mac": mac,
            "interface": iface,
            "vlan": vlan,
            "age": age,
        }
        # Filter out None values to keep payload minimal.
        return {k: v for k, v in result.items() if v is not None}
    return None


def _iterate_mac_entries(payload: dict) -> Iterable[dict]:
    """Yield MAC table entries from common Junos JSON structures."""

    eth_switching = payload.get("ethernet-switching-table")
    if isinstance(eth_switching, dict):
        entries = eth_switching.get("ethernet-switching-table-entry") or []
        if isinstance(entries, dict):
            entries = [entries]
        if isinstance(entries, Iterable):
            for entry in entries:
                if isinstance(entry, dict):
                    yield entry

    mac_db = payload.get("l2ng-l2ald-rtb-macdb") or payload.get("l2ng-l2ald-rtb-macdb-mac-detail")
    if isinstance(mac_db, dict):
        for table_entry in mac_db.values():
            if isinstance(table_entry, dict):
                mac_entries = table_entry.get("l2ng-l2ald-mac-entry") or table_entry.get("mac-entry")
                if isinstance(mac_entries, dict):
                    mac_entries = [mac_entries]
                if isinstance(mac_entries, Iterable):
                    for entry in mac_entries:
                        if isinstance(entry, dict):
                            yield entry


def junos_cli_mac_entry(
    device_conn,
    mac_address: str,
    *,
    logger=None,
) -> Optional[Dict[str, str]]:
    """Return a normalized MAC entry for ``mac_address`` using Junos CLI JSON."""

    commands = [
        f"show ethernet-switching table mac-address {mac_address} | display json",
        f"show bridge mac-table mac-address {mac_address} | display json",
    ]

    for command in commands:
        payload = _run_cli_json(device_conn, command, logger=logger)
        if not payload:
            continue

        target = mac_address.lower()
        for entry in _iterate_mac_entries(payload):
            mac_value = _first_value(entry, "mac-address", "mac")
            if not mac_value:
                continue
            if mac_value.lower() != target:
                continue
            interface = _first_value(entry, "logical-interface", "interface", "nh-local-interface", "hostname", "port")
            vlan = _first_value(entry, "vlan", "vlan-name", "vlan-id")
            result: Dict[str, Optional[str]] = {
                "mac": mac_value,
                "interface": interface,
                "vlan": vlan,
            }
            return {k: v for k, v in result.items() if v is not None}
    return None


def junos_cli_lldp_neighbors(device_conn, *, logger=None) -> Dict[str, list[Dict[str, Optional[str]]]]:
    """Return LLDP neighbors keyed by local interface using Junos CLI JSON."""

    payload = _run_cli_json(device_conn, "show lldp neighbors detail | display json", logger=logger)
    if not payload:
        return {}

    lldp_info = payload.get("lldp-neighbors-information") or {}
    entries = lldp_info.get("lldp-neighbor-information") or []
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, Iterable):
        return {}

    neighbors: Dict[str, list[Dict[str, Optional[str]]]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        local_if = _first_value(entry, "lldp-local-port-id", "lldp-local-interface")
        remote_name = _first_value(entry, "lldp-remote-system-name", "lldp-remote-chassis-id")
        remote_port = _first_value(entry, "lldp-remote-port-id", "lldp-remote-port-description")
        remote_port_desc = _first_value(entry, "lldp-remote-port-description")
        if not local_if:
            continue
        neighbors.setdefault(local_if, []).append(
            {
                "hostname": remote_name,
                "port": remote_port,
                "port_description": remote_port_desc,
                "local_interface": local_if,
            }
        )
    return neighbors
