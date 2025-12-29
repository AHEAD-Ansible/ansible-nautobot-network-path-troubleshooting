"""Unit tests for Junos layer-2 CLI fallbacks (WP-004)."""

from __future__ import annotations

import json
import sys
from types import SimpleNamespace

if "napalm" not in sys.modules:
    sys.modules["napalm"] = SimpleNamespace(get_network_driver=lambda *_args, **_kwargs: None)

from jobs.network_path_tracing import NetworkPathSettings
from jobs.network_path_tracing.interfaces.nautobot import DeviceRecord
from jobs.network_path_tracing.steps.layer2_discovery import Layer2Discovery


def _build_helper():
    """Return a minimally configured Layer2Discovery instance."""
    return Layer2Discovery(
        napalm_module=SimpleNamespace(),  # not used by these tests
        settings=NetworkPathSettings(),
        data_source=SimpleNamespace(get_device=lambda *_args, **_kwargs: None),
        logger=None,
        select_driver=lambda device: device.napalm_driver or "",
        driver_attempts=lambda name: (name,),
        optional_args_for=lambda name: {},
        collect_lldp_neighbors=lambda *_args, **_kwargs: {},
        normalize_interface=lambda name: name,
        normalize_hostname=lambda name: name,
    )


def test_junos_cli_arp_fallback():
    arp_payload = {
        "arp-table-information": {
            "arp-table-entry": [
                {
                    "ip-address": "198.51.100.1",
                    "mac-address": "aa:bb:cc:00:00:01",
                    "interface-name": "ge-0/0/0.0",
                }
            ]
        }
    }

    class FakeConn:
        def get_arp_table(self):
            raise NotImplementedError

        def cli(self, commands):
            return {commands[0]: json.dumps(arp_payload)}

    helper = _build_helper()
    device = DeviceRecord(name="srx-1", napalm_driver="junos", platform_name="Juniper SRX")

    entry = helper._lookup_arp_entry(FakeConn(), "198.51.100.1", device)
    assert entry is not None
    assert entry.get("mac") == "aa:bb:cc:00:00:01"
    assert entry.get("interface") == "ge-0/0/0.0"


def test_junos_cli_mac_fallback():
    mac_payload = {
        "ethernet-switching-table": {
            "ethernet-switching-table-entry": [
                {
                    "mac-address": "aa:bb:cc:00:00:02",
                    "logical-interface": "ge-0/0/1.0",
                    "vlan": "VLAN100",
                }
            ]
        }
    }

    class FakeConn:
        def get_mac_address_table(self):
            raise NotImplementedError

        def cli(self, commands):
            return {commands[0]: json.dumps(mac_payload)}

    helper = _build_helper()
    device = DeviceRecord(name="srx-1", napalm_driver="junos", platform_name="Juniper SRX")

    entry = helper._lookup_mac_entry(FakeConn(), "aa:bb:cc:00:00:02", device)
    assert entry is not None
    assert entry.get("mac") == "aa:bb:cc:00:00:02"
    assert entry.get("interface") == "ge-0/0/1.0"
    assert entry.get("vlan") == "VLAN100"
