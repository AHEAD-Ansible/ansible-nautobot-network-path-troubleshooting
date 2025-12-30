"""Unit tests for Junos layer-2 CLI fallbacks (WP-004)."""

from __future__ import annotations

import json
import sys
from types import SimpleNamespace

if "napalm" not in sys.modules:
    sys.modules["napalm"] = SimpleNamespace(get_network_driver=lambda *_args, **_kwargs: None)

from jobs.network_path_tracing import NetworkPathSettings
from jobs.network_path_tracing.interfaces.juniper import junos_cli_lldp_neighbors
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


def test_junos_cli_lldp_fallback_parses_json():
    lldp_payload = {
        "lldp-neighbors-information": {
            "lldp-neighbor-information": [
                {
                    "lldp-local-port-id": "ge-0/0/0",
                    "lldp-remote-system-name": "leaf-1",
                    "lldp-remote-port-id": "et-0/0/1",
                    "lldp-remote-port-description": "uplink",
                }
            ]
        }
    }

    class FakeConn:
        def cli(self, commands):
            return {commands[0]: json.dumps(lldp_payload)}

    neighbors = junos_cli_lldp_neighbors(FakeConn())
    assert list(neighbors) == ["ge-0/0/0"]
    assert neighbors["ge-0/0/0"][0]["hostname"] == "leaf-1"
    assert neighbors["ge-0/0/0"][0]["port"] == "et-0/0/1"
    assert neighbors["ge-0/0/0"][0]["port_description"] == "uplink"


def test_junos_cli_lldp_fallback_parses_xml_when_json_fails():
    json_cmd = "show lldp neighbors detail | display json"
    xml_cmd = "show lldp neighbors detail | display xml"
    xml_payload = """\
<rpc-reply>
  <lldp-neighbors-information>
    <lldp-neighbor-information>
      <lldp-local-port-id>ge-0/0/0</lldp-local-port-id>
      <lldp-remote-system-name>leaf-2</lldp-remote-system-name>
      <lldp-remote-port-id>et-0/0/2</lldp-remote-port-id>
      <lldp-remote-port-description>uplink-2</lldp-remote-port-description>
    </lldp-neighbor-information>
  </lldp-neighbors-information>
</rpc-reply>
"""

    class FakeConn:
        def cli(self, commands):
            cmd = commands[0]
            if cmd == json_cmd:
                return {cmd: "No LLDP neighbors found."}
            if cmd == xml_cmd:
                return {cmd: xml_payload}
            raise AssertionError(f"Unexpected CLI command: {cmd}")

    neighbors = junos_cli_lldp_neighbors(FakeConn())
    assert list(neighbors) == ["ge-0/0/0"]
    assert neighbors["ge-0/0/0"][0]["hostname"] == "leaf-2"
    assert neighbors["ge-0/0/0"][0]["port"] == "et-0/0/2"
    assert neighbors["ge-0/0/0"][0]["port_description"] == "uplink-2"


def test_layer2_discovery_prioritizes_base_interface_for_subinterfaces():
    helper = _build_helper()
    neighbors = {
        "ae0": [{"hostname": "sw-ae0", "local_interface": "ae0"}],
        "ge-0/0/0": [{"hostname": "sw-ge0", "local_interface": "ge-0/0/0"}],
    }

    candidates = helper._candidate_neighbors_for_interface(neighbors, "ge-0/0/0.88")
    assert candidates
    assert candidates[0].get("hostname") == "sw-ge0"
