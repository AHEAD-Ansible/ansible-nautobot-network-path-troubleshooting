"""Smoke helper to walk from the default gateway back toward the source via layer-2 discovery.

Edit the constants in this file to match your lab environment, then run:

    python tests/gateway_source_l2_smoke.py

The script will:
1. Validate the source/destination inputs using a lightweight static data source.
2. Resolve the default gateway via the existing GatewayDiscoveryStep.
3. Use the Layer2Discovery helper (via NextHopDiscoveryStep tooling) to follow LLDP/ARP breadcrumbs
   from the gateway toward the source, printing the resulting structure as JSON.
"""

from __future__ import annotations

import json
import logging
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Union

SITE_PACKAGES = Path(__file__).resolve().parents[1] / "venv" / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
if SITE_PACKAGES.exists() and str(SITE_PACKAGES) not in sys.path:
    sys.path.insert(0, str(SITE_PACKAGES))

# Stub out minimal Django modules so package imports don't fail when Django isn't installed.
if "django" not in sys.modules:
    django_module = types.ModuleType("django")
    django_core = types.ModuleType("django.core")
    django_core_exceptions = types.ModuleType("django.core.exceptions")

    class FieldError(Exception):
        """Stub FieldError used by Nautobot ORM helpers."""

        pass

    django_core_exceptions.FieldError = FieldError
    django_core.exceptions = django_core_exceptions
    django_module.core = django_core

    sys.modules["django"] = django_module
    sys.modules["django.core"] = django_core
    sys.modules["django.core.exceptions"] = django_core_exceptions

# Provide a minimal networkx stub so modules importing NetworkPathGraph don't fail
if "networkx" not in sys.modules:
    networkx_module = types.ModuleType("networkx")

    class _StubMultiDiGraph:
        def __init__(self) -> None:
            self._nodes: Dict[str, Dict[str, object]] = {}
            self._edges: list[tuple[str, str, Optional[str], Dict[str, object]]] = []

        def add_node(self, node_id: str, **attrs: object) -> None:
            self._nodes.setdefault(node_id, {}).update(attrs)

        def nodes(self, data: bool = False):
            return list(self._nodes.items()) if data else list(self._nodes.keys())

        def add_edge(
            self,
            source: str,
            target: str,
            key: Optional[str] = None,
            **attrs: object,
        ) -> None:
            self._edges.append((source, target, key, dict(attrs)))

        def edges(self, keys: bool = False, data: bool = False):
            result = []
            for source, target, key, attrs in self._edges:
                entry = [source, target]
                if keys:
                    entry.append(key)
                if data:
                    entry.append(attrs)
                result.append(tuple(entry))
            return result

        def neighbors(self, node_id: str):
            for source, target, _, _ in self._edges:
                if source == node_id:
                    yield target

        def number_of_nodes(self) -> int:
            return len(self._nodes)

        def get_edge_data(self, source: str, target: str, default=None):
            payload = {}
            for idx, (src, dst, key, attrs) in enumerate(self._edges):
                if src == source and dst == target:
                    payload[key or idx] = attrs
            return payload or default

    networkx_module.MultiDiGraph = _StubMultiDiGraph
    sys.modules["networkx"] = networkx_module

try:
    import napalm as _napalm_module
except ImportError:  # noqa: F401 - handled downstream
    _napalm_module = None

from jobs.network_path_tracing.config import (
    NetworkPathSettings,
    NapalmSettings,
)
from jobs.network_path_tracing.interfaces.nautobot import (
    DeviceRecord,
    IPAddressRecord,
    NautobotDataSource,
    PrefixRecord,
    RedundancyMember,
    RedundancyResolution,
)
from jobs.network_path_tracing.steps.gateway_discovery import (
    GatewayDiscoveryStep,
    GatewayDiscoveryResult,
)
from jobs.network_path_tracing.steps.input_validation import (
    InputValidationResult,
    InputValidationStep,
)
from jobs.network_path_tracing.steps.next_hop_discovery import (
    NextHopDiscoveryStep,
    NextHopDiscoveryError,
)
import jobs.network_path_tracing.steps.next_hop_discovery as nhd

if _napalm_module is not None:
    nhd.napalm = _napalm_module



# --------------------------------------------------------------------------------------
# Configure your lab-specific values here.
# --------------------------------------------------------------------------------------

SOURCE_IP = "10.100.100.100"
DESTINATION_IP = "10.200.200.200"

# Gateway device (where the script will start the upstream layer-2 walk)
GATEWAY_DEVICE = DeviceRecord(
    name="Catalyst-1",
    primary_ip="192.168.100.72",  # management / Napalm IP
    platform_slug="cisco_ios",
)

# Intermediate switch expected between gateway and source
L2_SWITCH = DeviceRecord(
    name="L2-Switch-1",
    primary_ip="192.168.100.70",
    platform_slug="cisco_ios",
)

# Source endpoint (host) representation
SOURCE_DEVICE = DeviceRecord(
    name="Server-1",
    primary_ip=None,
    platform_slug=None,
)

# Static IP address registry (minimal Nautobot substitute)
IP_RECORDS: Dict[str, IPAddressRecord] = {
    SOURCE_IP: IPAddressRecord(
        address=SOURCE_IP,
        prefix_length=24,
        device_name=SOURCE_DEVICE.name,
        interface_name="eth1",
    ),
    "10.100.100.1": IPAddressRecord(
        address="10.100.100.1",
        prefix_length=24,
        device_name=GATEWAY_DEVICE.name,
        interface_name="Vlan100",
    ),
}

# Static prefix record for the source subnet
SOURCE_PREFIX = PrefixRecord(prefix="10.100.100.0/24")

# Napalm credentials used for every device connection opened by the smoke test.
NAPALM_USERNAME = "admin-ro"
NAPALM_PASSWORD = "Labl@b!234"


# --------------------------------------------------------------------------------------
# Minimal Nautobot data source implementation backed by the static tables above.
# --------------------------------------------------------------------------------------

@dataclass
class StaticDataSource(NautobotDataSource):
    """Simple in-memory data source to satisfy the NautobotDataSource protocol."""

    devices: Dict[str, DeviceRecord]
    ip_records: Dict[str, IPAddressRecord]
    prefix_record: PrefixRecord

    def get_ip_address(self, address: str) -> Optional[IPAddressRecord]:
        return self.ip_records.get(address)

    def get_most_specific_prefix(self, address: str) -> Optional[PrefixRecord]:
        # Only a single prefix is needed for this smoke helper.
        if address.startswith(self.prefix_record.prefix.split("/")[0].rsplit(".", 1)[0]):
            return self.prefix_record
        return None

    def find_gateway_ip(
        self, prefix: PrefixRecord, custom_field: str
    ) -> Optional[IPAddressRecord]:
        # Return the statically-defined gateway inside the source prefix.
        return self.ip_records.get("10.100.100.1")

    def get_device(self, name: str) -> Optional[DeviceRecord]:
        return self.devices.get(name)

    def get_interface_ip(self, device_name: str, interface_name: str) -> Optional[IPAddressRecord]:
        # Not required for this smoke helper.
        return None

    def resolve_redundant_gateway(
        self, address: str
    ) -> Optional[Union[RedundancyResolution, IPAddressRecord]]:
        # No redundancy handling in this minimal example.
        return None


# --------------------------------------------------------------------------------------
# Smoke workflow
# --------------------------------------------------------------------------------------

def discover_gateway_and_layer2(
    data_source: StaticDataSource,
    settings: NetworkPathSettings,
    logger: logging.Logger,
) -> dict:
    """Run gateway discovery and upstream layer-2 discovery."""

    # Step 1: validate the source/destination inputs using the static data source.
    validation = InputValidationStep(data_source).run(settings)

    # Step 2: discover the gateway using the same step the main job relies on.
    gateway_step = GatewayDiscoveryStep(data_source, settings.gateway_custom_field)
    gateway = gateway_step.run(validation)
    if not gateway.found or not gateway.gateway:
        raise RuntimeError("Gateway discovery failed; check static data source definitions.")

    logger.info(
        "Gateway resolved: %s (%s) via %s",
        gateway.gateway.device_name,
        gateway.gateway.interface_name,
        gateway.method,
    )

    # Prepare the next-hop step so we can reuse its driver selection + LLDP helpers.
    next_hop_step = NextHopDiscoveryStep(data_source, settings, logger)
    layer2_hops = next_hop_step.discover_layer2_path(
        device_name=gateway.gateway.device_name,
        egress_interface=gateway.gateway.interface_name,
        target_ip=validation.source_ip,
    ) or []
    if not layer2_hops:
        logger.warning(
            "Layer-2 path between %s and source %s could not be determined.",
            gateway.gateway.device_name,
            validation.source_ip,
        )

    payload = {
        "source": {
            "ip": validation.source_ip,
            "device": validation.source_record.device_name,
            "interface": validation.source_record.interface_name,
        },
        "destination": {
            "ip": validation.destination_ip,
        },
        "gateway": {
            "ip": gateway.gateway.address,
            "device": gateway.gateway.device_name,
            "interface": gateway.gateway.interface_name,
            "details": gateway.details,
            "method": gateway.method,
        },
        "layer2_hops": layer2_hops,
    }
    return payload


def main() -> None:
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
    logger = logging.getLogger("gateway_source_l2_smoke")
    logger.setLevel(logging.DEBUG)

    logger.debug("napalm module: %s", nhd.napalm)

    devices = {
        GATEWAY_DEVICE.name: GATEWAY_DEVICE,
        L2_SWITCH.name: L2_SWITCH,
        SOURCE_DEVICE.name: SOURCE_DEVICE,
    }
    data_source = StaticDataSource(
        devices=devices,
        ip_records=IP_RECORDS,
        prefix_record=SOURCE_PREFIX,
    )

    settings = NetworkPathSettings(
        source_ip=SOURCE_IP,
        destination_ip=DESTINATION_IP,
        napalm=NapalmSettings(username=NAPALM_USERNAME, password=NAPALM_PASSWORD),
        enable_layer2_discovery=True,
    )

    try:
        payload = discover_gateway_and_layer2(data_source, settings, logger)
    except NextHopDiscoveryError as exc:
        logger.error("Smoke test failed during next-hop discovery: %s", exc)
        raise SystemExit(1) from exc
    except Exception as exc:  # pragma: no cover - smoke helper debugging
        logger.error("Smoke test failed: %s", exc)
        raise SystemExit(1) from exc

    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
