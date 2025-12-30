"""Unit tests for individual network path tracing steps."""

import json
import sys
import xml.etree.ElementTree as ET
from types import SimpleNamespace
from typing import Any

import pytest

if "napalm" not in sys.modules:
    sys.modules["napalm"] = SimpleNamespace(get_network_driver=lambda *_args, **_kwargs: None)

from jobs.network_path_tracing import NetworkPathSettings, NapalmSettings, F5Settings, PaloAltoSettings
from jobs.network_path_tracing import GatewayDiscoveryError, InputValidationError
from jobs.network_path_tracing.interfaces.nautobot import (
    IPAddressRecord,
    PrefixRecord,
    DeviceRecord,
    RedundancyMember,
    RedundancyResolution,
)
from jobs.network_path_tracing.interfaces.nautobot_api import NautobotAPIDataSource, NautobotAPISettings
from jobs.network_path_tracing.steps import (
    GatewayDiscoveryResult,
    GatewayDiscoveryStep,
    InputValidationResult,
    InputValidationStep,
    NextHopDiscoveryResult,
    NextHopDiscoveryStep,
    PathTracingStep,
)
from jobs.network_path_tracing.steps.layer2_discovery import Layer2Discovery
import jobs.network_path_tracing.steps.next_hop_discovery as next_hop_module
from jobs.network_path_tracing.interfaces.f5_bigip import F5NextHopSummary


class FakeDataSource:
    """Minimal Nautobot data source used to exercise step logic."""

    def __init__(
        self,
        ip_records: dict[str, IPAddressRecord],
        prefix_record: PrefixRecord | None,
        gateway_record: IPAddressRecord | None = None,
        redundancy_resolution: RedundancyResolution | None = None,
    ) -> None:
        self._ip_records = ip_records
        self._prefix_record = prefix_record
        self._gateway_record = gateway_record
        self.last_gateway_lookup = None
        self._redundancy_resolution = redundancy_resolution

    def get_ip_address(self, address: str) -> IPAddressRecord | None:
        return self._ip_records.get(address)

    def get_most_specific_prefix(self, address: str) -> PrefixRecord | None:
        return self._prefix_record

    def find_gateway_ip(
        self, prefix: PrefixRecord, custom_field: str
    ) -> IPAddressRecord | None:  # noqa: ARG002
        self.last_gateway_lookup = prefix
        return self._gateway_record

    def get_device(self, name: str):  # pragma: no cover - not used in these tests
        for record in self._ip_records.values():
            if record.device_name == name:
                return DeviceRecord(name=name)
        return None

    def get_interface_ip(self, device_name: str, interface_name: str) -> IPAddressRecord | None:
        for record in self._ip_records.values():
            if record.device_name == device_name and record.interface_name == interface_name:
                return record
        return None

    def resolve_redundant_gateway(self, address: str):  # noqa: D401
        return self._redundancy_resolution


def test_nautobot_api_interface_vrf_lookup():
    """REST API interface lookup should return VRF name even when IP record lacks it."""

    settings = NautobotAPISettings(base_url="http://nautobot.local", token="test-token")
    ds = NautobotAPIDataSource(settings)

    interface_payload = {
        "results": [
            {
                "name": "Vlan889",
                "device": {"name": "Cat-1"},
                "vrf": {
                    "id": "cb441273-4cad-41a7-b121-327fd8a59a35",
                    "url": "/api/ipam/vrfs/cb441273-4cad-41a7-b121-327fd8a59a35/",
                },
                "ip_addresses": [
                    {
                        "id": "39231011-a71c-48e2-847d-a802004541cf",
                        "address": "10.8.99.1/24",
                    }
                ],
            }
        ]
    }

    ip_payload = {
        "id": "39231011-a71c-48e2-847d-a802004541cf",
        "address": "10.8.99.1/24",
        "assigned_object": {
            "name": "Vlan889",
            "device": {"name": "Cat-1"},
        },
    }

    vrf_payload = {"name": "VRF-Test"}

    class DummySession:
        def __init__(self):
            self.calls = []

        def get_json(self, path, params=None):
            self.calls.append((path, params))
            if path == "/api/dcim/interfaces/":
                return interface_payload
            if path == "/api/ipam/ip-addresses/39231011-a71c-48e2-847d-a802004541cf/":
                return ip_payload
            if path in {
                "/api/ipam/vrfs/cb441273-4cad-41a7-b121-327fd8a59a35/",
                "http://nautobot.local/api/ipam/vrfs/cb441273-4cad-41a7-b121-327fd8a59a35/",
            }:
                return vrf_payload
            raise AssertionError(f"Unexpected path {path}")

    ds._session = DummySession()

    record = ds.get_interface_ip("Cat-1", "Vlan889")
    assert record
    assert record.vrf == "VRF-Test"


@pytest.fixture
def default_settings() -> NetworkPathSettings:
    return NetworkPathSettings(
        source_ip="10.10.10.10",
        destination_ip="10.20.20.20",
    )


@pytest.fixture
def prefix_record() -> PrefixRecord:
    return PrefixRecord(prefix="10.10.10.0/24", status="active", id="prefix-uuid")


@pytest.fixture
def source_ip_record() -> IPAddressRecord:
    return IPAddressRecord(
        address="10.10.10.10",
        prefix_length=24,
        device_name="server-1",
        interface_name="eth0",
    )


def test_input_validation_success(default_settings, prefix_record, source_ip_record):
    data_source = FakeDataSource(
        ip_records={source_ip_record.address: source_ip_record},
        prefix_record=prefix_record,
    )

    step = InputValidationStep(data_source)
    result = step.run(default_settings)

    assert result.source_ip == "10.10.10.10"
    assert result.source_prefix == prefix_record
    assert result.source_record == source_ip_record
    assert result.is_host_ip is False
    assert result.source_found is True


def test_input_validation_missing_ip(default_settings, prefix_record):
    data_source = FakeDataSource(ip_records={}, prefix_record=prefix_record)
    step = InputValidationStep(data_source)

    result = step.run(default_settings)

    assert result.source_found is False
    assert result.source_record.device_name is None
    assert result.source_record.interface_name is None
    assert result.source_record.prefix_length == 24
    assert result.source_prefix == prefix_record
    assert result.is_host_ip is False


def test_input_validation_missing_prefix(default_settings, source_ip_record):
    data_source = FakeDataSource(
        ip_records={source_ip_record.address: source_ip_record},
        prefix_record=None,
    )
    step = InputValidationStep(data_source)

    with pytest.raises(InputValidationError) as excinfo:
        step.run(default_settings)

    assert "No containing prefix" in str(excinfo.value)


def test_gateway_direct_host(prefix_record, source_ip_record):
    validation = build_validation_result(prefix_record, source_ip_record, is_host=True)

    step = GatewayDiscoveryStep(FakeDataSource({}, prefix_record), "network_gateway")
    result = step.run(validation)

    assert result.method == "direct_host"
    assert result.gateway == source_ip_record


def test_gateway_custom_field(prefix_record, source_ip_record):
    gateway_record = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name="gw-1",
        interface_name="Gig0/0",
    )
    data_source = FakeDataSource(
        ip_records={},
        prefix_record=prefix_record,
        gateway_record=gateway_record,
    )

    validation = build_validation_result(prefix_record, source_ip_record, is_host=False)

    step = GatewayDiscoveryStep(data_source, "network_gateway")
    result = step.run(validation)

    assert result.method == "custom_field"
    assert result.gateway == gateway_record
    assert "network_gateway" in (result.details or "")


def test_gateway_custom_field_source_missing(default_settings, prefix_record):
    gateway_record = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name="gw-1",
        interface_name="Gig0/0",
    )
    data_source = FakeDataSource(
        ip_records={},
        prefix_record=prefix_record,
        gateway_record=gateway_record,
    )

    validation = InputValidationStep(data_source).run(default_settings)

    assert validation.source_found is False
    step = GatewayDiscoveryStep(data_source, "network_gateway")
    result = step.run(validation)

    assert result.method == "custom_field"
    assert result.gateway == gateway_record


def test_gateway_custom_field_hsrp_fallback(prefix_record, source_ip_record):
    base_gateway_record = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name=None,
        interface_name=None,
    )
    redundant_gateway = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name="hsrp-device",
        interface_name="Gig0/2",
    )
    resolution = RedundancyResolution(
        preferred=redundant_gateway,
        members=(
            RedundancyMember(
                device_name="hsrp-device",
                interface_name="Gig0/2",
                priority=110,
                is_preferred=True,
            ),
            RedundancyMember(
                device_name="hsrp-backup",
                interface_name="Gig0/3",
                priority=90,
                is_preferred=False,
            ),
        ),
    )

    data_source = FakeDataSource(
        ip_records={},
        prefix_record=prefix_record,
        gateway_record=base_gateway_record,
        redundancy_resolution=resolution,
    )

    validation = build_validation_result(prefix_record, source_ip_record, is_host=False)
    step = GatewayDiscoveryStep(data_source, "network_gateway")
    result = step.run(validation)

    assert result.method == "hsrp"
    assert result.gateway == redundant_gateway
    assert "interface redundancy" in result.details.lower()
    assert len(result.redundant_members) == 2
    assert any(member.is_preferred for member in result.redundant_members)


def test_gateway_fallback_to_lowest_host(prefix_record, source_ip_record):
    fallback_gateway = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name="gw-fallback",
        interface_name="Gig0/1",
    )
    data_source = FakeDataSource(
        ip_records={fallback_gateway.address: fallback_gateway},
        prefix_record=prefix_record,
        gateway_record=None,
    )

    validation = build_validation_result(prefix_record, source_ip_record, is_host=False)

    step = GatewayDiscoveryStep(data_source, "network_gateway")
    result = step.run(validation)

    assert result.method == "lowest_host"
    assert result.gateway == fallback_gateway
    assert "fallback" in (result.details or "").lower()
    assert "gw-fallback" in (result.details or "")


def test_gateway_lowest_host_resolves_redundancy(prefix_record, source_ip_record):
    fallback_gateway = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name=None,
        interface_name=None,
    )
    preferred = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name="gw-active",
        interface_name="Gig0/1",
    )
    resolution = RedundancyResolution(
        preferred=preferred,
        members=(
            RedundancyMember(
                device_name="gw-active",
                interface_name="Gig0/1",
                priority=110,
                is_preferred=True,
            ),
            RedundancyMember(
                device_name="gw-standby",
                interface_name="Gig0/2",
                priority=100,
                is_preferred=False,
            ),
        ),
    )

    data_source = FakeDataSource(
        ip_records={fallback_gateway.address: fallback_gateway},
        prefix_record=prefix_record,
        gateway_record=None,
        redundancy_resolution=resolution,
    )

    validation = build_validation_result(prefix_record, source_ip_record, is_host=False)

    step = GatewayDiscoveryStep(data_source, "network_gateway")
    result = step.run(validation)

    assert result.method == "lowest_host"
    assert result.gateway.device_name == "gw-active"
    assert len(result.redundant_members) == 2
    assert any(member.is_preferred for member in result.redundant_members)
    assert "interface redundancy" in result.details.lower()


def test_gateway_missing_data_raises(prefix_record, source_ip_record):
    small_prefix = PrefixRecord(prefix="10.10.10.0/30", status="active", id="pfx-small")
    validation = build_validation_result(small_prefix, source_ip_record, is_host=False)

    data_source = FakeDataSource(ip_records={}, prefix_record=small_prefix, gateway_record=None)
    step = GatewayDiscoveryStep(data_source, "network_gateway")

    with pytest.raises(GatewayDiscoveryError):
        step.run(validation)


def test_gateway_lowest_host_requires_existing_ip(prefix_record, source_ip_record):
    validation = build_validation_result(prefix_record, source_ip_record, is_host=False)
    data_source = FakeDataSource(ip_records={}, prefix_record=prefix_record, gateway_record=None)
    step = GatewayDiscoveryStep(data_source, "network_gateway")

    result = step.run(validation)

    assert result.method == "lowest_host"
    assert result.gateway.address == "10.10.10.1"
    assert result.gateway.device_name is None
    assert "not present" in (result.details or "").lower()
    assert "fallback" in (result.details or "").lower()


def build_validation_result(
    prefix: PrefixRecord,
    record: IPAddressRecord,
    is_host: bool,
    *,
    source_found: bool = True,
) -> InputValidationResult:
    return InputValidationResult(
        source_ip=record.address,
        destination_ip="10.20.20.20",
        source_record=record,
        source_prefix=prefix,
        is_host_ip=is_host,
        source_found=source_found,
    )


class PathDataSource(FakeDataSource):
    """Data source that only needs get_ip_address for path tracing tests."""

    def __init__(
        self,
        ip_records: dict[str, IPAddressRecord],
        prefix_record: PrefixRecord | None = None,
        gateway_record: IPAddressRecord | None = None,
    ) -> None:
        super().__init__(
            ip_records=ip_records,
            prefix_record=prefix_record,
            gateway_record=gateway_record,
        )


@pytest.fixture
def path_gateway() -> GatewayDiscoveryResult:
    gateway = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name="edge-1",
        interface_name="Gig0/0",
    )
    return GatewayDiscoveryResult(found=True, method="custom", gateway=gateway)


@pytest.fixture
def path_validation(source_ip_record, prefix_record) -> InputValidationResult:
    return build_validation_result(prefix_record, source_ip_record, is_host=False)


def test_path_tracing_reaches_destination(default_settings, path_gateway, path_validation):
    """Path tracing should record a successful hop when next-hop equals destination."""

    next_hop_result = NextHopDiscoveryResult(
        found=True,
        next_hops=[{
            "next_hop_ip": default_settings.destination_ip,
            "egress_interface": "Gig0/1",
            "probe": "f5",
        }],
        details="direct",
    )

    dest_record = IPAddressRecord(
        address=default_settings.destination_ip,
        prefix_length=32,
        device_name="dest-host",
        interface_name="eth0",
    )
    vrf_record = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name="edge-1",
        interface_name="Gig0/1",
        vrf="VRF-Test",
    )
    data_source = PathDataSource(
        ip_records={
            default_settings.destination_ip: dest_record,
            vrf_record.address: vrf_record,
        }
    )
    class StubNextHopStep:
        def run(self, *_args, **_kwargs):  # noqa: D401
            return next_hop_result

    step = PathTracingStep(data_source, default_settings, StubNextHopStep())

    result = step.run(path_validation, path_gateway)

    assert len(result.paths) == 1
    path = result.paths[0]
    assert path.reached_destination is True
    assert len(path.hops) == 2
    assert path.hops[0].next_hop_ip == default_settings.destination_ip
    assert path.hops[1].device_name == "dest-host"
    assert path.hops[1].details == "Destination device resolved via Nautobot"
    assert path.hops[0].extras == {"probe": "f5"}
    assert path.hops[1].extras == {}
    assert path.hops[0].egress_vrf == "VRF-Test"
    serialized_edges = result.graph.serialize()["edges"]
    assert any(edge.get("egress_vrf") == "VRF-Test" for edge in serialized_edges)


def test_path_tracing_uses_layer2_gateway_for_egress(default_settings, path_gateway, path_validation):
    """Egress interface should fall back to layer-2 gateway interface when missing."""

    next_hop_ip = "10.30.30.30"
    next_hop_result = NextHopDiscoveryResult(
        found=True,
        next_hops=[{
            "next_hop_ip": next_hop_ip,
            "egress_interface": None,
            "layer2_hops": [
                {
                    "device_name": "Switch-Edge",
                    "ingress_interface": "Eth1/1",
                    "egress_interface": "Eth1/2",
                    "gateway_interface": "Gig0/5",
                    "mac_address": "aa:bb:cc:dd:ee:11",
                }
            ],
        }],
        details="via l2",
    )

    data_source = PathDataSource(ip_records={})

    class StubNextHopStep:
        def run(self, *_args, **_kwargs):  # noqa: D401
            return next_hop_result

    step = PathTracingStep(data_source, default_settings, StubNextHopStep())

    result = step.run(path_validation, path_gateway)

    hop = result.paths[0].hops[0]
    assert hop.egress_interface == "Gig0/5"


def test_path_tracing_blackhole(default_settings, path_gateway, path_validation):
    """Path tracing should flag routing blackholes when no next hop is found."""

    next_hop_result = NextHopDiscoveryResult(found=False, next_hops=[], details="no route")

    data_source = PathDataSource(ip_records={})
    class StubNextHopStep:
        def run(self, *_args, **_kwargs):  # noqa: D401
            return next_hop_result

    step = PathTracingStep(data_source, default_settings, StubNextHopStep())

    result = step.run(path_validation, path_gateway)

    assert len(result.paths) == 1
    path = result.paths[0]
    assert path.reached_destination is False
    assert any("blackhole" in issue for issue in path.issues)
    assert path.hops[0].details == "no route"
    assert result.graph is not None
    nodes = {n["id"]: n for n in result.graph.serialize()["nodes"]}
    assert any(node.get("error") for node in nodes.values())


def test_path_tracing_multiple_hops(default_settings, path_gateway, path_validation):
    """Path tracing should follow multiple hops until the destination is reached."""

    hop_sequence = [
        NextHopDiscoveryResult(
            found=True,
            next_hops=[{"next_hop_ip": "10.10.20.1", "egress_interface": "Gig0/1"}],
            details="toward agg",
        ),
        NextHopDiscoveryResult(
            found=True,
            next_hops=[{"next_hop_ip": default_settings.destination_ip, "egress_interface": "Gig0/2"}],
            details="toward dest",
        ),
    ]

    dest_record = IPAddressRecord(
        address=default_settings.destination_ip,
        prefix_length=32,
        device_name="dest-host",
        interface_name="eth0",
    )
    data_source = PathDataSource(
        ip_records={
            "10.10.20.1": IPAddressRecord(
                address="10.10.20.1",
                prefix_length=24,
                device_name="agg-1",
                interface_name="Gig1/0",
            ),
            default_settings.destination_ip: dest_record,
        }
    )
    class SequencedNextHopStep:
        def run(self, *_args, **_kwargs):  # noqa: D401
            if hop_sequence:
                return hop_sequence.pop(0)
            return NextHopDiscoveryResult(found=False, next_hops=[], details="exhausted")

    step = PathTracingStep(data_source, default_settings, SequencedNextHopStep())

    result = step.run(path_validation, path_gateway)

    assert len(result.paths) == 1
    path = result.paths[0]
    assert path.reached_destination is True
    assert len(path.hops) == 3
    assert path.hops[0].next_hop_ip == "10.10.20.1"
    assert path.hops[1].next_hop_ip == default_settings.destination_ip
    assert path.hops[2].device_name == "dest-host"


def test_path_tracing_destination_info_missing(default_settings, path_gateway, path_validation):
    """Destination hop should be appended even when Nautobot lacks device info."""

    next_hop_result = NextHopDiscoveryResult(
        found=True,
        next_hops=[{"next_hop_ip": default_settings.destination_ip, "egress_interface": "Gig0/1"}],
        details="direct",
    )

    data_source = PathDataSource(ip_records={})

    class StubNextHopStep:
        def run(self, *_args, **_kwargs):  # noqa: D401
            return next_hop_result

    step = PathTracingStep(data_source, default_settings, StubNextHopStep())

    result = step.run(path_validation, path_gateway)

    path = result.paths[0]
    assert path.reached_destination is True
    assert len(path.hops) == 2
    assert path.hops[-1].device_name == "device_info: Not Found"
    assert "not found" in path.hops[-1].details.lower()


def test_path_tracing_local_subnet_via_interface(prefix_record, source_ip_record):
    """Treat lack of next-hop as success when destination shares the egress subnet."""

    settings = NetworkPathSettings(
        source_ip="10.10.10.10",
        destination_ip="10.200.200.55",
    )

    validation = InputValidationResult(
        source_ip=settings.source_ip,
        destination_ip=settings.destination_ip,
        source_record=source_ip_record,
        source_prefix=prefix_record,
        is_host_ip=False,
    )

    gateway = GatewayDiscoveryResult(
        found=True,
        method="custom",
        gateway=IPAddressRecord(
            address="10.10.10.1",
            prefix_length=24,
            device_name="edge-1",
            interface_name="Gig0/0",
        ),
    )

    dest_record = IPAddressRecord(
        address=settings.destination_ip,
        prefix_length=24,
        device_name="dest-host",
        interface_name="eth0",
    )

    firewall_ingress = IPAddressRecord(
        address="172.16.0.2",
        prefix_length=30,
        device_name="PaloAlto-1",
        interface_name="eth1/2",
    )

    firewall_interface = IPAddressRecord(
        address="10.200.200.1",
        prefix_length=24,
        device_name="PaloAlto-1",
        interface_name="vlan.200",
    )

    data_source = PathDataSource(
        ip_records={
            dest_record.address: dest_record,
            firewall_ingress.address: firewall_ingress,
            firewall_interface.address: firewall_interface,
        }
    )

    class PaloAltoSequencedNextHop:
        def run(self, _validation, next_gateway):  # noqa: D401
            device_name = next_gateway.gateway.device_name
            if device_name == "edge-1":
                return NextHopDiscoveryResult(
                    found=True,
                    next_hops=[
                        {
                            "next_hop_ip": firewall_ingress.address,
                            "egress_interface": "Gig0/1",
                        }
                    ],
                    details="toward firewall",
                )
            return NextHopDiscoveryResult(
                found=True,
                next_hops=[
                    {
                        "next_hop_ip": None,
                        "egress_interface": firewall_interface.interface_name,
                    }
                ],
                details="Connected network",
            )

    step = PathTracingStep(data_source, settings, PaloAltoSequencedNextHop())

    result = step.run(validation, gateway)

    assert result.paths
    path = result.paths[0]
    assert path.reached_destination is True
    assert any(hop.egress_interface == firewall_interface.interface_name for hop in path.hops)
    assert all("blackhole" not in issue.lower() for issue in path.issues)
    assert path.hops[-1].device_name == dest_record.device_name


def test_path_tracing_destination_layer2_extension(default_settings, path_gateway, path_validation):
    """Layer-2 hops between the final router and destination should be inserted."""

    dest_record = IPAddressRecord(
        address=default_settings.destination_ip,
        prefix_length=24,
        device_name="Branch-Server",
        interface_name="eth0",
    )
    data_source = PathDataSource(ip_records={default_settings.destination_ip: dest_record})

    class DestinationAwareNextHop:
        def run(self, *_args, **_kwargs):  # noqa: D401
            return NextHopDiscoveryResult(
                found=True,
                next_hops=[{
                    "next_hop_ip": default_settings.destination_ip,
                    "egress_interface": "Gig0/2",
                }],
                details="toward dest",
            )

        def discover_layer2_path(self, *, device_name, egress_interface, target_ip):  # noqa: D401
            assert target_ip == default_settings.destination_ip
            if device_name == "edge-1":
                return [
                    {
                        "device_name": "L2-Switch-WAN",
                        "ingress_interface": egress_interface,
                        "egress_interface": "Gig0/0",
                        "mac_address": "aa:bb:cc:dd:ee:ff",
                        "details": "LLDP/MAC",
                    }
                ]
            return []

    step = PathTracingStep(data_source, default_settings, DestinationAwareNextHop())

    result = step.run(path_validation, path_gateway)

    hops = result.paths[0].hops
    assert hops[0].device_name == "edge-1"
    assert hops[0].hop_type == "layer3"
    assert hops[1].device_name == "L2-Switch-WAN"
    assert hops[1].hop_type == "layer2"
    assert hops[2].device_name == "Branch-Server"
    assert result.paths[0].reached_destination is True


def test_path_tracing_destination_gateway_shortcut(default_settings, path_gateway, path_validation):
    """Destination gateway discovery should drive the final segment, including L2 hops."""

    dest_ip = default_settings.destination_ip
    dest_record = IPAddressRecord(
        address=dest_ip,
        prefix_length=32,
        device_name="Branch-Host",
        interface_name="eth0",
    )
    dest_prefix = PrefixRecord(prefix="10.20.20.0/24", status="active", id="dest-prefix")
    dest_gateway_record = IPAddressRecord(
        address="10.20.20.1",
        prefix_length=32,
        device_name="Branch-L3",
        interface_name="Gig0/2",
    )
    data_source = PathDataSource(
        ip_records={
            dest_record.address: dest_record,
            dest_gateway_record.address: dest_gateway_record,
        },
        prefix_record=dest_prefix,
        gateway_record=dest_gateway_record,
    )

    class ShortcutNextHop:
        def run(self, _validation, gateway):  # noqa: D401
            device_name = gateway.gateway.device_name
            if device_name == "Branch-L3":
                raise AssertionError("Next-hop lookup should be skipped on destination gateway")
            return NextHopDiscoveryResult(
                found=True,
                next_hops=[
                    {
                        "next_hop_ip": dest_gateway_record.address,
                        "egress_interface": "Gig0/1",
                    }
                ],
                details="toward branch router",
            )

        def discover_layer2_path(self, *, device_name, egress_interface, target_ip):  # noqa: D401
            if device_name != "Branch-L3":
                return []
            return [
                {
                    "device_name": "L2-Switch-WAN",
                    "ingress_interface": egress_interface,
                    "egress_interface": "Gi0/0",
                    "mac_address": "aa:bb:cc:dd:ee:ff",
                    "details": f"LLDP/MAC toward {target_ip}",
                }
            ]

    step = PathTracingStep(data_source, default_settings, ShortcutNextHop())
    result = step.run(path_validation, path_gateway)

    assert result.paths
    path = result.paths[0]
    assert path.reached_destination is True
    hop_names = [hop.device_name for hop in path.hops]
    assert any(name == "L2-Switch-WAN" for name in hop_names), hop_names
    assert path.hops[-1].device_name == dest_record.device_name
    assert path.hops[-2].device_name == "L2-Switch-WAN"


class NextHopDataSource:
    """Minimal data source for next-hop discovery tests."""

    def __init__(
        self,
        device: DeviceRecord,
        ip_records: dict[str, IPAddressRecord] | None = None,
        devices: dict[str, DeviceRecord] | None = None,
    ) -> None:
        self._devices = devices or {}
        self._devices.setdefault(device.name, device)
        self._ip_records = ip_records or {}

    def get_device(self, name: str) -> DeviceRecord | None:  # noqa: D401
        return self._devices.get(name)

    def get_ip_address(self, address: str) -> IPAddressRecord | None:  # noqa: D401
        return self._ip_records.get(address)

    def get_interface_ip(self, device_name: str, interface_name: str):  # noqa: D401,ARG002
        for record in self._ip_records.values():
            if record.device_name == device_name and record.interface_name == interface_name:
                return record
        return None

    def resolve_redundant_gateway(self, address: str):  # noqa: D401,ARG002
        return None


def _build_next_hop_validation(settings: NetworkPathSettings, gateway: IPAddressRecord) -> InputValidationResult:
    return InputValidationResult(
        source_ip=settings.source_ip,
        destination_ip=settings.destination_ip,
        source_record=gateway,
        source_prefix=PrefixRecord(prefix="10.10.10.0/24", status="active", id="pfx"),
        is_host_ip=False,
    )


def test_selects_junos_driver_from_napalm_driver():
    """Junos detection should rely on the explicit NAPALM driver field."""

    device = DeviceRecord(
        name="srx-detect",
        primary_ip="192.0.2.10",
        platform_slug="custom",
        platform_name="Custom SRX",
        napalm_driver="junos",
    )
    data_source = NextHopDataSource(device)
    step = NextHopDiscoveryStep(data_source, NetworkPathSettings())

    assert step._select_napalm_driver(device) == "junos"


def test_next_hop_junos_uses_port_830(monkeypatch):
    """NAPALM Junos connections should use NETCONF port 830."""

    captured: dict[str, object] = {}

    class DummyDriver:
        def __init__(self, hostname, username, password, optional_args=None):
            captured["init"] = {
                "hostname": hostname,
                "username": username,
                "password": password,
                "optional_args": optional_args,
            }

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def get_route_to(self, destination):  # noqa: D401
            assert destination == "203.0.113.10"
            return {
                "203.0.113.10/32": [
                    {"next_hop": "198.51.100.1", "outgoing_interface": "ge-0/0/0.0"}
                ]
            }

        def get_lldp_neighbors_detail(self):
            return {}

        def get_lldp_neighbors(self):
            return {}

    class DummyNapalm:
        @staticmethod
        def get_network_driver(name):
            captured["driver_name"] = name
            return DummyDriver

    monkeypatch.setattr(next_hop_module, "napalm", DummyNapalm())

    settings = NetworkPathSettings(
        source_ip="10.0.0.1",
        destination_ip="203.0.113.10",
        napalm=NapalmSettings(username="netops", password="secret"),
        enable_layer2_discovery=False,
    )
    device = DeviceRecord(
        name="srx-1",
        primary_ip="192.0.2.10",
        platform_slug="juniper_junos",
        platform_name="Juniper SRX",
        napalm_driver="junos",
    )
    data_source = NextHopDataSource(device)
    step = NextHopDiscoveryStep(data_source, settings)
    gateway = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name=device.name,
        interface_name="ge-0/0/0.0",
    )
    validation = _build_next_hop_validation(settings, gateway)

    result = step.run(validation, GatewayDiscoveryResult(found=True, method="manual", gateway=gateway))

    assert result.found is True
    assert captured["driver_name"] == "junos"
    assert captured["init"]["optional_args"] == {"port": 830}


def test_next_hop_junos_route_normalization(monkeypatch):
    """Junos route payload should normalize next-hop IP and egress interface."""

    route_table = {
        "203.0.113.10/32": [
            {
                "next_hop": "198.51.100.1",
                "outgoing_interface": "ge-0/0/0.0",
                "protocol": "Static",
            },
            {
                "next_hop": "198.51.100.2",
                "outgoing_interface": "ge-0/0/1.0",
                "protocol": "Static",
            },
        ]
    }

    class DummyDriver:
        def __init__(self, *_, **__):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def get_route_to(self, destination):  # noqa: D401
            assert destination == "203.0.113.10"
            return route_table

        def get_lldp_neighbors_detail(self):
            return {}

        def get_lldp_neighbors(self):
            return {}

    class DummyNapalm:
        @staticmethod
        def get_network_driver(name):
            assert name == "junos"
            return DummyDriver

    monkeypatch.setattr(next_hop_module, "napalm", DummyNapalm())

    settings = NetworkPathSettings(
        source_ip="10.0.0.1",
        destination_ip="203.0.113.10",
        napalm=NapalmSettings(username="netops", password="secret"),
        enable_layer2_discovery=False,
    )
    device = DeviceRecord(
        name="srx-2",
        primary_ip="192.0.2.11",
        platform_slug="juniper_junos",
        platform_name="Juniper SRX",
        napalm_driver="junos",
    )
    data_source = NextHopDataSource(device)
    step = NextHopDiscoveryStep(data_source, settings)
    gateway = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name=device.name,
        interface_name="ge-0/0/0.0",
    )
    validation = _build_next_hop_validation(settings, gateway)

    result = step.run(validation, GatewayDiscoveryResult(found=True, method="manual", gateway=gateway))

    assert result.found is True
    assert len(result.next_hops) == 2
    hop_interfaces = {hop["egress_interface"] for hop in result.next_hops}
    assert hop_interfaces == {"ge-0/0/0.0", "ge-0/0/1.0"}
    assert all(hop.get("hop_type") == "layer3" for hop in result.next_hops)


def test_next_hop_junos_lldp_classification(monkeypatch):
    """LLDP evidence on Junos should classify hops as layer2+layer3."""

    class DummyDriver:
        def __init__(self, *_, **__):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def get_route_to(self, destination):  # noqa: D401
            assert destination == "198.51.100.10"
            return {
                "198.51.100.10/32": [
                    {"next_hop": "198.51.100.10", "outgoing_interface": "ge-0/0/0.0"}
                ]
            }

        def get_lldp_neighbors_detail(self):
            return {
                "ge-0/0/0.0": [
                    {"remote_system_name": "agg-1", "remote_port": "xe-0/0/1"}
                ]
            }

        def get_lldp_neighbors(self):
            return {}

    class DummyNapalm:
        @staticmethod
        def get_network_driver(name):
            assert name == "junos"
            return DummyDriver

    monkeypatch.setattr(next_hop_module, "napalm", DummyNapalm())

    settings = NetworkPathSettings(
        source_ip="10.0.0.1",
        destination_ip="198.51.100.10",
        napalm=NapalmSettings(username="netops", password="secret"),
        enable_layer2_discovery=False,
    )
    device = DeviceRecord(
        name="srx-3",
        primary_ip="192.0.2.12",
        platform_slug="juniper_junos",
        platform_name="Juniper SRX",
        napalm_driver="junos",
    )
    ip_records = {
        "198.51.100.10": IPAddressRecord(
            address="198.51.100.10",
            prefix_length=31,
            device_name="agg-1",
            interface_name="xe-0/0/1",
        )
    }
    data_source = NextHopDataSource(device, ip_records=ip_records)
    step = NextHopDiscoveryStep(data_source, settings)
    gateway = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name=device.name,
        interface_name="ge-0/0/0.0",
    )
    validation = _build_next_hop_validation(settings, gateway)

    result = step.run(validation, GatewayDiscoveryResult(found=True, method="manual", gateway=gateway))

    assert result.found is True
    hop = result.next_hops[0]
    assert hop["next_hop_ip"] == "198.51.100.10"
    assert hop["hop_type"] == "layer2+layer3"


def test_next_hop_junos_layer2_fallback(monkeypatch):
    """Layer-2 discovery should fall back to Junos CLI when getters are missing."""

    mac_address = "aa:bb:cc:00:00:01"

    arp_payload = {
        "arp-table-information": {
            "arp-table-entry": [
                {
                    "ip-address": "198.51.100.1",
                    "mac-address": mac_address,
                    "interface-name": "ge-0/0/0.0",
                }
            ]
        }
    }
    mac_payload_edge = {
        "ethernet-switching-table": {
            "ethernet-switching-table-entry": [
                {
                    "mac-address": mac_address,
                    "logical-interface": "ge-0/0/0.0",
                    "vlan": "VLAN100",
                }
            ]
        }
    }
    mac_payload_neighbor = {
        "ethernet-switching-table": {
            "ethernet-switching-table-entry": [
                {
                    "mac-address": mac_address,
                    "logical-interface": "xe-0/0/1.0",
                    "vlan": "VLAN100",
                }
            ]
        }
    }

    class DummyDriver:
        def __init__(self, hostname, username, password, optional_args=None):
            self.hostname = hostname
            self.username = username
            self.password = password
            self.optional_args = optional_args
            self.opened = False

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def open(self):
            self.opened = True
            return self

        def close(self):
            self.opened = False

        def get_route_to(self, destination):  # noqa: D401
            if destination != "203.0.113.10":
                raise AssertionError(f"Unexpected destination {destination}")
            return {
                "203.0.113.10/32": [
                    {"next_hop": "198.51.100.1", "outgoing_interface": "ge-0/0/0.0"}
                ]
            }

        def get_lldp_neighbors_detail(self):
            if self.hostname == "192.0.2.10":
                return {
                    "ge-0/0/0.0": [
                        {"remote_system_name": "Agg-1", "remote_port": "xe-0/0/1"}
                    ]
                }
            return {}

        def get_lldp_neighbors(self):
            return {}

        def get_arp_table(self):
            raise NotImplementedError

        def get_mac_address_table(self):
            raise NotImplementedError

        def cli(self, commands):
            command = commands[0]
            if "show arp" in command:
                return {command: json.dumps(arp_payload)}
            if "show ethernet-switching table" in command:
                if self.hostname == "192.0.2.10":
                    return {command: json.dumps(mac_payload_edge)}
                return {command: json.dumps(mac_payload_neighbor)}
            if "show bridge mac-table" in command:
                return {command: json.dumps(mac_payload_neighbor)}
            return {command: "{}"}

    class DummyNapalm:
        @staticmethod
        def get_network_driver(name):
            assert name == "junos"
            return DummyDriver

    monkeypatch.setattr(next_hop_module, "napalm", DummyNapalm())

    settings = NetworkPathSettings(
        source_ip="10.0.0.1",
        destination_ip="203.0.113.10",
        napalm=NapalmSettings(username="netops", password="secret"),
        layer2_max_depth=1,
    )

    device = DeviceRecord(
        name="srx-l2",
        primary_ip="192.0.2.10",
        platform_slug="juniper_junos",
        platform_name="Juniper SRX",
        napalm_driver="junos",
    )
    neighbor_device = DeviceRecord(
        name="Agg-1",
        primary_ip="192.0.2.11",
        platform_slug="juniper_junos",
        platform_name="Juniper QFX",
        napalm_driver="junos",
    )
    ip_records = {
        "198.51.100.1": IPAddressRecord(
            address="198.51.100.1",
            prefix_length=31,
            device_name="core-1",
            interface_name="xe-0/0/2",
        )
    }
    devices_map = {
        neighbor_device.name: neighbor_device,
    }
    data_source = NextHopDataSource(device, ip_records=ip_records, devices=devices_map)
    step = NextHopDiscoveryStep(data_source, settings)
    gateway = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name=device.name,
        interface_name="ge-0/0/0.0",
    )
    validation = _build_next_hop_validation(settings, gateway)

    result = step.run(validation, GatewayDiscoveryResult(found=True, method="manual", gateway=gateway))

    assert result.found is True
    hop = result.next_hops[0]
    assert hop["hop_type"] == "layer3"
    assert "layer2_hops" in hop
    layer2_hops = hop["layer2_hops"]
    assert len(layer2_hops) == 1
    l2 = layer2_hops[0]
    assert l2["device_name"] == neighbor_device.name
    assert l2["ingress_interface"] == "xe-0/0/1"
    assert l2["egress_interface"] == "xe-0/0/1.0"
    assert l2["mac_address"] == mac_address
    assert l2["gateway_interface"] == "ge-0/0/0.0"


def test_next_hop_napalm_parses_route_list(monkeypatch):
    """NAPALM lookup should handle list-based route structures."""

    class DummyDriver:
        def __init__(self, *_, **__):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def get_route_to(self, destination):  # noqa: D401
            assert destination == "10.20.20.20"
            return {
                "10.20.20.20/32": [
                    {
                        "next_hop": "10.10.20.1",
                        "outgoing_interface": "Gig0/2",
                    }
                ]
            }

    class DummyNapalm:
        @staticmethod
        def get_network_driver(name):  # noqa: D401
            assert name == "ios"
            return DummyDriver

    monkeypatch.setattr(next_hop_module, "napalm", DummyNapalm())

    settings = NetworkPathSettings(
        source_ip="10.10.10.10",
        destination_ip="10.20.20.20",
        napalm=NapalmSettings(username="u", password="p"),
    )
    device = DeviceRecord(
        name="Catalyst-1",
        primary_ip="192.0.2.1",
        platform_slug="ios",
        platform_name="iosxe",
        napalm_driver="ios",
    )
    data_source = NextHopDataSource(device)
    step = NextHopDiscoveryStep(data_source, settings)
    gateway = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name="Catalyst-1",
        interface_name="Vlan100",
    )
    validation = _build_next_hop_validation(settings, gateway)

    result = step.run(validation, GatewayDiscoveryResult(found=True, method="manual", gateway=gateway))

    assert result.found is True
    assert len(result.next_hops) == 1
    hop = result.next_hops[0]
    assert hop["next_hop_ip"] == "10.10.20.1"
    assert hop["egress_interface"] == "Gig0/2"
    assert hop.get("hop_type") == "layer3"


def test_next_hop_napalm_lldp_matches_layer2_and_layer3(monkeypatch):
    """LLDP neighbor data should classify point-to-point hops as layer2+layer3."""

    class DummyDriver:
        def __init__(self, *_, **__):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def get_route_to(self, destination):  # noqa: D401
            assert destination == "10.20.20.20"
            return {
                "10.20.20.20/32": [
                    {
                        "next_hop": "10.10.20.1",
                        "outgoing_interface": "Gig0/2",
                    }
                ]
            }

        def get_lldp_neighbors_detail(self):
            return {
                "Gig0/2": [
                    {
                        "remote_system_name": "Agg-1",
                        "remote_port": "Ethernet1/1",
                    }
                ]
            }

    class DummyNapalm:
        @staticmethod
        def get_network_driver(name):
            assert name == "ios"
            return DummyDriver

    monkeypatch.setattr(next_hop_module, "napalm", DummyNapalm())

    settings = NetworkPathSettings(
        source_ip="10.10.10.10",
        destination_ip="10.20.20.20",
        napalm=NapalmSettings(username="u", password="p"),
    )
    device = DeviceRecord(
        name="Catalyst-1",
        primary_ip="192.0.2.1",
        platform_slug="ios",
        platform_name="iosxe",
        napalm_driver="ios",
    )
    ip_records = {
        "10.10.20.1": IPAddressRecord(
            address="10.10.20.1",
            prefix_length=24,
            device_name="Agg-1",
            interface_name="Ethernet1/1",
        )
    }
    data_source = NextHopDataSource(device, ip_records=ip_records)
    step = NextHopDiscoveryStep(data_source, settings)
    gateway = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name="Catalyst-1",
        interface_name="Vlan100",
    )
    validation = _build_next_hop_validation(settings, gateway)

    result = step.run(validation, GatewayDiscoveryResult(found=True, method="manual", gateway=gateway))

    assert result.found is True
    assert len(result.next_hops) == 1
    hop = result.next_hops[0]
    assert hop["next_hop_ip"] == "10.10.20.1"
    assert hop["egress_interface"] == "Gig0/2"
    assert hop.get("hop_type") == "layer2+layer3"
    assert "lldp_neighbor" not in hop


def test_next_hop_napalm_layer2_chain(monkeypatch):
    """NAPALM lookup should derive intermediate layer-2 hops when enabled."""

    roles = {
        "198.51.100.1": "edge",
        "198.51.100.2": "switch",
        "198.51.100.3": "core",
    }
    route_table = {
        "edge": {
            "10.70.70.100/32": [
                {
                    "next_hop": "10.70.70.1",
                    "outgoing_interface": "Gig0/1",
                }
            ]
        }
    }
    arp_table = {
        "edge": [
            {"ip": "10.70.70.1", "mac": "AA:BB:CC:DD:EE:01", "interface": "Gig0/1"},
        ],
        "switch": [
            {"ip": "10.70.70.1", "mac": "AA:BB:CC:DD:EE:01", "interface": "Gig1/1"},
        ],
        "core": [],
    }
    mac_table = {
        "switch": [
            {"mac": "AA:BB:CC:DD:EE:01", "interface": "Gig1/1"},
        ],
    }
    lldp_table = {
        "edge": {
            "Gig0/1": [
                {"remote_system_name": "Switch-1", "remote_port": "Ethernet1/48"},
            ]
        },
        "switch": {
            "Gig1/1": [
                {"remote_system_name": "Core-1", "remote_port": "Ethernet2/1"},
            ]
        },
        "core": {},
    }

    class DummyDriver:
        def __init__(self, hostname, username, password, optional_args=None):
            self.hostname = hostname
            self.role = roles[hostname]
            self.connected = False

        def __enter__(self):
            self.open()
            return self

        def __exit__(self, exc_type, exc, tb):
            self.close()
            return False

        def open(self):
            self.connected = True

        def close(self):
            self.connected = False

        def get_route_to(self, destination):
            return route_table.get(self.role, {})

        def get_lldp_neighbors_detail(self):
            return lldp_table.get(self.role, {})

        def get_lldp_neighbors(self):
            return {}

        def get_mac_address_table(self):
            return mac_table.get(self.role, [])

        def get_arp_table(self):
            return arp_table.get(self.role, [])

    class DummyNapalm:
        @staticmethod
        def get_network_driver(name):
            return lambda hostname, username, password, optional_args=None: DummyDriver(
                hostname,
                username,
                password,
                optional_args,
            )

    monkeypatch.setattr(next_hop_module, "napalm", DummyNapalm())

    device_edge = DeviceRecord(
        name="Edge-R1",
        primary_ip="198.51.100.1",
        platform_slug="ios",
        platform_name="iosxe",
        napalm_driver="ios",
    )
    device_switch = DeviceRecord(
        name="Switch-1",
        primary_ip="198.51.100.2",
        platform_slug="ios",
        platform_name="iosxe",
        napalm_driver="ios",
    )
    device_core = DeviceRecord(
        name="Core-1",
        primary_ip="198.51.100.3",
        platform_slug="ios",
        platform_name="iosxe",
        napalm_driver="ios",
    )

    ip_records = {
        "10.70.70.1": IPAddressRecord(
            address="10.70.70.1",
            prefix_length=31,
            device_name="Core-1",
            interface_name="Gig2/1",
        )
    }
    devices_map = {
        d.name: d
        for d in (device_edge, device_switch, device_core)
    }
    data_source = NextHopDataSource(device_edge, ip_records=ip_records, devices=devices_map)

    settings = NetworkPathSettings(
        source_ip="10.10.10.10",
        destination_ip="10.70.70.100",
        napalm=NapalmSettings(username="u", password="p"),
    )
    step = NextHopDiscoveryStep(data_source, settings)
    gateway = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name=device_edge.name,
        interface_name="Gig0/1",
    )
    validation = _build_next_hop_validation(settings, gateway)

    result = step.run(validation, GatewayDiscoveryResult(found=True, method="manual", gateway=gateway))

    assert result.found is True
    hop = result.next_hops[0]
    assert hop["hop_type"] == "layer3"
    assert "layer2_hops" in hop
    assert len(hop["layer2_hops"]) == 1
    assert hop["layer2_hops"][0]["device_name"] == "Switch-1"


def test_next_hop_ios_vrf_cli_resolves_egress_interface(monkeypatch):
    """IOS CLI VRF route parsing should resolve egress interface for static routes."""

    destination_ip = "10.88.0.100"
    next_hop_ip = "172.8.9.2"
    vrf = "VRF-Test"

    route_output = f"""Routing Table: {vrf}
Routing entry for 10.88.0.0/24
  Known via "static", distance 1, metric 0
  Routing Descriptor Blocks:
  * {next_hop_ip}
      Route metric is 0, traffic share count is 1
"""
    next_hop_output = f"""Routing Table: {vrf}
Routing entry for 172.8.9.0/30
  Known via "connected", distance 0, metric 0 (connected, via interface)
  Routing Descriptor Blocks:
  * directly connected, via GigabitEthernet1/0/3
      Route metric is 0, traffic share count is 1
"""

    class DummyDriver:
        def __init__(self, *_, **__):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def get_lldp_neighbors_detail(self):  # noqa: D401
            return {}

        def get_lldp_neighbors(self):  # noqa: D401
            return {}

        def get_route_to(self, destination):  # noqa: D401
            assert destination == destination_ip
            return {f"{destination_ip}/32": [{"next_hop": next_hop_ip}]}

        def cli(self, commands):  # noqa: D401
            command = commands[0]
            if command == f"show ip route vrf {vrf} {destination_ip}":
                return {command: route_output}
            if command == f"show ip route vrf {vrf} {next_hop_ip}":
                return {command: next_hop_output}
            return {command: ""}

    class DummyNapalm:
        @staticmethod
        def get_network_driver(name):  # noqa: D401
            assert name == "ios"
            return DummyDriver

    monkeypatch.setattr(next_hop_module, "napalm", DummyNapalm())

    device = DeviceRecord(
        name="Catalyst-2",
        primary_ip="198.51.100.10",
        platform_slug="ios",
        platform_name="iosxe",
        napalm_driver="ios",
    )

    vrf_ingress = IPAddressRecord(
        address="10.8.99.1",
        prefix_length=24,
        device_name=device.name,
        interface_name="Vlan899",
        vrf=vrf,
    )

    data_source = NextHopDataSource(device, ip_records={vrf_ingress.address: vrf_ingress})
    settings = NetworkPathSettings(
        source_ip="10.8.99.100",
        destination_ip=destination_ip,
        napalm=NapalmSettings(username="u", password="p"),
    )
    step = NextHopDiscoveryStep(data_source, settings)
    gateway = IPAddressRecord(
        address="10.8.99.1",
        prefix_length=24,
        device_name=device.name,
        interface_name="Vlan899",
    )
    validation = _build_next_hop_validation(settings, gateway)

    result = step.run(validation, GatewayDiscoveryResult(found=True, method="manual", gateway=gateway))
    assert result.found is True
    assert result.next_hops
    hop = result.next_hops[0]
    assert hop["next_hop_ip"] == next_hop_ip
    assert hop["egress_interface"] == "GigabitEthernet1/0/3"


def test_layer2_arp_lookup_respects_interface_vrf(monkeypatch):
    """Layer-2 ARP lookups should consult VRF-specific tables when available."""

    arp_payload = {
        "TABLE_vrf": {
            "ROW_vrf": {
                "vrf-name-out": "VRF-Test",
                "TABLE_adj": {
                    "ROW_adj": {
                        "ip-addr-out": "10.8.99.100",
                        "mac": "aa:bb:cc:dd:ee:ff",
                        "intf-out": "Vlan899",
                    }
                },
            }
        }
    }

    class DummyConn:
        def __init__(self):
            self.calls: list[tuple[str, object]] = []

        def get_arp_table(self, *args, **kwargs):
            self.calls.append(("get_arp_table", kwargs))
            return []

        def cli(self, commands):
            self.calls.append(("cli", tuple(commands)))
            return {commands[0]: json.dumps(arp_payload)}

    class DummySource:
        def get_interface_ip(self, device_name, interface_name):
            return IPAddressRecord(
                address="10.8.99.1",
                prefix_length=24,
                device_name=device_name,
                interface_name=interface_name,
                vrf="VRF-Test",
            )

        def get_ip_address(self, address):  # noqa: ARG002
            return None

        def get_device(self, name):  # noqa: ARG002
            return None

    helper = Layer2Discovery(
        napalm_module=SimpleNamespace(get_network_driver=lambda *_args, **_kwargs: None),
        settings=NetworkPathSettings(layer2_max_depth=1),
        data_source=DummySource(),
        logger=None,
        select_driver=lambda device: "ios",
        driver_attempts=lambda driver: (driver,),
        optional_args_for=lambda driver: {},
        collect_lldp_neighbors=lambda conn, name: {},
        normalize_interface=lambda iface: iface,
        normalize_hostname=lambda host: host,
    )

    device = DeviceRecord(
        name="Cat-1",
        primary_ip="198.51.100.10",
        platform_slug="ios",
        platform_name="iosxe",
        napalm_driver="ios",
    )

    conn = DummyConn()
    entry = helper._lookup_arp_entry(conn, "10.8.99.100", device, "Vlan899")

    assert entry
    assert entry.get("interface") == "Vlan899"
    assert entry.get("mac") == "aa:bb:cc:dd:ee:ff"
    assert any(call[0] == "cli" for call in conn.calls)
    assert ("get_arp_table", {"vrf": "VRF-Test"}) in conn.calls


def test_next_hop_napalm_layer2_disabled(monkeypatch):
    """Layer-2 discovery should be skipped when disabled."""

    class DummyDriver:
        def __init__(self, *_, **__):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def get_route_to(self, destination):
            return {
                "10.80.80.200/32": [
                    {"next_hop": "10.80.80.1", "outgoing_interface": "Gig0/1"}
                ]
            }

        def get_lldp_neighbors_detail(self):
            return {"Gig0/1": [{"remote_system_name": "Switch-Disable", "remote_port": "Gi1/0"}]}

        def get_arp_table(self):
            return [{"ip": "10.80.80.1", "mac": "00:aa:bb:cc:dd:ee", "interface": "Gig0/1"}]

        def get_mac_address_table(self):
            return [{"mac": "00:aa:bb:cc:dd:ee", "interface": "Gi1/0"}]

        def get_lldp_neighbors(self):
            return {}

    class DummyNapalm:
        @staticmethod
        def get_network_driver(name):
            return DummyDriver

    monkeypatch.setattr(next_hop_module, "napalm", DummyNapalm())

    device = DeviceRecord(
        name="Edge-Disable",
        primary_ip="198.51.200.1",
        platform_slug="ios",
        platform_name="iosxe",
        napalm_driver="ios",
    )
    ip_records = {
        "10.80.80.1": IPAddressRecord(
            address="10.80.80.1",
            prefix_length=31,
            device_name="Core-Disable",
            interface_name="Gig0/0",
        )
    }
    data_source = NextHopDataSource(device, ip_records=ip_records)

    settings = NetworkPathSettings(
        source_ip="10.10.10.10",
        destination_ip="10.80.80.200",
        napalm=NapalmSettings(username="u", password="p"),
        enable_layer2_discovery=False,
    )
    step = NextHopDiscoveryStep(data_source, settings)
    gateway = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name=device.name,
        interface_name="Gig0/1",
    )
    validation = _build_next_hop_validation(settings, gateway)

    result = step.run(validation, GatewayDiscoveryResult(found=True, method="manual", gateway=gateway))

    assert result.found is True
    hop = result.next_hops[0]
    assert "layer2_hops" not in hop


def test_next_hop_palo_alto_lldp_and_arp(monkeypatch):
    """Palo Alto lookups should classify hops as layer2+layer3 when LLDP/ARP agree."""

    class DummyClient:
        def __init__(self, host, verify_ssl, timeout=10, logger=None):
            self.host = host
            self.verify_ssl = verify_ssl
            self.timeout = timeout
            self.logger = logger

        def keygen(self, username, password):  # noqa: D401
            assert username == "api"
            assert password == "secret"
            return "token"

        def get_virtual_router_for_interface(self, api_key, interface):  # noqa: D401
            assert api_key == "token"
            return "default"

        def fib_lookup(self, api_key, vr, ip):  # noqa: D401
            assert vr == "default"
            return {"next_hop": "10.40.40.1", "egress_interface": "ethernet1/3"}

        def route_lookup(self, api_key, vr, ip):  # noqa: D401
            return {}

        def get_lldp_neighbors(self, api_key, interface=None):  # noqa: D401
            return {
                "ethernet1/3": [
                    {
                        "hostname": "Agg-1",
                        "port": "Gig1/0",
                        "local_interface": "ethernet1/3",
                    }
                ]
            }

        def get_arp_table(self, api_key):  # noqa: D401
            return [
                {
                    "ip": "10.40.40.1",
                    "interface": "ethernet1/3",
                    "mac": "00:11:22:33:44:55",
                }
            ]

        def get_mac_table(self, api_key):  # noqa: D401
            return [
                {
                    "mac": "00:11:22:33:44:55",
                    "interface": "ethernet1/3",
                }
            ]

        def config_show(self, api_key, xpath):  # noqa: D401
            return ET.fromstring(
                """
                <response status="success">
                  <result>
                    <entry>
                      <vlan-interface>vlan.200</vlan-interface>
                      <interface>
                        <member>ethernet1/3</member>
                      </interface>
                    </entry>
                  </result>
                </response>
                """
            )

    monkeypatch.setattr(next_hop_module, "PaloAltoClient", DummyClient)

    settings = NetworkPathSettings(
        source_ip="10.10.10.10",
        destination_ip="10.40.40.40",
        pa=PaloAltoSettings(username="api", password="secret"),
    )
    device = DeviceRecord(
        name="PA-Edge",
        primary_ip="192.0.2.60",
        platform_slug="palo_alto",
        platform_name="Palo Alto",
        napalm_driver=None,
    )
    ip_records = {
        "10.40.40.1": IPAddressRecord(
            address="10.40.40.1",
            prefix_length=31,
            device_name="Agg-1",
            interface_name="Gig1/0",
        )
    }
    data_source = NextHopDataSource(device, ip_records=ip_records)
    step = NextHopDiscoveryStep(data_source, settings)
    gateway = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name=device.name,
        interface_name="ethernet1/3",
    )
    validation = _build_next_hop_validation(settings, gateway)

    result = step.run(validation, GatewayDiscoveryResult(found=True, method="manual", gateway=gateway))

    assert result.found is True
    hop = result.next_hops[0]
    assert hop["hop_type"] == "layer2+layer3"
    assert "lldp_neighbor" not in hop
    assert "arp_entry" not in hop
    assert "layer2_hops" not in hop


def test_next_hop_palo_alto_layer3_without_lldp(monkeypatch):
    """Palo Alto lookup should fall back to layer3 classification without LLDP/ARP evidence."""

    class DummyClientNoL2:
        def __init__(self, *_, **__):
            pass

        def keygen(self, *_args, **_kwargs):  # noqa: D401
            return "token"

        def get_virtual_router_for_interface(self, *_args, **_kwargs):  # noqa: D401
            return "default"

        def fib_lookup(self, *_args, **_kwargs):  # noqa: D401
            return {"next_hop": "10.50.50.1", "egress_interface": "ethernet1/5"}

        def route_lookup(self, *_args, **_kwargs):  # noqa: D401
            return {}

        def get_lldp_neighbors(self, *_args, **_kwargs):  # noqa: D401
            return {}

        def get_arp_table(self, *_args, **_kwargs):  # noqa: D401
            return []

        def get_mac_table(self, *_args, **_kwargs):  # noqa: D401
            return []

    monkeypatch.setattr(next_hop_module, "PaloAltoClient", DummyClientNoL2)

    settings = NetworkPathSettings(
        source_ip="10.10.10.10",
        destination_ip="10.50.50.50",
        pa=PaloAltoSettings(username="api", password="secret"),
    )
    device = DeviceRecord(
        name="PA-Core",
        primary_ip="192.0.2.61",
        platform_slug="palo_alto",
        platform_name="Palo Alto",
        napalm_driver=None,
    )
    ip_records = {
        "10.50.50.1": IPAddressRecord(
            address="10.50.50.1",
            prefix_length=31,
            device_name="Core-1",
            interface_name="Gig1/5",
        )
    }
    data_source = NextHopDataSource(device, ip_records=ip_records)
    step = NextHopDiscoveryStep(data_source, settings)
    gateway = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name=device.name,
        interface_name="ethernet1/5",
    )
    validation = _build_next_hop_validation(settings, gateway)

    result = step.run(validation, GatewayDiscoveryResult(found=True, method="manual", gateway=gateway))

    assert result.found is True
    hop = result.next_hops[0]
    assert hop["hop_type"] == "layer3"
    assert "lldp_neighbor" not in hop
    assert "arp_entry" not in hop


def test_discover_layer2_path_palo_alto(monkeypatch):
    class DummyClient:
        def __init__(self, host, verify_ssl, timeout=10, logger=None):
            self.host = host
            self.verify_ssl = verify_ssl
            self.timeout = timeout
            self.logger = logger

        def keygen(self, username, password):  # noqa: D401
            return "token"

        def get_lldp_neighbors(self, api_key, interface=None):  # noqa: D401
            assert api_key == "token"
            return {
                "ethernet1/3": [
                    {
                        "hostname": "Agg-2",
                        "port": "Gig2/0",
                        "local_interface": "ethernet1/3",
                    }
                ]
            }

        def get_arp_table(self, api_key):  # noqa: D401
            return [
                {
                    "ip": "10.60.60.1",
                    "interface": "ethernet1/3",
                    "mac": "AA:BB:CC:DD:EE:FF",
                }
            ]

        def get_mac_table(self, api_key):  # noqa: D401
            return [
                {
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "interface": "ethernet1/3",
                }
            ]

        def config_show(self, api_key, xpath):  # noqa: D401
            return ET.fromstring(
                """
                <response status="success">
                  <result>
                    <entry>
                      <vlan-interface>vlan.200</vlan-interface>
                      <interface>
                        <member>ethernet1/3</member>
                      </interface>
                    </entry>
                  </result>
                </response>
                """
            )

        def vlan_members_for_interface(self, api_key, vlan_if):  # noqa: D401
            if vlan_if in {"vlan.200", "200"}:
                return ["ethernet1/3"]
            return []

    monkeypatch.setattr(next_hop_module, "PaloAltoClient", DummyClient)

    settings = NetworkPathSettings(
        source_ip="10.10.10.10",
        destination_ip="10.60.60.60",
        pa=PaloAltoSettings(username="api", password="secret"),
    )

    device = DeviceRecord(
        name="PA-Branch",
        primary_ip="192.0.2.70",
        platform_slug="palo_alto",
        platform_name="Palo Alto",
        napalm_driver=None,
    )

    ip_record = IPAddressRecord(
        address="10.60.60.1",
        prefix_length=31,
        device_name="Agg-2",
        interface_name="Gig2/0",
    )

    class PaloAltoDataSource:
        def __init__(self, record, ip_record):
            self._record = record
            self._ip_record = ip_record

        def get_device(self, name):  # noqa: D401
            if name == self._record.name:
                return self._record
            return None

        def get_ip_address(self, address):  # noqa: D401
            if address == self._ip_record.address:
                return self._ip_record
            return None

    data_source = PaloAltoDataSource(device, ip_record)
    step = NextHopDiscoveryStep(data_source, settings)

    hops = step.discover_layer2_path(
        device_name=device.name,
        egress_interface="vlan.200",
        target_ip="10.60.60.1",
    )

    assert hops
    hop = hops[0]
    assert hop["device_name"] == "Agg-2"
    assert hop["ingress_interface"] == "Gig2/0"
    assert hop["mac_address"] == "AA:BB:CC:DD:EE:FF"
    assert hop["egress_interface"] == "ethernet1/3"


def test_next_hop_napalm_handles_missing_routes(monkeypatch):
    """NAPALM lookup should report when no next-hops are available."""

    class DummyDriver:
        def __init__(self, *_, **__):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def get_route_to(self, destination):  # noqa: D401
            assert destination == "10.20.20.20"
            return {"10.20.20.20/32": []}

    class DummyNapalm:
        @staticmethod
        def get_network_driver(name):
            return DummyDriver

    monkeypatch.setattr(next_hop_module, "napalm", DummyNapalm())

    settings = NetworkPathSettings(
        source_ip="10.10.10.10",
        destination_ip="10.20.20.20",
        napalm=NapalmSettings(username="u", password="p"),
    )
    device = DeviceRecord(
        name="Catalyst-1",
        primary_ip="192.0.2.1",
        platform_slug="ios",
        platform_name="iosxe",
        napalm_driver="ios",
    )
    data_source = NextHopDataSource(device)
    step = NextHopDiscoveryStep(data_source, settings)
    gateway = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name="Catalyst-1",
        interface_name="Vlan100",
    )
    validation = _build_next_hop_validation(settings, gateway)

    result = step.run(validation, GatewayDiscoveryResult(found=True, method="manual", gateway=gateway))

    assert result.found is False
    assert result.next_hops == []
    assert "No route found" in (result.details or "")


def test_next_hop_nxos_cli_lookup(monkeypatch):
    """NX-OS drivers should use CLI JSON parsing to determine next hops."""

    class DummyDriver:
        def __init__(self, *_, **__):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def cli(self, commands):
            cmd = commands[0]
            payload = {
                "TABLE_vrf": {
                    "ROW_vrf": {
                        "vrf_name": "default",
                        "TABLE_addr": {
                            "ROW_addr": {
                                "TABLE_path": {
                                    "ROW_path": [
                                        {
                                            "nexthop": "10.10.30.1",
                                            "ifname": "Ethernet1/1",
                                            "ubest": "true",
                                        }
                                    ]
                                }
                            }
                        },
                    }
                }
            }
            return {cmd: json.dumps(payload)}

    class DummyNapalm:
        @staticmethod
        def get_network_driver(name):
            assert name == "nxos_ssh"
            return DummyDriver

    monkeypatch.setattr(next_hop_module, "napalm", DummyNapalm())

    settings = NetworkPathSettings(
        source_ip="10.10.10.10",
        destination_ip="10.20.20.20",
        napalm=NapalmSettings(username="u", password="p"),
    )
    device = DeviceRecord(
        name="NX-Core",
        primary_ip="192.0.2.20",
        platform_slug="cisco_nxos",
        platform_name="NX-OS",
        napalm_driver="nxos_ssh",
    )
    data_source = NextHopDataSource(device)
    step = NextHopDiscoveryStep(data_source, settings)
    gateway = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name="NX-Core",
        interface_name="Vlan200",
    )
    validation = _build_next_hop_validation(settings, gateway)

    result = step.run(validation, GatewayDiscoveryResult(found=True, method="manual", gateway=gateway))

    assert result.found is True
    assert len(result.next_hops) == 1
    hop = result.next_hops[0]
    assert hop["next_hop_ip"] == "10.10.30.1"
    assert hop["egress_interface"] == "Ethernet1/1"
    assert hop.get("hop_type") == "layer3"
    assert "NX-OS CLI" in (result.details or "")


def test_next_hop_nxos_fallback_to_ssh(monkeypatch):
    """When the NX-API driver fails, the step should retry with nxos_ssh."""

    calls: list[str] = []

    class FailingDriver:
        def __init__(self, *_, **__):
            pass

        def __enter__(self):
            raise RuntimeError("nxos api unavailable")

        def __exit__(self, *exc_info):
            return False

    class WorkingDriver:
        def __init__(self, *_, **__):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def cli(self, commands):
            cmd = commands[0]
            payload = {
                "TABLE_vrf": {
                    "ROW_vrf": {
                        "vrf_name": "default",
                        "TABLE_addr": {
                            "ROW_addr": {
                                "TABLE_path": {
                                    "ROW_path": {
                                        "nexthop": "10.10.50.1",
                                        "ifname": "Ethernet1/5",
                                        "ubest": "true",
                                    }
                                }
                            }
                        },
                    }
                }
            }
            return {cmd: json.dumps(payload)}

    class DummyNapalm:
        @staticmethod
        def get_network_driver(name):
            calls.append(name)
            if name == "nxos":
                return FailingDriver
            if name == "nxos_ssh":
                return WorkingDriver
            raise AssertionError(f"Unexpected driver {name}")

    monkeypatch.setattr(next_hop_module, "napalm", DummyNapalm())

    settings = NetworkPathSettings(
        source_ip="10.10.10.10",
        destination_ip="10.20.20.20",
        napalm=NapalmSettings(username="u", password="p"),
    )
    device = DeviceRecord(
        name="NX-Fallback",
        primary_ip="192.0.2.40",
        platform_slug="cisco_nxos",
        platform_name="NX-OS",
        napalm_driver="nxos",
    )
    data_source = NextHopDataSource(device)
    step = NextHopDiscoveryStep(data_source, settings)
    gateway = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name="NX-Fallback",
        interface_name="Vlan400",
    )
    validation = _build_next_hop_validation(settings, gateway)

    result = step.run(validation, GatewayDiscoveryResult(found=True, method="manual", gateway=gateway))

    assert result.found is True
    assert len(result.next_hops) == 1
    hop = result.next_hops[0]
    assert hop["next_hop_ip"] == "10.10.50.1"
    assert hop["egress_interface"] == "Ethernet1/5"
    assert hop.get("hop_type") == "layer3"
    assert calls == ["nxos", "nxos_ssh"]


def test_next_hop_nxos_vrf_lookup(monkeypatch):
    """NX-OS CLI should search VRFs when the default table lacks the route."""

    responses: dict[str, dict] = {}

    base_payload = {"TABLE_vrf": {"ROW_vrf": []}}
    responses[f"show ip route 10.20.20.20 | json"] = {"show ip route 10.20.20.20 | json": json.dumps(base_payload)}
    vrf_payload = {
        "TABLE_vrf": {
            "ROW_vrf": [
                {"vrf_name": "blue"},
                {"vrf_name": "default"},
            ]
        }
    }
    responses["show vrf | json"] = {"show vrf | json": json.dumps(vrf_payload)}
    vrf_route_payload = {
        "TABLE_vrf": {
            "ROW_vrf": {
                "TABLE_addr": {
                    "ROW_addr": {
                        "TABLE_path": {
                            "ROW_path": {
                                "nexthop": "10.10.60.1",
                                "ifname": "Ethernet1/6",
                                "ubest": "true",
                            }
                        }
                    }
                }
            }
        }
    }
    responses["show ip route vrf blue 10.20.20.20 | json"] = {
        "show ip route vrf blue 10.20.20.20 | json": json.dumps(vrf_route_payload)
    }

    class DummyDriver:
        def __init__(self, *_, **__):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def cli(self, commands):  # noqa: D401
            cmd = commands[0]
            payload = responses.get(cmd)
            if payload is None:
                raise AssertionError(f"Unexpected command {cmd}")
            return payload

    class DummyNapalm:
        @staticmethod
        def get_network_driver(name):
            assert name == "nxos_ssh"
            return DummyDriver

    monkeypatch.setattr(next_hop_module, "napalm", DummyNapalm())

    settings = NetworkPathSettings(
        source_ip="10.10.10.10",
        destination_ip="10.20.20.20",
        napalm=NapalmSettings(username="u", password="p"),
    )
    device = DeviceRecord(
        name="NX-VRF",
        primary_ip="192.0.2.41",
        platform_slug="cisco_nxos",
        platform_name="NX-OS",
        napalm_driver="nxos_ssh",
    )
    data_source = NextHopDataSource(device)
    step = NextHopDiscoveryStep(data_source, settings)
    gateway = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name="NX-VRF",
        interface_name="Vlan401",
    )
    validation = _build_next_hop_validation(settings, gateway)

    result = step.run(validation, GatewayDiscoveryResult(found=True, method="manual", gateway=gateway))

    assert result.found is True
    assert len(result.next_hops) == 1
    hop = result.next_hops[0]
    assert hop["next_hop_ip"] == "10.10.60.1"
    assert hop["egress_interface"] == "Ethernet1/6"
    assert hop.get("hop_type") == "layer3"


def test_next_hop_caches_results(monkeypatch):
    """Repeated lookups for the same device/destination should reuse cached data."""

    calls: list[str] = []

    class DummyDriver:
        def __init__(self, *_, **__):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def get_route_to(self, destination):  # noqa: D401
            assert destination == "10.20.20.20"
            return {
                "10.20.20.20/32": [
                    {
                        "next_hop": "10.10.40.1",
                        "outgoing_interface": "Gig0/3",
                    }
                ]
            }

    class DummyNapalm:
        @staticmethod
        def get_network_driver(name):
            calls.append(name)
            return DummyDriver

    monkeypatch.setattr(next_hop_module, "napalm", DummyNapalm())

    settings = NetworkPathSettings(
        source_ip="10.10.10.10",
        destination_ip="10.20.20.20",
        napalm=NapalmSettings(username="u", password="p"),
    )
    device = DeviceRecord(
        name="Cache-Test",
        primary_ip="192.0.2.30",
        platform_slug="ios",
        platform_name="IOS",
        napalm_driver="ios",
    )
    data_source = NextHopDataSource(device)
    step = NextHopDiscoveryStep(data_source, settings)
    gateway = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name="Cache-Test",
        interface_name="Vlan300",
    )
    validation = _build_next_hop_validation(settings, gateway)

    first = step.run(validation, GatewayDiscoveryResult(found=True, method="manual", gateway=gateway))
    second = step.run(validation, GatewayDiscoveryResult(found=True, method="manual", gateway=gateway))

    assert first == second
    assert calls.count("ios") == 1


def test_next_hop_f5_lookup(monkeypatch):
    """F5 platforms should leverage the BIG-IP API for next-hop metadata."""

    summary = F5NextHopSummary(
        destination_ip="10.20.20.20",
        pools_containing_member=["/Common/pool_web_http"],
        virtual_servers=[
            {
                "name": "/Common/vs_web_http",
                "virtual_address": "10.249.0.100",
            }
        ],
        next_hop_ip="10.20.20.20",
        ingress_vlan="/Common/vlan_external",
        ingress_interface="1.1",
        egress_vlan="/Common/vlan_internal",
        egress_interface="1.2",
        egress_self_ip="/Common/self_internal",
        egress_self_ip_address="10.251.0.1/24",
    )

    captured: dict[str, Any] = {}

    class DummyF5Client:
        def __init__(self, host, username, password, verify_ssl, timeout=10):  # noqa: D401
            captured.update({
                "host": host,
                "username": username,
                "password": password,
                "verify_ssl": verify_ssl,
                "timeout": timeout,
            })

        def collect_destination_summary(self, dest_ip, partitions=None, ingress_hint=None):  # noqa: D401
            captured["dest_ip"] = dest_ip
            captured["partitions"] = partitions
            captured["ingress_hint"] = ingress_hint
            return summary

    monkeypatch.setattr(next_hop_module, "F5Client", DummyF5Client)

    settings = NetworkPathSettings(
        source_ip="10.10.10.10",
        destination_ip="10.20.20.20",
        f5=F5Settings(username="f5-user", password="secret", verify_ssl=False, partitions=("Common",)),
    )
    device = DeviceRecord(
        name="F5-LTM",
        primary_ip="192.0.2.80",
        platform_slug="f5-bigip",
        platform_name="F5 BIG-IP",
    )
    data_source = NextHopDataSource(device)
    step = NextHopDiscoveryStep(data_source, settings)
    gateway = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name="F5-LTM",
        interface_name="Vlan200",
    )
    validation = _build_next_hop_validation(settings, gateway)

    result = step.run(validation, GatewayDiscoveryResult(found=True, method="manual", gateway=gateway))

    assert result.found is True
    assert "F5 API" in (result.details or "")
    next_hop_entry = result.next_hops[0]
    assert next_hop_entry["next_hop_ip"] == settings.destination_ip
    assert next_hop_entry["egress_interface"] == summary.egress_interface
    assert next_hop_entry["ingress_vlan"] == summary.ingress_vlan
    assert next_hop_entry["ingress_interface"] == summary.ingress_interface
    assert next_hop_entry["pools_containing_member"] == summary.pools_containing_member
    assert next_hop_entry["virtual_servers"] == summary.virtual_servers
    assert captured == {
        "host": "192.0.2.80",
        "username": "f5-user",
        "password": "secret",
        "verify_ssl": False,
        "timeout": 10,
        "dest_ip": "10.20.20.20",
        "partitions": ("Common",),
        "ingress_hint": "Vlan200",
    }


def test_nxos_prefix_table_format(monkeypatch):
    """NX-OS TABLE_addrf format should be parsed correctly."""

    payload = {
        "TABLE_vrf": {
            "ROW_vrf": {
                "vrf-name-out": "default",
                "TABLE_addrf": {
                    "ROW_addrf": {
                        "addrf": "ipv4",
                        "TABLE_prefix": {
                            "ROW_prefix": {
                                "ipprefix": "10.200.200.0/24",
                                "TABLE_path": {
                                    "ROW_path": {
                                        "entry": "0",
                                        "ipnexthop": "10.200.200.1",
                                        "ifname": "Vlan200",
                                        "ubest": "true",
                                    }
                                },
                            }
                        },
                    }
                },
            }
        }
    }

    class DummyDriver:
        def __init__(self, *_, **__):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def cli(self, commands):  # noqa: D401
            cmd = commands[0]
            return {cmd: json.dumps(payload)}

    class DummyNapalm:
        @staticmethod
        def get_network_driver(name):
            return DummyDriver

    monkeypatch.setattr(next_hop_module, "napalm", DummyNapalm())

    settings = NetworkPathSettings(
        source_ip="10.10.10.10",
        destination_ip="10.200.200.200",
        napalm=NapalmSettings(username="u", password="p"),
    )
    device = DeviceRecord(
        name="NX-Prefix",
        primary_ip="192.0.2.42",
        platform_slug="cisco_nxos",
        platform_name="NX-OS",
        napalm_driver="nxos_ssh",
    )
    data_source = NextHopDataSource(device)
    step = NextHopDiscoveryStep(data_source, settings)
    gateway = IPAddressRecord(
        address="10.10.10.1",
        prefix_length=24,
        device_name="NX-Prefix",
        interface_name="Vlan402",
    )
    validation = _build_next_hop_validation(settings, gateway)

    result = step.run(validation, GatewayDiscoveryResult(found=True, method="manual", gateway=gateway))

    assert result.found is True
    assert len(result.next_hops) == 1
    hop = result.next_hops[0]
    assert hop["next_hop_ip"] == "10.200.200.1"
    assert hop["egress_interface"] == "Vlan200"
    assert hop.get("hop_type") == "layer3"
