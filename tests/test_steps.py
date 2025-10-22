"""Unit tests for individual network path tracing steps."""

import json
import sys
from types import SimpleNamespace
from typing import Any

import pytest

if "napalm" not in sys.modules:
    sys.modules["napalm"] = SimpleNamespace(get_network_driver=lambda *_args, **_kwargs: None)

from jobs.network_path_tracing import NetworkPathSettings, NapalmSettings, F5Settings
from jobs.network_path_tracing import GatewayDiscoveryError, InputValidationError
from jobs.network_path_tracing.interfaces.nautobot import (
    IPAddressRecord,
    PrefixRecord,
    DeviceRecord,
    RedundancyMember,
    RedundancyResolution,
)
from jobs.network_path_tracing.steps import (
    GatewayDiscoveryResult,
    GatewayDiscoveryStep,
    InputValidationResult,
    InputValidationStep,
    NextHopDiscoveryResult,
    NextHopDiscoveryStep,
    PathTracingStep,
)
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
    assert data_source.get_ip_address("10.10.10.1") == fallback_gateway


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

    with pytest.raises(GatewayDiscoveryError):
        step.run(validation)


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

    def __init__(self, ip_records: dict[str, IPAddressRecord]) -> None:
        super().__init__(ip_records=ip_records, prefix_record=None, gateway_record=None)


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
    data_source = PathDataSource(ip_records={default_settings.destination_ip: dest_record})
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


class NextHopDataSource:
    """Minimal data source for next-hop discovery tests."""

    def __init__(self, device: DeviceRecord) -> None:
        self._device = device

    def get_device(self, name: str) -> DeviceRecord | None:  # noqa: D401
        return self._device if self._device.name == name else None

    def get_interface_ip(self, device_name: str, interface_name: str):  # noqa: D401,ARG002
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
    assert result.next_hops == [{"next_hop_ip": "10.10.20.1", "egress_interface": "Gig0/2"}]


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
    assert result.next_hops == [{"next_hop_ip": "10.10.30.1", "egress_interface": "Ethernet1/1"}]
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
    assert result.next_hops == [{"next_hop_ip": "10.10.50.1", "egress_interface": "Ethernet1/5"}]
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
    assert result.next_hops == [{"next_hop_ip": "10.10.60.1", "egress_interface": "Ethernet1/6"}]


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
    assert result.next_hops == [{"next_hop_ip": "10.200.200.1", "egress_interface": "Vlan200"}]
