"""Unit tests for individual network path tracing steps."""

import pytest

from jobs.network_path_tracing import NetworkPathSettings
from jobs.network_path_tracing import GatewayDiscoveryError, InputValidationError
from jobs.network_path_tracing.interfaces.nautobot import IPAddressRecord, PrefixRecord
from jobs.network_path_tracing.steps import (
    GatewayDiscoveryResult,
    GatewayDiscoveryStep,
    InputValidationResult,
    InputValidationStep,
    NextHopDiscoveryResult,
    PathTracingStep,
)
import jobs.network_path_tracing.steps.path_tracing as path_tracing_module


class FakeDataSource:
    """Minimal Nautobot data source used to exercise step logic."""

    def __init__(
        self,
        ip_records: dict[str, IPAddressRecord],
        prefix_record: PrefixRecord | None,
        gateway_record: IPAddressRecord | None = None,
    ) -> None:
        self._ip_records = ip_records
        self._prefix_record = prefix_record
        self._gateway_record = gateway_record
        self.last_gateway_lookup = None

    def get_ip_address(self, address: str) -> IPAddressRecord | None:
        return self._ip_records.get(address)

    def get_most_specific_prefix(self, address: str) -> PrefixRecord | None:
        return self._prefix_record

    def find_gateway_ip(
        self, prefix: PrefixRecord, custom_field: str
    ) -> IPAddressRecord | None:  # noqa: ARG002
        self.last_gateway_lookup = prefix
        return self._gateway_record


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


def test_input_validation_missing_ip(default_settings, prefix_record):
    data_source = FakeDataSource(ip_records={}, prefix_record=prefix_record)
    step = InputValidationStep(data_source)

    with pytest.raises(InputValidationError) as excinfo:
        step.run(default_settings)

    assert "Source IP 10.10.10.10" in str(excinfo.value)


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
) -> InputValidationResult:
    return InputValidationResult(
        source_ip=record.address,
        destination_ip="10.20.20.20",
        source_record=record,
        source_prefix=prefix,
        is_host_ip=is_host,
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


def test_path_tracing_reaches_destination(monkeypatch, default_settings, path_gateway, path_validation):
    """Path tracing should record a successful hop when next-hop equals destination."""

    next_hop_result = NextHopDiscoveryResult(
        found=True,
        next_hops=[{"next_hop_ip": default_settings.destination_ip, "egress_interface": "Gig0/1"}],
        details="direct",
    )

    class StubNextHop:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def run(self, _validation, _gateway):
            return next_hop_result

    monkeypatch.setattr(path_tracing_module, "NextHopDiscoveryStep", StubNextHop)

    data_source = PathDataSource(ip_records={})
    step = PathTracingStep(data_source, default_settings)

    result = step.run(path_validation, path_gateway)

    assert len(result.paths) == 1
    path = result.paths[0]
    assert path.reached_destination is True
    assert path.hops[0].next_hop_ip == default_settings.destination_ip


def test_path_tracing_blackhole(monkeypatch, default_settings, path_gateway, path_validation):
    """Path tracing should flag routing blackholes when no next hop is found."""

    next_hop_result = NextHopDiscoveryResult(found=False, next_hops=[], details="no route")

    class StubNextHop:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def run(self, _validation, _gateway):
            return next_hop_result

    monkeypatch.setattr(path_tracing_module, "NextHopDiscoveryStep", StubNextHop)

    data_source = PathDataSource(ip_records={})
    step = PathTracingStep(data_source, default_settings)

    result = step.run(path_validation, path_gateway)

    assert len(result.paths) == 1
    path = result.paths[0]
    assert path.reached_destination is False
    assert any("blackhole" in issue for issue in path.issues)
    assert path.hops[0].details == "no route"


def test_path_tracing_multiple_hops(monkeypatch, default_settings, path_gateway, path_validation):
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

    def pop_result() -> NextHopDiscoveryResult:
        if hop_sequence:
            return hop_sequence.pop(0)
        return NextHopDiscoveryResult(found=False, next_hops=[], details="exhausted")

    class SequencedNextHop:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def run(self, _validation, _gateway):
            return pop_result()

    monkeypatch.setattr(path_tracing_module, "NextHopDiscoveryStep", SequencedNextHop)

    data_source = PathDataSource(
        ip_records={
            "10.10.20.1": IPAddressRecord(
                address="10.10.20.1",
                prefix_length=24,
                device_name="agg-1",
                interface_name="Gig1/0",
            )
        }
    )
    step = PathTracingStep(data_source, default_settings)

    result = step.run(path_validation, path_gateway)

    assert len(result.paths) == 1
    path = result.paths[0]
    assert path.reached_destination is True
    assert len(path.hops) == 2
    assert path.hops[0].next_hop_ip == "10.10.20.1"
    assert path.hops[1].next_hop_ip == default_settings.destination_ip
