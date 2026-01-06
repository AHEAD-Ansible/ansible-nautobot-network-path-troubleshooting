from __future__ import annotations

import sys
from types import SimpleNamespace

if "napalm" not in sys.modules:
    sys.modules["napalm"] = SimpleNamespace(get_network_driver=lambda *_args, **_kwargs: None)

from jobs.network_path_tracing import cli as cli_module


def test_cli_payload_includes_firewall_logs_when_enabled(monkeypatch):
    class DummySource:
        def get_ip_address(self, address):  # noqa: ANN001
            return None

    monkeypatch.setattr(cli_module, "select_data_source", lambda *_args, **_kwargs: DummySource())

    validation = SimpleNamespace(
        source_found=True,
        source_ip="10.0.0.1",
        source_record=SimpleNamespace(
            prefix_length=24,
            device_name="server-1",
            interface_name="eth0",
        ),
        source_prefix=SimpleNamespace(prefix="10.0.0.0/24"),
        is_host_ip=False,
    )

    gateway = SimpleNamespace(
        found=True,
        method="custom_field",
        gateway=SimpleNamespace(
            address="10.0.0.254",
            device_name="gw-1",
            interface_name="Gig0/0",
        ),
        details="gateway discovered",
    )

    path_result = SimpleNamespace(
        paths=[
            SimpleNamespace(
                reached_destination=False,
                hops=[],
                issues=[],
            )
        ],
        issues=[],
        graph=None,
    )

    class DummyInputValidationStep:
        def __init__(self, source):  # noqa: ANN001
            self._source = source

        def run(self, settings):  # noqa: ANN001
            return validation

    class DummyGatewayDiscoveryStep:
        def __init__(self, source, gateway_custom_field):  # noqa: ANN001, ARG002
            self._source = source

        def run(self, validation_result):  # noqa: ANN001
            return gateway

    class DummyPathTracingStep:
        def __init__(self, source, settings, next_hop_step):  # noqa: ANN001, ARG002
            self._source = source

        def run(self, validation_result, gateway_result):  # noqa: ANN001, ARG002
            return path_result

    monkeypatch.setattr(cli_module, "InputValidationStep", DummyInputValidationStep)
    monkeypatch.setattr(cli_module, "GatewayDiscoveryStep", DummyGatewayDiscoveryStep)
    monkeypatch.setattr(cli_module, "NextHopDiscoveryStep", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(cli_module, "PathTracingStep", DummyPathTracingStep)

    def fake_firewall_run(  # noqa: ANN001, PLR0913
        self,
        settings,
        *,
        panorama_host,
        destination_port,
        panorama_name=None,
        max_wait_seconds=None,
        fetch_limit=None,
        max_results=None,
    ):
        assert max_wait_seconds is None
        assert fetch_limit is None
        assert max_results is None
        return {
            "enabled": True,
            "status": "success",
            "provider": "panorama",
            "panorama": {"name": panorama_name, "host": panorama_host},
            "query": {
                "source_ip": settings.source_ip,
                "destination_ip": settings.destination_ip,
                "destination_port": destination_port,
                "since_hours": 24,
                "max_results": 10,
                "action": "deny",
            },
            "found": False,
            "entries": [],
            "message": "No logs.",
            "errors": [],
        }

    monkeypatch.setattr(cli_module.FirewallLogCheckStep, "run", fake_firewall_run)

    payload = cli_module.run_steps(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        check_panorama_logs=True,
        panorama_host="panorama.local",
        log_port=443,
    )

    assert payload["firewall_logs"]["enabled"] is True
    assert payload["firewall_logs"]["panorama"]["host"] == "panorama.local"
