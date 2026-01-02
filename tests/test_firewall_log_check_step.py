from __future__ import annotations

from typing import Any

import jobs.network_path_tracing.steps.firewall_log_check as firewall_log_check_module
from jobs.network_path_tracing.config import NetworkPathSettings, PaloAltoSettings
from jobs.network_path_tracing.exceptions import FirewallLogCheckError
from jobs.network_path_tracing.steps.firewall_log_check import FirewallLogCheckStep


def test_firewall_log_check_disabled_payload_is_stable():
    payload = FirewallLogCheckStep.disabled_payload()

    assert payload["enabled"] is False
    assert payload["status"] == "disabled"
    assert payload["provider"] == "panorama"
    assert payload["panorama"] is None
    assert payload["query"] is None
    assert payload["found"] is False
    assert payload["entries"] == []
    assert payload["errors"] == []


def test_firewall_log_check_step_success_found_includes_entries_and_message(monkeypatch):
    entries = [
        {
            "timestamp": "2025/12/30 12:00:00",
            "action": "deny",
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "protocol": "tcp",
            "destination_port": 443,
            "rule": "block-https",
            "app": "ssl",
            "device_serial": "001122334455",
            "device_name": "PA-EDGE-1",
            "session_end_reason": "policy-deny",
        }
    ]

    class DummyClient:
        def __init__(self, host: str, *, verify_ssl: bool, logger=None):  # noqa: ANN001
            assert host == "panorama.local"
            assert verify_ssl is False

        def keygen(self, username: str, password: str) -> str:
            assert username == "alice"
            assert password == "s3cr3t"
            return "APIKEY"

        def traffic_logs_deny_for_flow(  # noqa: PLR0913
            self,
            api_key: str,
            *,
            src_ip: str,
            dst_ip: str,
            dst_port: Any,
            since_hours: int = 24,
            max_results: int = 10,
            max_wait_seconds: int = 30,
            fetch_limit: int | None = None,
        ) -> list[dict[str, Any]]:
            assert api_key == "APIKEY"
            assert src_ip == "10.0.0.1"
            assert dst_ip == "10.0.0.2"
            assert dst_port == 443
            assert since_hours == 24
            assert max_results == 10
            assert max_wait_seconds >= 1
            assert fetch_limit in (None, 10)
            return entries

    monkeypatch.setattr(firewall_log_check_module, "PaloAltoClient", DummyClient)

    settings = NetworkPathSettings(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        pa=PaloAltoSettings(username="alice", password="s3cr3t", verify_ssl=False),
    )
    step = FirewallLogCheckStep()
    payload = step.run(
        settings,
        panorama_host="panorama.local",
        destination_port=443,
        panorama_name="Panorama-1",
    )

    assert payload["enabled"] is True
    assert payload["status"] == "success"
    assert payload["panorama"] == {"name": "Panorama-1", "host": "panorama.local"}
    assert payload["found"] is True
    assert payload["entries"] == entries
    assert "Found 1 DENY traffic log(s)" in payload["message"]


def test_firewall_log_check_step_success_not_found_has_clear_message(monkeypatch):
    class DummyClient:
        def __init__(self, host: str, *, verify_ssl: bool, logger=None):  # noqa: ANN001
            assert host == "panorama.local"
            assert verify_ssl is False

        def keygen(self, username: str, password: str) -> str:  # noqa: ARG002
            return "APIKEY"

        def traffic_logs_deny_for_flow(self, *args, **kwargs):  # noqa: ANN001, D401
            return []

    monkeypatch.setattr(firewall_log_check_module, "PaloAltoClient", DummyClient)

    settings = NetworkPathSettings(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        pa=PaloAltoSettings(username="alice", password="s3cr3t", verify_ssl=False),
    )
    step = FirewallLogCheckStep()
    payload = step.run(settings, panorama_host="panorama.local", destination_port=443)

    assert payload["status"] == "success"
    assert payload["found"] is False
    assert payload["entries"] == []
    assert "No DENY traffic logs found" in payload["message"]


def test_firewall_log_check_step_error_redacts_credentials(monkeypatch):
    class DummyClient:
        def __init__(self, host: str, *, verify_ssl: bool, logger=None):  # noqa: ANN001, ARG002
            assert host == "panorama.local"

        def keygen(self, username: str, password: str) -> str:  # noqa: ARG002
            return "APIKEY"

        def traffic_logs_deny_for_flow(self, *args, **kwargs):  # noqa: ANN001, D401
            raise RuntimeError(
                "request failed user=alice password=s3cr3t https://panorama.local/api/?type=log&user=alice&password=s3cr3t&key=APIKEY"
            )

    monkeypatch.setattr(firewall_log_check_module, "PaloAltoClient", DummyClient)

    settings = NetworkPathSettings(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        pa=PaloAltoSettings(username="alice", password="s3cr3t", verify_ssl=False),
    )
    step = FirewallLogCheckStep()
    payload = step.run(settings, panorama_host="panorama.local", destination_port=443)

    assert payload["status"] == "error"
    error = payload["errors"][0]
    assert "alice" not in error
    assert "s3cr3t" not in error
    assert "key=APIKEY" not in error
    assert "user=***redacted***" in error
    assert "password=***redacted***" in error
    assert "key=***redacted***" in error


def test_firewall_log_check_step_retries_timeout_with_fetch_limit_1(monkeypatch):
    observed_fetch_limits = []

    class DummyClient:
        def __init__(self, host: str, *, verify_ssl: bool, logger=None):  # noqa: ANN001, ARG002
            assert host == "panorama.local"
            assert verify_ssl is False

        def keygen(self, username: str, password: str) -> str:  # noqa: ARG002
            return "APIKEY"

        def traffic_logs_deny_for_flow(  # noqa: PLR0913
            self,
            api_key: str,
            *,
            src_ip: str,
            dst_ip: str,
            dst_port: Any,
            since_hours: int = 24,
            max_results: int = 10,
            max_wait_seconds: int = 30,
            fetch_limit: int | None = None,
        ) -> list[dict[str, Any]]:
            assert api_key == "APIKEY"
            assert src_ip == "10.0.0.1"
            assert dst_ip == "10.0.0.2"
            assert dst_port == 443
            assert since_hours == 24
            assert max_results == 10
            assert max_wait_seconds >= 1
            observed_fetch_limits.append(fetch_limit)
            if len(observed_fetch_limits) == 1:
                raise FirewallLogCheckError("Panorama traffic log query timed out after 30 seconds (job 18).")
            return []

    monkeypatch.setattr(firewall_log_check_module, "PaloAltoClient", DummyClient)

    settings = NetworkPathSettings(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        pa=PaloAltoSettings(username="alice", password="s3cr3t", verify_ssl=False),
    )
    step = FirewallLogCheckStep()
    payload = step.run(settings, panorama_host="panorama.local", destination_port=443)

    assert observed_fetch_limits == [10, 1]
    assert payload["status"] == "success"
    assert payload["query"]["fetch_limit"] == 1
    assert payload["found"] is False
    assert "retried with fetch_limit=1 after timeout" in payload["message"]


def test_firewall_log_check_step_timeout_retry_still_errors_with_hint(monkeypatch):
    class DummyClient:
        def __init__(self, host: str, *, verify_ssl: bool, logger=None):  # noqa: ANN001, ARG002
            assert host == "panorama.local"
            assert verify_ssl is False

        def keygen(self, username: str, password: str) -> str:  # noqa: ARG002
            return "APIKEY"

        def traffic_logs_deny_for_flow(self, *args, **kwargs):  # noqa: ANN001, D401
            raise FirewallLogCheckError("Panorama traffic log query timed out after 30 seconds (job 18).")

    monkeypatch.setattr(firewall_log_check_module, "PaloAltoClient", DummyClient)

    settings = NetworkPathSettings(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        pa=PaloAltoSettings(username="alice", password="s3cr3t", verify_ssl=False),
    )
    step = FirewallLogCheckStep()
    payload = step.run(settings, panorama_host="panorama.local", destination_port=443)

    assert payload["status"] == "error"
    assert "Retry with fetch_limit=1 failed" in payload["errors"][0]
    assert "PANORAMA_LOG_QUERY_MAX_WAIT_SECONDS" in payload["errors"][0]
    assert "lower PANORAMA_LOG_QUERY_FETCH_LIMIT" not in payload["errors"][0]
