from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
import requests
import responses

from jobs.network_path_tracing.exceptions import FirewallLogCheckError
import jobs.network_path_tracing.interfaces.palo_alto as palo_alto_module
from jobs.network_path_tracing.interfaces.palo_alto import PaloAltoClient


PAN_SUCCESS_XML = """\
<response status="success">
  <result>
    <log>
      <logs count="2" progress="100" total="2">
        <entry>
          <receive_time>2025/12/30 12:00:00</receive_time>
          <action>deny</action>
          <src>10.0.0.1</src>
          <dst>10.0.0.2</dst>
          <proto>6</proto>
          <dport>443</dport>
          <rule>block-https</rule>
          <app>ssl</app>
          <serial>001122334455</serial>
          <device_name>PA-EDGE-1</device_name>
          <session_end_reason>policy-deny</session_end_reason>
        </entry>
        <entry>
          <receive_time>2025/12/30 12:01:00</receive_time>
          <action>deny</action>
          <src>10.0.0.1</src>
          <dst>10.0.0.2</dst>
          <proto>17</proto>
          <dport>53</dport>
          <serial>001122334455</serial>
        </entry>
      </logs>
    </log>
  </result>
</response>
"""


PAN_EMPTY_XML = """\
<response status="success">
  <result>
    <log>
      <logs count="0" progress="100" total="0"/>
    </log>
  </result>
</response>
"""


PAN_ERROR_XML = """\
<response status="error">
  <msg>
    <line>Invalid credentials</line>
  </msg>
</response>
"""

PAN_MIXED_ACTION_XML = """\
<response status="success">
  <result>
    <log>
      <logs count="2" progress="100" total="2">
        <entry>
          <receive_time>2025/12/30 12:00:00</receive_time>
          <action>allow</action>
          <src>10.0.0.1</src>
          <dst>10.0.0.2</dst>
          <proto>6</proto>
          <dport>443</dport>
          <serial>001122334455</serial>
        </entry>
        <entry>
          <receive_time>2025/12/30 12:01:00</receive_time>
          <action>deny</action>
          <src>10.0.0.1</src>
          <dst>10.0.0.2</dst>
          <proto>6</proto>
          <dport>443</dport>
          <serial>001122334455</serial>
        </entry>
      </logs>
    </log>
  </result>
</response>
"""


@responses.activate
def test_panorama_traffic_logs_query_parses_entries():
    client = PaloAltoClient("panorama.local", verify_ssl=False)

    responses.add(
        responses.GET,
        "https://panorama.local/api/",
        body=PAN_SUCCESS_XML,
        status=200,
        content_type="application/xml",
    )

    entries = client.traffic_logs_query("APIKEY", query="(action eq deny)", nlogs=10)

    assert entries == [
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
        },
        {
            "timestamp": "2025/12/30 12:01:00",
            "action": "deny",
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "protocol": "udp",
            "destination_port": 53,
            "rule": None,
            "app": None,
            "device_serial": "001122334455",
            "device_name": None,
            "session_end_reason": None,
        },
    ]


@responses.activate
def test_panorama_traffic_logs_query_empty_results_returns_empty_list():
    client = PaloAltoClient("panorama.local", verify_ssl=False)

    responses.add(
        responses.GET,
        "https://panorama.local/api/",
        body=PAN_EMPTY_XML,
        status=200,
        content_type="application/xml",
    )

    entries = client.traffic_logs_query("APIKEY", query="(action eq deny)", nlogs=10)
    assert entries == []


@responses.activate
def test_panorama_traffic_logs_query_status_error_raises_domain_exception():
    client = PaloAltoClient("panorama.local", verify_ssl=False)

    responses.add(
        responses.GET,
        "https://panorama.local/api/",
        body=PAN_ERROR_XML,
        status=200,
        content_type="application/xml",
    )

    with pytest.raises(FirewallLogCheckError) as excinfo:
        client.traffic_logs_query("APIKEY", query="(action eq deny)", nlogs=10)

    assert "Invalid credentials" in str(excinfo.value)


@responses.activate
def test_panorama_traffic_logs_query_redacts_api_key_on_request_exception():
    client = PaloAltoClient("panorama.local", verify_ssl=False)

    responses.add(
        responses.GET,
        "https://panorama.local/api/",
        body=requests.exceptions.ConnectionError("failed calling /api/?type=log&key=APIKEY"),
    )

    with pytest.raises(FirewallLogCheckError) as excinfo:
        client.traffic_logs_query("APIKEY", query="(action eq deny)", nlogs=10)

    assert "APIKEY" not in str(excinfo.value)
    assert "key=***redacted***" in str(excinfo.value)


@responses.activate
def test_panorama_traffic_logs_query_polls_job_id():
    client = PaloAltoClient("panorama.local", verify_ssl=False)

    submit_xml = """\
<response status="success">
  <result>
    <job>123</job>
  </result>
</response>
"""

    get_xml = """\
<response status="success">
  <result>
    <log>
      <logs count="1" progress="100" total="1">
        <entry>
          <receive_time>2025/12/30 12:00:00</receive_time>
          <action>deny</action>
          <src>10.0.0.1</src>
          <dst>10.0.0.2</dst>
          <proto>6</proto>
          <dport>443</dport>
          <serial>001122334455</serial>
        </entry>
      </logs>
    </log>
  </result>
</response>
"""

    def callback(request):  # noqa: ANN001
        params = parse_qs(urlparse(request.url).query)
        if params.get("action") == ["get"]:
            return (200, {"Content-Type": "application/xml"}, get_xml)
        return (200, {"Content-Type": "application/xml"}, submit_xml)

    responses.add_callback(
        responses.GET,
        "https://panorama.local/api/",
        callback=callback,
    )

    entries = client.traffic_logs_query("APIKEY", query="(action eq deny)", nlogs=10)
    assert len(entries) == 1
    assert entries[0]["protocol"] == "tcp"
    assert len(responses.calls) == 2


@responses.activate
def test_panorama_traffic_logs_query_returns_partial_entries_on_timeout(monkeypatch):
    client = PaloAltoClient("panorama.local", verify_ssl=False)

    submit_xml = """\
<response status="success">
  <result>
    <job>123</job>
  </result>
</response>
"""

    get_partial_xml = """\
<response status="success">
  <result>
    <log>
      <logs count="1" progress="0" total="1">
        <entry>
          <receive_time>2025/12/30 12:00:00</receive_time>
          <action>deny</action>
          <src>10.0.0.1</src>
          <dst>10.0.0.2</dst>
          <proto>6</proto>
          <dport>443</dport>
          <serial>001122334455</serial>
        </entry>
      </logs>
    </log>
  </result>
</response>
"""

    def callback(request):  # noqa: ANN001
        params = parse_qs(urlparse(request.url).query)
        if params.get("action") == ["get"]:
            return (200, {"Content-Type": "application/xml"}, get_partial_xml)
        return (200, {"Content-Type": "application/xml"}, submit_xml)

    responses.add_callback(
        responses.GET,
        "https://panorama.local/api/",
        callback=callback,
    )

    monotonic_values = [0.0, 2.0]

    def fake_monotonic():  # noqa: ANN001
        return monotonic_values.pop(0) if monotonic_values else 2.0

    monkeypatch.setattr(palo_alto_module.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(palo_alto_module.time, "sleep", lambda *_args, **_kwargs: None)

    entries = client.traffic_logs_query("APIKEY", query="(query)", nlogs=10, max_wait_seconds=1)

    assert len(entries) == 1
    assert entries[0]["action"] == "deny"
    assert entries[0]["protocol"] == "tcp"


@responses.activate
def test_panorama_traffic_logs_query_timeout_with_no_entries_raises(monkeypatch):
    client = PaloAltoClient("panorama.local", verify_ssl=False)

    submit_xml = """\
<response status="success">
  <result>
    <job>123</job>
  </result>
</response>
"""

    get_empty_incomplete_xml = """\
<response status="success">
  <result>
    <log>
      <logs count="0" progress="0" total="0"/>
    </log>
  </result>
</response>
"""

    def callback(request):  # noqa: ANN001
        params = parse_qs(urlparse(request.url).query)
        if params.get("action") == ["get"]:
            return (200, {"Content-Type": "application/xml"}, get_empty_incomplete_xml)
        return (200, {"Content-Type": "application/xml"}, submit_xml)

    responses.add_callback(
        responses.GET,
        "https://panorama.local/api/",
        callback=callback,
    )

    monotonic_values = [0.0, 2.0]

    def fake_monotonic():  # noqa: ANN001
        return monotonic_values.pop(0) if monotonic_values else 2.0

    monkeypatch.setattr(palo_alto_module.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(palo_alto_module.time, "sleep", lambda *_args, **_kwargs: None)

    with pytest.raises(FirewallLogCheckError) as excinfo:
        client.traffic_logs_query("APIKEY", query="(query)", nlogs=10, max_wait_seconds=1)

    assert "timed out after 1 seconds" in str(excinfo.value)


@responses.activate
def test_panorama_traffic_logs_deny_for_flow_builds_query_from_inputs():
    client = PaloAltoClient("panorama.local", verify_ssl=False)

    observed_params = {}

    def callback(request):  # noqa: ANN001
        params = parse_qs(urlparse(request.url).query)
        observed_params.update({key: values[0] for key, values in params.items()})
        return (200, {"Content-Type": "application/xml"}, PAN_EMPTY_XML)

    responses.add_callback(
        responses.GET,
        "https://panorama.local/api/",
        callback=callback,
    )

    entries = client.traffic_logs_deny_for_flow(
        "APIKEY",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        dst_port=443,
        since_hours=24,
        max_results=10,
    )

    assert entries == []
    assert observed_params["type"] == "log"
    assert observed_params["log-type"] == "traffic"
    assert observed_params["nlogs"] == "10"
    assert "(receive_time in last-24-hrs)" in observed_params["query"]
    assert "(addr.src in 10.0.0.1)" in observed_params["query"]
    assert "(addr.dst in 10.0.0.2)" in observed_params["query"]
    assert "(dport eq 443)" in observed_params["query"]


@responses.activate
def test_panorama_traffic_logs_deny_for_flow_allows_fetch_limit_above_max_results():
    client = PaloAltoClient("panorama.local", verify_ssl=False)

    observed_params = {}

    def callback(request):  # noqa: ANN001
        params = parse_qs(urlparse(request.url).query)
        observed_params.update({key: values[0] for key, values in params.items()})
        return (200, {"Content-Type": "application/xml"}, PAN_EMPTY_XML)

    responses.add_callback(
        responses.GET,
        "https://panorama.local/api/",
        callback=callback,
    )

    entries = client.traffic_logs_deny_for_flow(
        "APIKEY",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        dst_port=443,
        since_hours=24,
        max_results=10,
        fetch_limit=50,
    )

    assert entries == []
    assert observed_params["nlogs"] == "50"


@responses.activate
def test_panorama_traffic_logs_deny_for_flow_filters_non_deny_actions():
    client = PaloAltoClient("panorama.local", verify_ssl=False)

    responses.add(
        responses.GET,
        "https://panorama.local/api/",
        body=PAN_MIXED_ACTION_XML,
        status=200,
        content_type="application/xml",
    )

    entries = client.traffic_logs_deny_for_flow(
        "APIKEY",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        dst_port=443,
        since_hours=24,
        max_results=10,
    )

    assert len(entries) == 1
    assert entries[0]["action"] == "deny"


def test_panorama_traffic_logs_deny_for_flow_rejects_invalid_port():
    client = PaloAltoClient("panorama.local", verify_ssl=False)

    with pytest.raises(FirewallLogCheckError) as excinfo:
        client.traffic_logs_deny_for_flow(
            "APIKEY",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            dst_port="not-a-port",
        )

    assert "Invalid destination port" in str(excinfo.value)
