from urllib.parse import parse_qs, urlparse

import pytest
import responses

from network_path_tracing.config import NautobotAPISettings
from network_path_tracing.interfaces.nautobot import PrefixRecord
from network_path_tracing.interfaces.nautobot_api import NautobotAPIDataSource


@pytest.fixture()
def api_settings() -> NautobotAPISettings:
    return NautobotAPISettings(
        base_url="http://nautobot.local/",
        token="token",
        verify_ssl=False,
    )


@pytest.fixture()
def data_source(api_settings) -> NautobotAPIDataSource:
    return NautobotAPIDataSource(api_settings)


@pytest.fixture()
def gateway_payload():
    return {
        "results": [
            {
                "id": "ip-uuid",
                "address": "10.10.10.1/24",
                "host": "10.10.10.1",
                "prefix_length": 24,
                "assigned_object": {
                    "name": "Gig0/0",
                    "device": {"name": "gw-device"},
                },
            }
        ]
    }


@responses.activate
def test_find_gateway_uses_prefix_id(data_source, gateway_payload):
    prefix = PrefixRecord(prefix="10.10.10.0/24", status="active", id="prefix-uuid")

    responses.add(
        "GET",
        "http://nautobot.local/api/ipam/ip-addresses/",
        json=gateway_payload,
        status=200,
    )

    record = data_source.find_gateway_ip(prefix, "network_gateway")

    assert record is not None
    assert record.address == "10.10.10.1"
    assert record.device_name == "gw-device"
    assert record.interface_name == "Gig0/0"

    called_url = responses.calls[0].request.url
    params = parse_qs(urlparse(called_url).query)
    assert params.get("parent") == ["prefix-uuid"]
    assert params.get("cf_network_gateway") == ["True"]


@responses.activate
def test_find_gateway_fetches_prefix_id_when_missing(data_source, gateway_payload):
    prefix = PrefixRecord(prefix="10.10.10.0/24", status="active", id=None)

    responses.add(
        "GET",
        "http://nautobot.local/api/ipam/prefixes/",
        json={
            "results": [
                {"id": "resolved-uuid", "prefix": "10.10.10.0/24"}
            ]
        },
        status=200,
    )
    responses.add(
        "GET",
        "http://nautobot.local/api/ipam/ip-addresses/",
        json=gateway_payload,
        status=200,
    )

    data_source.find_gateway_ip(prefix, "network_gateway")

    assert len(responses.calls) == 2
    second_url = responses.calls[1].request.url
    params = parse_qs(urlparse(second_url).query)
    assert params.get("parent") == ["resolved-uuid"]


@responses.activate
def test_get_ip_address_returns_enriched_record(data_source):
    responses.add(
        "GET",
        "http://nautobot.local/api/ipam/ip-addresses/",
        json={
            "results": [
                {
                    "id": "ip-uuid",
                    "address": "10.10.10.10/24",
                    "host": "10.10.10.10",
                    "prefix_length": 24,
                    "assigned_object": {
                        "name": "Gig0/1",
                        "device": {"name": "server-1"},
                    },
                }
            ]
        },
        status=200,
    )

    record = data_source.get_ip_address("10.10.10.10")
    assert record is not None
    assert record.address == "10.10.10.10"
    assert record.device_name == "server-1"
    assert record.interface_name == "Gig0/1"


@responses.activate
def test_find_gateway_returns_none_when_not_found(data_source):
    prefix = PrefixRecord(prefix="10.10.10.0/24", status="active", id="prefix-uuid")

    responses.add(
        "GET",
        "http://nautobot.local/api/ipam/ip-addresses/",
        json={"results": []},
        status=200,
    )

    assert data_source.find_gateway_ip(prefix, "network_gateway") is None
