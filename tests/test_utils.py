from __future__ import annotations

import socket

import pytest

from jobs.network_path_tracing.utils import resolve_target_to_ipv4
from jobs.network_path_tracing import InputValidationError


def test_resolve_target_to_ipv4_returns_same_ip():
    assert resolve_target_to_ipv4("192.0.2.1", "source") == "192.0.2.1"
    assert resolve_target_to_ipv4("192.0.2.1/24", "source") == "192.0.2.1"


def test_resolve_target_to_ipv4_hostname_success(monkeypatch):
    expected_ip = "198.51.100.10"

    def mock_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        assert host == "example.local"
        assert family == socket.AF_INET
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (expected_ip, 0)),
            (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("203.0.113.5", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

    resolved = resolve_target_to_ipv4("example.local", "source")
    assert resolved == expected_ip


def test_resolve_target_to_ipv4_hostname_failure(monkeypatch):
    def mock_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        raise socket.gaierror("lookups failed")

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

    with pytest.raises(InputValidationError) as exc:
        resolve_target_to_ipv4("missing.local", "destination")
    assert "Unable to resolve destination hostname 'missing.local'" in str(exc.value)


def test_resolve_target_to_ipv4_rejects_ipv6():
    with pytest.raises(InputValidationError) as exc:
        resolve_target_to_ipv4("2001:db8::1", "source")
    assert "IPv6" in str(exc.value)
