"""Utility helpers for network path tracing workflows."""

from __future__ import annotations

import ipaddress
import socket

from .exceptions import InputValidationError


def resolve_target_to_ipv4(value: str, field_label: str) -> str:
    """Resolve a user-supplied IP address or hostname to an IPv4 string."""

    raw_input = (value or "").strip()
    if not raw_input:
        raise InputValidationError(f"Missing {field_label} IP address or hostname.")

    candidate = raw_input.split("/")[0].strip()

    try:
        ip_obj = ipaddress.ip_address(candidate)
    except ValueError:
        ip_obj = None
    else:
        if ip_obj.version != 4:
            raise InputValidationError(
                f"{field_label.capitalize()} '{raw_input}' resolved to IPv6, which is not supported."
            )
        return candidate

    try:
        addr_info = socket.getaddrinfo(candidate, None, family=socket.AF_INET)
    except socket.gaierror as exc:
        raise InputValidationError(
            f"Unable to resolve {field_label} hostname '{raw_input}' to an IPv4 address."
        ) from exc

    for entry in addr_info:
        sockaddr = entry[4]
        if sockaddr and sockaddr[0]:
            return sockaddr[0]

    raise InputValidationError(
        f"Unable to resolve {field_label} hostname '{raw_input}' to an IPv4 address."
    )


__all__ = ["resolve_target_to_ipv4"]
