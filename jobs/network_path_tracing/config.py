"""Configuration helpers for the network path tracing toolkit."""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Optional

_DEFAULT_SOURCE_IP = "10.100.100.100"
_DEFAULT_DESTINATION_IP = "10.200.200.200"
_DEFAULT_GATEWAY_CUSTOM_FIELD = "network_gateway"


def _env_flag(name: str, default: bool = True) -> bool:
    """Return a boolean flag based on common truthy/falsey strings."""

    value = os.getenv(name)
    if value is None:
        return default

    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class NautobotAPISettings:
    """Settings that describe how to reach the Nautobot REST API."""

    base_url: str = os.getenv("NAUTOBOT_API_URL", "http://192.168.100.10:8085/")
    token: str = os.getenv("NAUTOBOT_API_TOKEN", "0123456789abcdef0123456789abcdef01234567")
    verify_ssl: bool = _env_flag("NAUTOBOT_API_VERIFY_SSL", False)

    def is_configured(self) -> bool:
        """Check whether we have enough details to make API calls."""

        return bool(self.base_url and self.token)


@dataclass(frozen=True)
class NetworkPathSettings:
    """Container for runtime settings used by the path tracing workflow.

    The defaults keep the module runnable in local tooling while still allowing
    Nautobot job parameters or environment variables to override values when
    running in production.
    """

    source_ip: str = os.getenv("NETWORK_PATH_SOURCE_IP", _DEFAULT_SOURCE_IP)
    destination_ip: str = os.getenv("NETWORK_PATH_DESTINATION_IP", _DEFAULT_DESTINATION_IP)
    api: NautobotAPISettings = NautobotAPISettings()
    gateway_custom_field: str = os.getenv(
        "NETWORK_PATH_GATEWAY_CF", _DEFAULT_GATEWAY_CUSTOM_FIELD
    )

    def as_tuple(self) -> tuple[str, str]:
        """Return the configured source/destination pair."""

        return self.source_ip, self.destination_ip

    def api_settings(self) -> Optional[NautobotAPISettings]:
        """Return API configuration if the required values are present."""

        if self.api.is_configured():
            return self.api
        return None
