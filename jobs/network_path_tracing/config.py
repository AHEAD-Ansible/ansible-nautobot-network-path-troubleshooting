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
        return bool(self.base_url and self.token)


@dataclass(frozen=True)
class PaloAltoSettings:
    """Settings for connecting to Palo Alto devices."""
    username: str = os.getenv("PA_USERNAME", "")
    password: str = os.getenv("PA_PASSWORD", "")
    verify_ssl: bool = _env_flag("PA_VERIFY_SSL", False)

    def is_configured(self) -> bool:
        return bool(self.username and self.password)


@dataclass(frozen=True)
class NapalmSettings:
    """Settings for NAPALM connections."""
    username: str = os.getenv("NAPALM_USERNAME", "")
    password: str = os.getenv("NAPALM_PASSWORD", "")

    def is_configured(self) -> bool:
        return bool(self.username and self.password)


@dataclass(frozen=True)
class NetworkPathSettings:
    """Container for runtime settings used by the path tracing workflow."""
    source_ip: str = os.getenv("NETWORK_PATH_SOURCE_IP", _DEFAULT_SOURCE_IP)
    destination_ip: str = os.getenv("NETWORK_PATH_DESTINATION_IP", _DEFAULT_DESTINATION_IP)
    api: NautobotAPISettings = NautobotAPISettings()
    gateway_custom_field: str = os.getenv("NETWORK_PATH_GATEWAY_CF", _DEFAULT_GATEWAY_CUSTOM_FIELD)
    pa: PaloAltoSettings = PaloAltoSettings()
    napalm: NapalmSettings = NapalmSettings()

    def as_tuple(self) -> tuple[str, str]:
        return self.source_ip, self.destination_ip

    def api_settings(self) -> Optional[NautobotAPISettings]:
        if self.api.is_configured():
            return self.api
        return None

    def pa_settings(self) -> Optional[PaloAltoSettings]:
        if self.pa.is_configured():
            return self.pa
        return None

    def napalm_settings(self) -> Optional[NapalmSettings]:
        if self.napalm.is_configured():
            return self.napalm
        return None