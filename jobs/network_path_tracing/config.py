"""Configuration helpers for the network path tracing toolkit."""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Optional, Sequence


_DEFAULT_SOURCE_IP = "10.100.100.100"
_DEFAULT_DESTINATION_IP = "10.200.200.200"
_DEFAULT_GATEWAY_CUSTOM_FIELD = "network_gateway"
_DEFAULT_LAYER2_MAX_DEPTH = 3


def _env_flag(name: str, default: bool = True) -> bool:
    """Return a boolean flag based on common truthy/falsey strings."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_csv(name: str) -> tuple[str, ...]:
    """Return a tuple of non-empty values split by comma."""
    value = os.getenv(name)
    if not value:
        return ()
    parts = [item.strip() for item in value.split(",")]
    return tuple(part for part in parts if part)


def _env_int(name: str, default: int) -> int:
    """Return integer value from environment or default."""
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value.strip())
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class NautobotAPISettings:
    """Settings for reaching the Nautobot REST API."""
    base_url: str = os.getenv("NAUTOBOT_API_URL", "http://192.168.100.10:8085/")
    token: str = os.getenv("NAUTOBOT_API_TOKEN", "0123456789abcdef0123456789abcdef01234567")
    verify_ssl: bool = _env_flag("NAUTOBOT_API_VERIFY_SSL", False)

    def is_configured(self) -> bool:
        """Check if API settings are valid."""
        return bool(self.base_url and self.token)


@dataclass(frozen=True)
class PaloAltoSettings:
    """Settings for connecting to Palo Alto devices."""
    username: str = os.getenv("PA_USERNAME", "")
    password: str = os.getenv("PA_PASSWORD", "")
    verify_ssl: bool = _env_flag("PA_VERIFY_SSL", False)

    def is_configured(self) -> bool:
        """Check if Palo Alto credentials are valid."""
        return bool(self.username and self.password)


@dataclass(frozen=True)
class NapalmSettings:
    """Settings for NAPALM connections."""
    username: str = os.getenv("NAPALM_USERNAME", "")
    password: str = os.getenv("NAPALM_PASSWORD", "")

    def is_configured(self) -> bool:
        """Check if NAPALM credentials are valid."""
        return bool(self.username and self.password)


@dataclass(frozen=True)
class F5Settings:
    """Settings for connecting to F5 BIG-IP devices."""
    username: str = os.getenv("F5_USERNAME", "")
    password: str = os.getenv("F5_PASSWORD", "")
    verify_ssl: bool = _env_flag("F5_VERIFY_SSL", False)
    partitions: tuple[str, ...] = _env_csv("F5_PARTITIONS")

    def is_configured(self) -> bool:
        """Check if BIG-IP credentials are available."""
        return bool(self.username and self.password)

    def partitions_list(self) -> Optional[Sequence[str]]:
        """Return configured partitions if provided."""
        return self.partitions or None


@dataclass(frozen=True)
class NetworkPathSettings:
    """Runtime settings for the path tracing workflow."""
    source_ip: str = os.getenv("NETWORK_PATH_SOURCE_IP", _DEFAULT_SOURCE_IP)
    destination_ip: str = os.getenv("NETWORK_PATH_DESTINATION_IP", _DEFAULT_DESTINATION_IP)
    api: NautobotAPISettings = NautobotAPISettings()
    gateway_custom_field: str = os.getenv("NETWORK_PATH_GATEWAY_CF", _DEFAULT_GATEWAY_CUSTOM_FIELD)
    pa: PaloAltoSettings = PaloAltoSettings()
    napalm: NapalmSettings = NapalmSettings()
    f5: F5Settings = F5Settings()
    enable_layer2_discovery: bool = _env_flag("NETWORK_PATH_ENABLE_LAYER2", True)
    layer2_max_depth: int = _env_int("NETWORK_PATH_LAYER2_MAX_DEPTH", _DEFAULT_LAYER2_MAX_DEPTH)

    def as_tuple(self) -> tuple[str, str]:
        """Return source and destination IPs as a tuple."""
        return self.source_ip, self.destination_ip

    def api_settings(self) -> Optional[NautobotAPISettings]:
        """Return API settings if configured, else None."""
        return self.api if self.api.is_configured() else None

    def pa_settings(self) -> Optional[PaloAltoSettings]:
        """Return Palo Alto settings if configured, else None."""
        return self.pa if self.pa.is_configured() else None

    def napalm_settings(self) -> Optional[NapalmSettings]:
        """Return NAPALM settings if configured, else None."""
        return self.napalm if self.napalm.is_configured() else None

    def f5_settings(self) -> Optional[F5Settings]:
        """Return F5 BIG-IP settings if configured, else None."""
        return self.f5 if self.f5.is_configured() else None
