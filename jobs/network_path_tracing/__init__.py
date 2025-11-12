"""Core package for modular network path tracing components."""

from .config import NautobotAPISettings, NetworkPathSettings, PaloAltoSettings, NapalmSettings, F5Settings
from .exceptions import GatewayDiscoveryError, InputValidationError, NextHopDiscoveryError, PathTracingError
from .interfaces.nautobot import (
    IPAddressRecord,
    PrefixRecord,
    DeviceRecord,
    NautobotDataSource,
    RedundancyMember,
    RedundancyResolution,
)
from .interfaces.nautobot_api import NautobotAPIDataSource
from .interfaces.nautobot_orm import NautobotORMDataSource
from .interfaces.palo_alto import PaloAltoClient
from .interfaces.f5_bigip import F5Client, F5NextHopSummary, F5APIError
from .steps.gateway_discovery import GatewayDiscoveryResult, GatewayDiscoveryStep
from .steps.input_validation import InputValidationResult, InputValidationStep
from .steps.next_hop_discovery import NextHopDiscoveryResult, NextHopDiscoveryStep
from .graph import NetworkPathGraph, build_pyvis_network
from .steps.path_tracing import PathHop, Path, PathTracingResult, PathTracingStep
from .utils import resolve_target_to_ipv4


__all__ = [
    "NautobotAPISettings",
    "NetworkPathSettings",
    "PaloAltoSettings",
    "NapalmSettings",
    "F5Settings",
    "InputValidationError",
    "GatewayDiscoveryError",
    "NextHopDiscoveryError",
    "PathTracingError",
    "IPAddressRecord",
    "PrefixRecord",
    "DeviceRecord",
    "NautobotDataSource",
    "RedundancyMember",
    "RedundancyResolution",
    "NautobotAPIDataSource",
    "NautobotORMDataSource",
    "PaloAltoClient",
    "F5Client",
    "F5APIError",
    "F5NextHopSummary",
    "InputValidationResult",
    "InputValidationStep",
    "GatewayDiscoveryResult",
    "GatewayDiscoveryStep",
    "NextHopDiscoveryResult",
    "NextHopDiscoveryStep",
    "PathHop",
    "Path",
    "PathTracingResult",
    "PathTracingStep",
    "NetworkPathGraph",
    "build_pyvis_network",
    "resolve_target_to_ipv4",
]
