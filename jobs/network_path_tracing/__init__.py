"""Core package for modular network path tracing components."""

from .config import NautobotAPISettings, NetworkPathSettings, PaloAltoSettings, NapalmSettings
from .exceptions import GatewayDiscoveryError, InputValidationError, NextHopDiscoveryError, PathTracingError
from .interfaces.nautobot import IPAddressRecord, PrefixRecord, DeviceRecord, NautobotDataSource
from .interfaces.nautobot_api import NautobotAPIDataSource
from .interfaces.nautobot_orm import NautobotORMDataSource
from .interfaces.palo_alto import PaloAltoClient
from .steps.gateway_discovery import GatewayDiscoveryResult, GatewayDiscoveryStep
from .steps.input_validation import InputValidationResult, InputValidationStep
from .steps.next_hop_discovery import NextHopDiscoveryResult, NextHopDiscoveryStep
from .steps.path_tracing import PathHop, Path, PathTracingResult, PathTracingStep


__all__ = [
    "NautobotAPISettings",
    "NetworkPathSettings",
    "PaloAltoSettings",
    "NapalmSettings",
    "InputValidationError",
    "GatewayDiscoveryError",
    "NextHopDiscoveryError",
    "PathTracingError",
    "IPAddressRecord",
    "PrefixRecord",
    "DeviceRecord",
    "NautobotDataSource",
    "NautobotAPIDataSource",
    "NautobotORMDataSource",
    "PaloAltoClient",
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
]