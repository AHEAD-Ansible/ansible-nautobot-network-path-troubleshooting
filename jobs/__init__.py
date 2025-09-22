"""Core package for modular network path tracing components."""

from .network_path_tracing.config import NautobotAPISettings, NetworkPathSettings, PaloAltoSettings, NapalmSettings
from .network_path_tracing.exceptions import GatewayDiscoveryError, InputValidationError, NextHopDiscoveryError, PathTracingError
from .network_path_tracing.interfaces.nautobot import IPAddressRecord, PrefixRecord, DeviceRecord, NautobotDataSource
from .network_path_tracing.interfaces.nautobot_api import NautobotAPIDataSource
from .network_path_tracing.interfaces.nautobot_orm import NautobotORMDataSource
from .network_path_tracing.interfaces.palo_alto import PaloAltoClient
from .network_path_tracing.steps.gateway_discovery import GatewayDiscoveryResult, GatewayDiscoveryStep
from .network_path_tracing.steps.input_validation import InputValidationResult, InputValidationStep
from .network_path_tracing.steps.next_hop_discovery import NextHopDiscoveryResult, NextHopDiscoveryStep
from .network_path_tracing.steps.path_tracing import PathHop, Path, PathTracingResult, PathTracingStep

__all__ = [
    "NautobotAPISettings",
    "NetworkPathSettings",
    "PaloAltoSettings",
    "NapalmSettings",
    "GatewayDiscoveryError",
    "InputValidationError",
    "NextHopDiscoveryError",
    "PathTracingError",
    "IPAddressRecord",
    "PrefixRecord",
    "DeviceRecord",
    "NautobotDataSource",
    "NautobotAPIDataSource",
    "NautobotORMDataSource",
    "PaloAltoClient",
    "GatewayDiscoveryResult",
    "GatewayDiscoveryStep",
    "InputValidationResult",
    "InputValidationStep",
    "NextHopDiscoveryResult",
    "NextHopDiscoveryStep",
    "PathHop",
    "Path",
    "PathTracingResult",
    "PathTracingStep",
]