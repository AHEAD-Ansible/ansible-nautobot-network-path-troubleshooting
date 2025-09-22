"""Core package for modular network path tracing components."""

from .config import NautobotAPISettings, NetworkPathSettings, PaloAltoSettings, NapalmSettings
from .exceptions import GatewayDiscoveryError, InputValidationError, NextHopDiscoveryError, PathTracingError
from .interfaces.nautobot_api import NautobotAPIDataSource
from .interfaces.nautobot_orm import NautobotORMDataSource
from .steps.gateway_discovery import GatewayDiscoveryResult, GatewayDiscoveryStep
from .steps.input_validation import InputValidationResult, InputValidationStep
from .steps.next_hop_discovery import NextHopDiscoveryResult, NextHopDiscoveryStep
from .steps.path_tracing import PathTracingResult, PathTracingStep

__all__ = [
    "NetworkPathSettings",
    "NautobotAPISettings",
    "PaloAltoSettings",
    "NapalmSettings",
    "InputValidationError",
    "GatewayDiscoveryError",
    "NextHopDiscoveryError",
    "PathTracingError",
    "InputValidationResult",
    "InputValidationStep",
    "GatewayDiscoveryResult",
    "GatewayDiscoveryStep",
    "NextHopDiscoveryResult",
    "NextHopDiscoveryStep",
    "PathTracingResult",
    "PathTracingStep",
    "NautobotAPIDataSource",
    "NautobotORMDataSource",
]