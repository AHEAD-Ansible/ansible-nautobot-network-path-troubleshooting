"""Custom exceptions for the network path tracing toolkit."""

from __future__ import annotations


class InputValidationError(RuntimeError):
    """Raised when the initial input validation workflow fails."""
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return self.message


class GatewayDiscoveryError(RuntimeError):
    """Raised when locating a default gateway fails."""
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return self.message


class NextHopDiscoveryError(RuntimeError):
    """Raised when next-hop discovery fails."""
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return self.message


class PathTracingError(RuntimeError):
    """Raised when path tracing fails."""
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return self.message