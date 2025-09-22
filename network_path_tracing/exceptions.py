"""Custom exceptions for the network path tracing toolkit."""

from __future__ import annotations


class InputValidationError(RuntimeError):
    """Raised when the initial input validation workflow fails."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:  # pragma: no cover - simple accessor
        return self.message


class GatewayDiscoveryError(RuntimeError):
    """Raised when locating a default gateway fails."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:  # pragma: no cover - simple accessor
        return self.message
