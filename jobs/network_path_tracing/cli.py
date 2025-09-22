"""Command-line helpers for running individual workflow steps."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Optional

from .config import NetworkPathSettings, _DEFAULT_SOURCE_IP, _DEFAULT_DESTINATION_IP
from .exceptions import GatewayDiscoveryError, InputValidationError
from .interfaces.nautobot_api import NautobotAPIDataSource
from .interfaces.nautobot_orm import NautobotORMDataSource
from .steps import GatewayDiscoveryStep, InputValidationStep


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""
    parser = argparse.ArgumentParser(description="Run network path tracing steps from the CLI")
    parser.add_argument(
        "--data-source",
        choices={"api", "orm"},
        default="orm",
        help="Select where to fetch Nautobot data (defaults to orm)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print additional debugging information about API/ORM responses",
    )
    parser.add_argument(
        "--source-ip",
        default=_DEFAULT_SOURCE_IP,
        help=f"Source IP address (default: {_DEFAULT_SOURCE_IP})",
    )
    parser.add_argument(
        "--destination-ip",
        default=_DEFAULT_DESTINATION_IP,
        help=f"Destination IP address (default: {_DEFAULT_DESTINATION_IP})",
    )
    return parser


def select_data_source(settings: NetworkPathSettings, source: str) -> Any:
    """Return the configured Nautobot data source implementation."""
    if source == "api":
        api_settings = settings.api_settings()
        if not api_settings:
            raise RuntimeError(
                "Nautobot API is not configured. Set NAUTOBOT_API_URL and NAUTOBOT_API_TOKEN."
            )
        return NautobotAPIDataSource(api_settings)
    if source == "orm":
        return NautobotORMDataSource()
    raise RuntimeError(f"Unsupported data source '{source}'")


def run_steps(
    settings: NetworkPathSettings | None = None,
    data_source: str = "orm",
    debug: bool = False,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
) -> dict[str, Any]:
    """Execute steps 1 and 2 and return a JSON-serializable payload."""
    if settings is None:
        kwargs = {}
        if source_ip:
            kwargs["source_ip"] = source_ip
        if destination_ip:
            kwargs["destination_ip"] = destination_ip
        settings = NetworkPathSettings(**kwargs)
    else:
        if source_ip or destination_ip:
            settings = NetworkPathSettings(
                source_ip=source_ip or settings.source_ip,
                destination_ip=destination_ip or settings.destination_ip,
                api=settings.api,
                gateway_custom_field=settings.gateway_custom_field,
                pa=settings.pa,
                napalm=settings.napalm,
            )

    source = select_data_source(settings, data_source)

    print(f"Running validation for source_ip={settings.source_ip}, destination_ip={settings.destination_ip}")
    validation_step = InputValidationStep(source)
    try:
        validation = validation_step.run(settings)
    except InputValidationError as exc:
        raise InputValidationError(f"Validation failed: {exc}") from exc

    print(f"Running gateway discovery for prefix={validation.source_prefix.prefix}")
    gateway_step = GatewayDiscoveryStep(source, settings.gateway_custom_field)
    gateway = gateway_step.run(validation)

    payload = {
        "status": "ok",
        "source": {
            "address": validation.source_ip,
            "prefix_length": validation.source_record.prefix_length,
            "prefix": validation.source_prefix.prefix,
            "device_name": validation.source_record.device_name,
            "interface_name": validation.source_record.interface_name,
            "is_host_ip": validation.is_host_ip,
        },
        "gateway": {
            "found": gateway.found,
            "method": gateway.method,
            "address": gateway.gateway.address if gateway.gateway else None,
            "device_name": gateway.gateway.device_name if gateway.gateway else None,
            "interface_name": gateway.gateway.interface_name if gateway.gateway else None,
            "details": gateway.details,
        },
    }

    if debug:
        payload["debug"] = {
            "source_record": validation.source_record.__dict__,
            "source_prefix": validation.source_prefix.__dict__,
            "gateway_record": gateway.gateway.__dict__ if gateway.gateway else None,
        }

    return payload


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for invoking individual workflow steps."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        payload = run_steps(
            data_source=args.data_source,
            debug=args.debug,
            source_ip=args.source_ip,
            destination_ip=args.destination_ip,
        )
    except InputValidationError as exc:
        payload = {"status": "error", "error": str(exc)}
        print(json.dumps(payload, indent=2), file=sys.stdout)
        return 1
    except GatewayDiscoveryError as exc:
        payload = {"status": "error", "error": str(exc)}
        print(json.dumps(payload, indent=2), file=sys.stdout)
        return 1
    except Exception as exc:  # pragma: no cover - CLI guard
        payload = {"status": "error", "error": str(exc)}
        print(json.dumps(payload, indent=2), file=sys.stdout)
        return 2

    print(json.dumps(payload, indent=2), file=sys.stdout)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())