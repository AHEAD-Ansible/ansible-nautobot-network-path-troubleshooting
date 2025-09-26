"""Command-line helpers for running the network path tracing workflow."""

from __future__ import annotations

import argparse
import json
import sys
from getpass import getpass
from pathlib import Path
from typing import Any, Optional

from .config import NapalmSettings, NetworkPathSettings, _DEFAULT_DESTINATION_IP, _DEFAULT_SOURCE_IP
from .exceptions import (
    GatewayDiscoveryError,
    InputValidationError,
    NextHopDiscoveryError,
    PathTracingError,
)
from .graph import build_pyvis_network
from .interfaces.nautobot_api import NautobotAPIDataSource
from .interfaces.nautobot_orm import NautobotORMDataSource
from .steps import (
    GatewayDiscoveryStep,
    InputValidationStep,
    NextHopDiscoveryStep,
    PathTracingStep,
)


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Run network path tracing steps from the CLI"
    )
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
    parser.add_argument(
        "--visualize-html",
        help=(
            "Optional output path for a PyVis HTML file representing the traced graph. "
            "Only generated if a path is found."
        ),
    )
    parser.add_argument(
        "--napalm-username",
        help="Override the NAPALM username instead of relying on environment variables",
    )
    parser.add_argument(
        "--napalm-password",
        help="Override the NAPALM password (use with caution; consider --napalm-prompt-password instead)",
    )
    parser.add_argument(
        "--napalm-prompt-password",
        action="store_true",
        help="Prompt securely for the NAPALM password if not supplied",
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
    visualize_html: Optional[str] = None,
    napalm_username: Optional[str] = None,
    napalm_password: Optional[str] = None,
) -> dict[str, Any]:
    """Execute the full workflow and return a JSON-serializable payload."""
    base_settings = settings or NetworkPathSettings()

    effective_source_ip = source_ip or base_settings.source_ip
    effective_destination_ip = destination_ip or base_settings.destination_ip

    base_napalm = base_settings.napalm
    effective_napalm = NapalmSettings(
        username=napalm_username or base_napalm.username,
        password=napalm_password or base_napalm.password,
    )

    settings = NetworkPathSettings(
        source_ip=effective_source_ip,
        destination_ip=effective_destination_ip,
        api=base_settings.api,
        gateway_custom_field=base_settings.gateway_custom_field,
        pa=base_settings.pa,
        napalm=effective_napalm,
    )

    source = select_data_source(settings, data_source)

    print(
        f"Running validation for source_ip={settings.source_ip}, destination_ip={settings.destination_ip}"
    )
    validation_step = InputValidationStep(source)
    try:
        validation = validation_step.run(settings)
    except InputValidationError as exc:
        raise InputValidationError(f"Validation failed: {exc}") from exc

    print(f"Running gateway discovery for prefix={validation.source_prefix.prefix}")
    gateway_step = GatewayDiscoveryStep(source, settings.gateway_custom_field)
    gateway = gateway_step.run(validation)

    next_hop_step = NextHopDiscoveryStep(source, settings)
    path_tracing_step = PathTracingStep(source, settings, next_hop_step)

    path_result = path_tracing_step.run(validation, gateway)

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
        "paths": [
            {
                "path": index,
                "hops": [
                    {
                        "device_name": hop.device_name,
                        "ingress_interface": hop.interface_name,
                        "egress_interface": hop.egress_interface,
                        "next_hop_ip": hop.next_hop_ip,
                        "details": hop.details,
                    }
                    for hop in path.hops
                ],
                "reached_destination": path.reached_destination,
                "issues": path.issues,
            }
            for index, path in enumerate(path_result.paths, start=1)
        ],
        "issues": path_result.issues,
    }

    if debug:
        payload["debug"] = {
            "source_record": validation.source_record.__dict__,
            "source_prefix": validation.source_prefix.__dict__,
            "gateway_record": gateway.gateway.__dict__ if gateway.gateway else None,
        }
        if path_result.graph:
            payload["debug"]["graph"] = path_result.graph.serialize()

    if visualize_html and path_result.graph and path_result.graph.graph.number_of_nodes() > 0:
        destination = Path(visualize_html).expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        net = build_pyvis_network(path_result.graph)
        net.save_graph(destination.as_posix())
        payload.setdefault("visualization", {})["pyvis_html"] = destination.as_posix()

    return payload


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for invoking individual workflow steps."""
    parser = build_parser()
    args = parser.parse_args(argv)

    napalm_password = args.napalm_password
    if args.napalm_prompt_password and not napalm_password:
        napalm_password = getpass("NAPALM password: ")

    try:
        payload = run_steps(
            data_source=args.data_source,
            debug=args.debug,
            source_ip=args.source_ip,
            destination_ip=args.destination_ip,
            visualize_html=args.visualize_html,
            napalm_username=args.napalm_username,
            napalm_password=napalm_password,
        )
    except InputValidationError as exc:
        payload = {"status": "error", "error": str(exc)}
        print(json.dumps(payload, indent=2), file=sys.stdout)
        return 1
    except GatewayDiscoveryError as exc:
        payload = {"status": "error", "error": str(exc)}
        print(json.dumps(payload, indent=2), file=sys.stdout)
        return 1
    except NextHopDiscoveryError as exc:
        payload = {"status": "error", "error": str(exc)}
        print(json.dumps(payload, indent=2), file=sys.stdout)
        return 1
    except PathTracingError as exc:
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
