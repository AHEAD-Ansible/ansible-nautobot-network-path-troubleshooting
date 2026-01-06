"""Command-line helpers for running the network path tracing workflow."""

from __future__ import annotations

import argparse
import json
import os
import sys
from getpass import getpass
from pathlib import Path
from typing import Any, Dict, Optional
import ipaddress

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
    FirewallLogCheckStep,
    GatewayDiscoveryStep,
    InputValidationStep,
    NextHopDiscoveryStep,
    PathTracingStep,
    PathHop,
    Path as TracedPath,
)
from .utils import resolve_target_to_ipv4


def _hop_to_payload(hop: PathHop) -> Dict[str, Any]:
    """Serialize PathHop instances for CLI output."""

    payload: Dict[str, Any] = {
        "device_name": hop.device_name,
        "ingress_interface": hop.interface_name,
        "egress_interface": hop.egress_interface,
        "next_hop_ip": hop.next_hop_ip,
        "details": hop.details,
    }
    include_vrf = hop.hop_type != "layer2"
    if include_vrf and hop.interface_name:
        payload["ingress_vrf"] = PathTracingStep._vrf_or_global(hop.ingress_vrf)
    if include_vrf and hop.egress_interface:
        payload["egress_vrf"] = PathTracingStep._vrf_or_global(hop.egress_vrf)
    for key, value in (hop.extras or {}).items():
        if value is None:
            continue
        if key in payload and payload[key] not in (None, "", []):
            continue
        payload[key] = value
    return payload


def _build_destination_summary(paths: list[TracedPath]) -> Optional[Dict[str, Any]]:
    """Return minimal destination details from the first successful path."""

    for path in paths:
        if not path.reached_destination or not path.hops:
            continue
        last_hop = path.hops[-1]
        if not last_hop.next_hop_ip:
            continue
        return {
            "address": last_hop.next_hop_ip,
            "device_name": last_hop.device_name,
        }
    return None


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
        help=f"Source IP address or hostname (default: {_DEFAULT_SOURCE_IP})",
    )
    parser.add_argument(
        "--destination-ip",
        default=_DEFAULT_DESTINATION_IP,
        help=f"Destination IP address or hostname (default: {_DEFAULT_DESTINATION_IP})",
    )
    parser.add_argument(
        "--check-panorama-logs",
        action="store_true",
        help=(
            "Enable Panorama traffic log check for DENY entries matching src/dst/--log-port "
            "(last 24h, default max 10 results; see --panorama-log-* options to tune)."
        ),
    )
    parser.add_argument(
        "--panorama-host",
        help="Panorama hostname/IP for log check (or set PANORAMA_HOST). Required with --check-panorama-logs.",
    )
    parser.add_argument(
        "--log-port",
        type=int,
        help="Destination port to match in Panorama traffic logs (0-65535). Required with --check-panorama-logs.",
    )
    parser.add_argument(
        "--panorama-log-max-wait-seconds",
        type=int,
        help=(
            "Optional: max seconds to wait for Panorama async traffic-log queries "
            "(default: PANORAMA_LOG_QUERY_MAX_WAIT_SECONDS or 30)."
        ),
    )
    parser.add_argument(
        "--panorama-log-fetch-limit",
        type=int,
        help=(
            "Optional: number of matching traffic log rows to fetch before filtering for DENY "
            "(default: PANORAMA_LOG_QUERY_FETCH_LIMIT or 10)."
        ),
    )
    parser.add_argument(
        "--panorama-log-max-results",
        type=int,
        help="Optional: maximum number of DENY log entries to return (default: 10).",
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
    check_panorama_logs: bool = False,
    panorama_host: Optional[str] = None,
    log_port: Optional[int] = None,
    panorama_log_max_wait_seconds: Optional[int] = None,
    panorama_log_fetch_limit: Optional[int] = None,
    panorama_log_max_results: Optional[int] = None,
    visualize_html: Optional[str] = None,
    napalm_username: Optional[str] = None,
    napalm_password: Optional[str] = None,
) -> dict[str, Any]:
    """Execute the full workflow and return a JSON-serializable payload."""
    base_settings = settings or NetworkPathSettings()

    source_input = (source_ip if source_ip is not None else base_settings.source_ip).strip()
    destination_input = (destination_ip if destination_ip is not None else base_settings.destination_ip).strip()

    resolved_source_ip = resolve_target_to_ipv4(source_input, "source")
    resolved_destination_ip = resolve_target_to_ipv4(destination_input, "destination")

    source_candidate = source_input.split("/")[0].strip()
    destination_candidate = destination_input.split("/")[0].strip()

    if source_candidate and source_candidate != resolved_source_ip:
        try:
            ipaddress.ip_address(source_candidate)
        except ValueError:
            print(f"Resolved source hostname '{source_input}' to IPv4 address {resolved_source_ip}")

    if destination_candidate and destination_candidate != resolved_destination_ip:
        try:
            ipaddress.ip_address(destination_candidate)
        except ValueError:
            print(f"Resolved destination hostname '{destination_input}' to IPv4 address {resolved_destination_ip}")

    base_napalm = base_settings.napalm
    effective_napalm = NapalmSettings(
        username=napalm_username or base_napalm.username,
        password=napalm_password or base_napalm.password,
    )

    settings = NetworkPathSettings(
        source_ip=resolved_source_ip,
        destination_ip=resolved_destination_ip,
        api=base_settings.api,
        gateway_custom_field=base_settings.gateway_custom_field,
        pa=base_settings.pa,
        napalm=effective_napalm,
        f5=base_settings.f5,
    )

    resolved_panorama_host: Optional[str] = None
    firewall_logs = FirewallLogCheckStep.disabled_payload()
    if check_panorama_logs:
        resolved_panorama_host = (panorama_host or os.getenv("PANORAMA_HOST", "")).strip()
        if not resolved_panorama_host:
            raise InputValidationError(
                "Panorama log check enabled but no host provided (use --panorama-host or set PANORAMA_HOST)."
            )
        if log_port is None:
            raise InputValidationError(
                "Panorama log check enabled but --log-port was not provided."
            )
        if log_port < 0 or log_port > 65535:
            raise InputValidationError("--log-port must be an integer in range 0-65535.")
        if panorama_log_max_wait_seconds is not None and panorama_log_max_wait_seconds < 1:
            raise InputValidationError("--panorama-log-max-wait-seconds must be >= 1.")
        if panorama_log_fetch_limit is not None and panorama_log_fetch_limit < 1:
            raise InputValidationError("--panorama-log-fetch-limit must be >= 1.")
        if panorama_log_max_results is not None and panorama_log_max_results < 1:
            raise InputValidationError("--panorama-log-max-results must be >= 1.")

    source = select_data_source(settings, data_source)

    print(
        f"Running validation for source_ip={settings.source_ip}, destination_ip={settings.destination_ip}"
    )
    validation_step = InputValidationStep(source)
    try:
        validation = validation_step.run(settings)
    except InputValidationError as exc:
        raise InputValidationError(f"Validation failed: {exc}") from exc

    if not validation.source_found:
        print(
            f"Source IP {settings.source_ip} not found in Nautobot; continuing with prefix-based lookup."
        )

    destination_found = source.get_ip_address(settings.destination_ip) is not None
    if not destination_found:
        print(
            f"Destination IP {settings.destination_ip} not found in Nautobot; proceeding without destination metadata."
        )

    print(f"Running gateway discovery for prefix={validation.source_prefix.prefix}")
    gateway_step = GatewayDiscoveryStep(source, settings.gateway_custom_field)
    gateway = gateway_step.run(validation)

    next_hop_step = NextHopDiscoveryStep(source, settings)
    path_tracing_step = PathTracingStep(source, settings, next_hop_step)

    path_result = path_tracing_step.run(validation, gateway)

    if check_panorama_logs and resolved_panorama_host is not None and log_port is not None:
        firewall_step = FirewallLogCheckStep()
        firewall_logs = firewall_step.run(
            settings,
            panorama_host=resolved_panorama_host,
            destination_port=log_port,
            max_wait_seconds=panorama_log_max_wait_seconds,
            fetch_limit=panorama_log_fetch_limit,
            max_results=panorama_log_max_results,
        )

    reached_destination = any(path.reached_destination for path in path_result.paths)

    payload = {
        "status": "success" if reached_destination else "failed",
        "firewall_logs": firewall_logs,
        "source": {
            "input": source_input,
            "found_in_nautobot": validation.source_found,
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
                    _hop_to_payload(hop)
                    for hop in path.hops
                ],
                "reached_destination": path.reached_destination,
                "issues": path.issues,
            }
            for index, path in enumerate(path_result.paths, start=1)
        ],
        "issues": path_result.issues,
    }

    destination_summary = _build_destination_summary(path_result.paths)
    destination_payload: Dict[str, Any] = {
        "input": destination_input,
        "found_in_nautobot": destination_found,
    }
    if destination_summary:
        destination_payload.update(destination_summary)
    payload["destination"] = destination_payload

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
        try:
            import inspect

            supports_firewall_logs = False
            try:
                supports_firewall_logs = "firewall_logs" in inspect.signature(build_pyvis_network).parameters
            except (TypeError, ValueError):
                supports_firewall_logs = False

            if supports_firewall_logs:
                try:
                    net = build_pyvis_network(path_result.graph, firewall_logs=firewall_logs)
                except Exception:
                    net = build_pyvis_network(path_result.graph)
            else:
                net = build_pyvis_network(path_result.graph)

            net.save_graph(destination.as_posix())
            payload.setdefault("visualization", {})["pyvis_html"] = destination.as_posix()
        except Exception as exc:
            payload.setdefault("visualization", {})["pyvis_error"] = str(exc)

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
            check_panorama_logs=args.check_panorama_logs,
            panorama_host=args.panorama_host,
            log_port=args.log_port,
            panorama_log_max_wait_seconds=args.panorama_log_max_wait_seconds,
            panorama_log_fetch_limit=args.panorama_log_fetch_limit,
            panorama_log_max_results=args.panorama_log_max_results,
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
