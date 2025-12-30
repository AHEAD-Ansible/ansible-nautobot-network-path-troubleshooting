"""Nautobot Job that orchestrates the network path tracing workflow."""

from __future__ import annotations

import ipaddress
import logging
import subprocess
from dataclasses import replace
from typing import Any, Dict, Optional

from django.core.exceptions import ObjectDoesNotExist, FieldError
from nautobot.apps.jobs import BooleanVar, Job, ObjectVar, StringVar, register_jobs
from nautobot.extras.choices import JobResultStatusChoices, LogLevelChoices, SecretsGroupAccessTypeChoices, SecretsGroupSecretTypeChoices
from nautobot.extras.models import CustomField, SecretsGroup
from nautobot.extras.secrets.exceptions import SecretError

from network_path_tracing import (  # Changed to absolute import
    GatewayDiscoveryError,
    GatewayDiscoveryStep,
    InputValidationError,
    InputValidationStep,
    NetworkPathSettings,
    NautobotORMDataSource,
    NextHopDiscoveryError,
    NextHopDiscoveryStep,
    PathTracingError,
    PathTracingStep,
    PathHop,
    Path,
    build_pyvis_network,
)
from network_path_tracing.utils import resolve_target_to_ipv4


@register_jobs
class NetworkPathTracerJob(Job):
    """Trace the network path between source and destination IPs.

    This Job follows Nautobot best practices: read-only, no sensitive variables,
    modular steps for validation/gateway/path tracing, robust error handling,
    and result visualization.
    """

    class Meta:
        name = "Network Path Tracer"
        description = (
            "Trace the full network path from source to destination IP, "
            "including gateway discovery, next-hop lookups, and ECMP handling."
        )
        has_sensitive_variables = False
        read_only = True
        dryrun_default = False  # Explicit for clarity, though read_only
        field_order = [
            "source_ip",
            "destination_ip",
            "secrets_group",
            "enable_layer2_discovery",
            "ping_endpoints",
            "enable_debug_logging",
        ]
        # soft_time_limit / time_limit could be added if long-running

    source_ip = StringVar(
        label="Source IP or FQDN",
        description="Source IP address or hostname (e.g., 10.0.0.1 or server01.example.com)",
        required=True,
    )
    destination_ip = StringVar(
        label="Destination IP or FQDN",
        description="Destination IP address or hostname (e.g., 4.2.2.1 or app01.example.com)",
        required=True,
    )

    secrets_group = ObjectVar(
        model=SecretsGroup,
        description="Secrets Group providing Generic username/password credentials for device lookups.",
        required=True,
    )
    enable_layer2_discovery = BooleanVar(
        description="Enable layer 2 neighbor discovery between layer 3 hops.",
        default=True,
    )
    ping_endpoints = BooleanVar(
        description="Ping the source and destination before tracing to refresh ARP/ND tables.",
        default=False,
    )
    enable_debug_logging = BooleanVar(
        description="Include debug-level log messages in the job output for troubleshooting.",
        default=False,
    )

    def run(
        self,
        *,
        source_ip: str,
        destination_ip: str,
        secrets_group: SecretsGroup,
        enable_layer2_discovery: bool = True,
        ping_endpoints: bool = False,
        enable_debug_logging: bool = False,
        **kwargs,
    ) -> dict:
        """Execute the full network path tracing workflow.

        Args:
            source_ip (str): Source IP address (e.g., '10.0.0.1').
            destination_ip (str): Destination IP address (e.g., '4.2.2.1').
            secrets_group (SecretsGroup): Selected secrets group supplying credentials.
            **kwargs: Additional keyword arguments passed by Nautobot (logged for debugging).

        Returns:
            dict: Result payload containing path tracing details.

        Raises:
            ValueError: If source_ip or destination_ip is invalid.
            InputValidationError: If IP addresses fail Nautobot data validation.
            GatewayDiscoveryError: If gateway discovery fails.
            NextHopDiscoveryError: If next-hop discovery fails.
            PathTracingError: If path tracing fails.

        Best practices: Use self.log_* for traceability. Set JobResult status/data.
        Raise exceptions for failures (Nautobot captures tracebacks in JobResult).
        """
        log_level = logging.DEBUG if enable_debug_logging else logging.INFO
        for candidate_logger in (self.logger, getattr(self.logger, "logger", None)):
            try:
                if candidate_logger and hasattr(candidate_logger, "setLevel"):
                    candidate_logger.setLevel(log_level)
                    break
            except Exception:
                continue

        # Log job start
        self.logger.info(
            msg=(
                f"Starting network path tracing job for source_host={source_ip}, "
                f"destination_host={destination_ip} (debug_logging={'on' if enable_debug_logging else 'off'})"
            )
        )

        # Log unexpected kwargs (robustness)
        if kwargs:
            self.logger.warning(msg=f"Unexpected keyword arguments received: {kwargs}")

        source_input = (source_ip or "").strip()
        destination_input = (destination_ip or "").strip()
        source_candidate = self._to_address_string(source_input)
        destination_candidate = self._to_address_string(destination_input)

        # Retrieve credentials from the selected Secrets Group
        try:
            username = secrets_group.get_secret_value(
                SecretsGroupAccessTypeChoices.TYPE_GENERIC,
                SecretsGroupSecretTypeChoices.TYPE_USERNAME,
                obj=None,
            )
        except ObjectDoesNotExist:
            self._fail_job(
                f"Secrets Group '{secrets_group}' does not define a Generic/username secret. "
                "Add the credential to the group or choose a different Secrets Group."
            )
            return {}
        except SecretError as exc:
            self._fail_job(
                f"Unable to retrieve username from Secrets Group '{secrets_group}': {exc.message}"
            )
            return {}

        try:
            password = secrets_group.get_secret_value(
                SecretsGroupAccessTypeChoices.TYPE_GENERIC,
                SecretsGroupSecretTypeChoices.TYPE_PASSWORD,
                obj=None,
            )
        except ObjectDoesNotExist:
            self._fail_job(
                f"Secrets Group '{secrets_group}' does not define a Generic/password secret. "
                "Add the credential to the group or choose a different Secrets Group."
            )
            return {}
        except SecretError as exc:
            self._fail_job(
                f"Unable to retrieve password from Secrets Group '{secrets_group}': {exc.message}"
            )
            return {}

        try:
            resolved_source_ip = resolve_target_to_ipv4(source_input, "source")
            resolved_destination_ip = resolve_target_to_ipv4(destination_input, "destination")
        except InputValidationError as exc:
            self._fail_job(str(exc))
            return {}

        self._log_hostname_resolution("source", source_candidate, resolved_source_ip)
        self._log_hostname_resolution("destination", destination_candidate, resolved_destination_ip)

        # Validate the resolved addresses
        normalized_source = self._to_address_string(resolved_source_ip)
        normalized_destination = self._to_address_string(resolved_destination_ip)
        try:
            ipaddress.ip_address(normalized_source)
            ipaddress.ip_address(normalized_destination)
        except ValueError as exc:  # pragma: no cover - defensive guardrail
            self._fail_job(f"Invalid IP address after resolution: {exc}")
            return {}

        # Initialize settings and override credentials with secrets group values
        base_settings = NetworkPathSettings(
            source_ip=normalized_source,
            destination_ip=normalized_destination,
        )
        settings = replace(
            base_settings,
            pa=replace(base_settings.pa, username=username, password=password),
            napalm=replace(base_settings.napalm, username=username, password=password),
            f5=replace(base_settings.f5, username=username, password=password),
            enable_layer2_discovery=enable_layer2_discovery,
        )
        self.logger.debug(
            msg=(
                f"Normalized settings: source_ip={settings.source_ip}, "
                f"destination_ip={settings.destination_ip}, secrets_group={secrets_group}"
            )
        )

        if ping_endpoints:
            self.logger.info("Pinging source and destination endpoints before tracing.")
            self._ping_endpoint("source", normalized_source)
            self._ping_endpoint("destination", normalized_destination)

        # Initialize workflow steps (modular for testability)
        data_source = NautobotORMDataSource()
        validation_step = InputValidationStep(data_source)
        gateway_step = GatewayDiscoveryStep(data_source, settings.gateway_custom_field)
        next_hop_step = NextHopDiscoveryStep(data_source, settings, logger=self.logger)  # Pass Job's logger
        path_tracing_step = PathTracingStep(data_source, settings, next_hop_step, logger=self.logger)

        try:
            # Step 1: Validate inputs
            self.logger.info(msg="Starting input validation")
            validation = validation_step.run(settings)
            source_found = getattr(validation, "source_found", True)
            if not source_found:
                self.logger.warning(
                    msg=(
                        f"Source IP {normalized_source} not found in Nautobot; "
                        "continuing with prefix-based gateway discovery."
                    )
                )
            self.logger.success("Input validation completed successfully")

            destination_record = data_source.get_ip_address(normalized_destination)
            destination_found = destination_record is not None
            if not destination_found:
                self.logger.warning(
                    msg=(
                        f"Destination IP {normalized_destination} not found in Nautobot; "
                        "path tracing will continue without destination metadata."
                    )
                )

            # Step 2: Locate gateway
            self.logger.info(msg="Starting gateway discovery")
            gateway = gateway_step.run(validation)
            self.logger.success(f"Gateway discovery completed: {gateway.details}")

            # Step 3: Initialize path tracing
            self.logger.info(msg="Starting path tracing")
            path_result = path_tracing_step.run(validation, gateway)
            self.logger.success("Path tracing completed successfully")

            # Generate visualization if graph is available (optional dependency)
            visualization_attached = False
            if path_result.graph:
                try:
                    net = build_pyvis_network(path_result.graph)
                    html = net.generate_html()
                    self.create_file("network_path_trace.html", html)  # Attach to JobResult
                    visualization_attached = True
                    self.logger.info(msg="Generated interactive network path visualization and attached to job result.")
                except ImportError as exc:
                    self.logger.warning(msg=f"Visualization skipped: pyvis or networkx not installed ({exc})")
                except Exception as exc:
                    import traceback

                    tb = traceback.format_exc()
                    self.logger.warning(msg=f"Visualization generation failed: {exc}\n{tb}")

            reached_destination = any(path.reached_destination for path in path_result.paths)

            # Prepare result payload (JSON-serializable for JobResult.data)
            result_payload = {
                "status": "success" if reached_destination else "failed",
                "source": {
                    "input": source_input,
                    "found_in_nautobot": source_found,
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
                            self._hop_to_payload(hop)
                            for hop in path.hops
                        ],
                        "reached_destination": path.reached_destination,
                        "issues": path.issues,
                    }
                    for index, path in enumerate(path_result.paths, start=1)
                ],
                "issues": path_result.issues,
            }

            destination_summary = self._build_destination_summary(path_result.paths)
            destination_payload: Dict[str, Any] = {
                "input": destination_input,
                "found_in_nautobot": destination_found,
            }
            if destination_summary:
                destination_payload.update(destination_summary)
            result_payload["destination"] = destination_payload

            if visualization_attached:
                result_payload["visualization"] = "See attached 'network_path_trace.html' for interactive graph."

            # Store result in JobResult (best practice)
            self.job_result.data = result_payload
            if reached_destination:
                self.job_result.set_status(JobResultStatusChoices.STATUS_SUCCESS)
                self.logger.success("Network path trace completed successfully.")
            else:
                self.job_result.set_status(JobResultStatusChoices.STATUS_FAILURE)
                self.logger.warning("Network path trace completed but destination was unreachable.")

            return result_payload

        except (InputValidationError, GatewayDiscoveryError, NextHopDiscoveryError, PathTracingError) as exc:
            self._fail_job(f"{type(exc).__name__} failed: {exc}")
        except Exception as exc:
            self._fail_job(f"Unexpected error: {exc}")
        finally:
            self.job_result.save()  # Always save JobResult

        return {}  # Return empty on failure (Nautobot logs the exception)

    def _fail_job(self, message: str) -> None:
        """Fail the job with a given error message.

        Logs failure and sets status. Raises exception for Nautobot to capture traceback.
        """
        self.logger.failure(message)
        self.job_result.set_status(JobResultStatusChoices.STATUS_FAILURE)
        raise RuntimeError(message)  # Use RuntimeError for general failures

    @staticmethod
    def _to_address_string(value: str) -> str:
        """Normalize Nautobot job input to a plain string IP address.

        Handles optional /prefix from user input.
        Args:
            value: Input value (str, e.g., '10.0.0.1/24').

        Returns:
            str: Normalized IP address without prefix (e.g., '10.0.0.1').
        """
        if isinstance(value, str):
            return value.split("/")[0]
        return str(value).split("/")[0]

    def _ping_endpoint(self, label: str, ip_address: str) -> None:
        """Best-effort ICMP reachability check with logging."""

        command = ["ping", "-c", "3", "-W", "1", ip_address]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            self.logger.warning(
                "Ping utility not available; skipping reachability check for %s (%s).",
                label,
                ip_address,
            )
            return
        except Exception as exc:  # pragma: no cover - defensive logging
            self.logger.warning(
                "Ping attempt for %s (%s) failed to start: %s",
                label,
                ip_address,
                exc,
            )
            return

        if result.returncode == 0:
            self.logger.info("Ping %s (%s) succeeded.", label, ip_address)
        else:
            detail = result.stderr.strip() or result.stdout.strip() or "no output"
            self.logger.warning(
                "Ping %s (%s) failed (rc=%s): %s",
                label,
                ip_address,
                result.returncode,
                detail,
            )

    @staticmethod
    def _hop_to_payload(hop: PathHop) -> Dict[str, Any]:
        """Serialize a PathHop, merging any extra metadata."""

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
        if hop.hop_type:
            payload["hop type"] = {"classification": hop.hop_type}
        for key, value in (hop.extras or {}).items():
            if value is None:
                continue
            if key in payload and payload[key] not in (None, "", []):
                continue
            payload[key] = value
        return payload

    @staticmethod
    def _build_destination_summary(paths: list[Path]) -> Optional[Dict[str, Any]]:
        """Derive destination info from the first successful path."""

        for path in paths:
            if not path.reached_destination:
                continue
            if not path.hops:
                continue
            last_hop = path.hops[-1]
            if not last_hop.next_hop_ip:
                continue
            return {
                "address": last_hop.next_hop_ip,
                "device_name": last_hop.device_name,
            }
        return None

    def _log_hostname_resolution(self, label: str, original: str, resolved: str) -> None:
        """Log when hostname inputs resolve to IPv4 addresses."""

        if not original or original == resolved:
            return
        try:
            ipaddress.ip_address(original)
        except ValueError:
            self.logger.info(
                msg=f"Resolved {label} hostname '{original}' to IPv4 address {resolved}"
            )
