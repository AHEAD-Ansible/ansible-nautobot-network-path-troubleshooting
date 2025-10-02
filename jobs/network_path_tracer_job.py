"""Nautobot Job that orchestrates the network path tracing workflow."""

from __future__ import annotations

import ipaddress
from typing import Optional

from nautobot.apps.jobs import IPAddressVar, Job
from nautobot.extras.choices import JobResultStatusChoices
from nautobot.extras.models import CustomField
from nautobot.extras.choices import JobResultStatusChoices, LogLevelChoices
from django.core.exceptions import ObjectDoesNotExist, FieldError
from nautobot.apps.jobs import register_jobs

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
    build_pyvis_network,
)


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
        field_order = ["source_ip", "destination_ip"]  # UI form order
        # soft_time_limit / time_limit could be added if long-running

    source_ip = IPAddressVar(
        description="Source IP Address (e.g., 10.0.0.1)",
        required=True,
    )
    destination_ip = IPAddressVar(
        description="Destination IP Address (e.g., 4.2.2.1)",
        required=True,
    )

    def run(self, *, source_ip: str, destination_ip: str, **kwargs) -> dict:
        """Execute the full network path tracing workflow.

        Args:
            source_ip (str): Source IP address (e.g., '10.0.0.1').
            destination_ip (str): Destination IP address (e.g., '4.2.2.1').
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
        # Log job start
        self.logger.info(msg=f"Starting network path tracing job for source_ip={source_ip}, destination_ip={destination_ip}")

        # Log unexpected kwargs (robustness)
        if kwargs:
            self.logger.warning(msg=f"Unexpected keyword arguments received: {kwargs}")

        # Validate IP addresses (IPAddressVar returns str, but we normalize)
        try:
            ipaddress.ip_address(self._to_address_string(source_ip))
            ipaddress.ip_address(self._to_address_string(destination_ip))
        except ValueError as exc:
            self._fail_job(f"Invalid IP address: {exc}")
            return {}  # Nautobot handles return on failure

        # Initialize settings
        settings = NetworkPathSettings(
            source_ip=self._to_address_string(source_ip),
            destination_ip=self._to_address_string(destination_ip),
        )
        self.logger.debug(msg=f"Normalized settings: source_ip={settings.source_ip}, destination_ip={settings.destination_ip}")

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
            self.logger.success("Input validation completed successfully")

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
                    self.logger.warning(msg=f"Visualization generation failed: {exc}")

            # Prepare result payload (JSON-serializable for JobResult.data)
            result_payload = {
                "status": "success",
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

            if visualization_attached:
                result_payload["visualization"] = "See attached 'network_path_trace.html' for interactive graph."

            # Store result in JobResult (best practice)
            self.job_result.data = result_payload
            self.job_result.set_status(JobResultStatusChoices.STATUS_SUCCESS)
            self.logger.success("Network path trace completed successfully.")

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