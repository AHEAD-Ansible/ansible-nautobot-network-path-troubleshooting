"""Nautobot Job that orchestrates the network path tracing workflow."""

from __future__ import annotations

import json
import ipaddress
from typing import Optional

from nautobot.apps.jobs import IPAddressVar, Job
from nautobot.extras.models import CustomField
from nautobot.extras.choices import JobResultStatusChoices, LogLevelChoices
from django.core.exceptions import ObjectDoesNotExist

from network_path_tracing import (
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
)
from nautobot.apps.jobs import register_jobs

@register_jobs
class NetworkPathTracerJob(Job):
    """Trace the network path between source and destination IPs."""

    class Meta:
        name = "Network Path Tracer"
        description = (
            "Trace the full network path from source to destination IP, "
            "including gateway discovery, next-hop lookups, and ECMP handling."
        )
        has_sensitive_variables = False
        read_only = False

    source_ip = IPAddressVar(
        description="Source IP Address (e.g., server IP)",
        required=True,
    )
    destination_ip = IPAddressVar(
        description="Destination IP Address",
        required=True,
    )

    def run(self, *, source_ip: str, destination_ip: str, **kwargs) -> dict:
        """Execute the full network path tracing workflow.

        Args:
            source_ip (str): Source IP address (e.g., '10.0.0.1/24').
            destination_ip (str): Destination IP address (e.g., '4.2.2.1/24').
            **kwargs: Additional keyword arguments passed by Nautobot (logged for debugging).

        Returns:
            dict: Result payload containing path tracing details.

        Raises:
            ValueError: If source_ip or destination_ip is invalid.
            InputValidationError: If IP addresses fail Nautobot data validation.
            GatewayDiscoveryError: If gateway discovery fails.
            NextHopDiscoveryError: If next-hop discovery fails.
            PathTracingError: If path tracing fails.
        """
        # Log job start
        self.logger.info(
            f"Starting network path tracing job for source_ip={source_ip}, destination_ip={destination_ip}",
            extra={"grouping": "job-start", "object": self.job_result}
        )
        self.job_result.log("Job has started.", level_choice=LogLevelChoices.LOG_INFO)
        self.job_result.save()

        # Log unexpected kwargs
        if kwargs:
            self.logger.warning(
                f"Unexpected keyword arguments received: {kwargs}",
                extra={"grouping": "job-start"}
            )

        # Validate IP addresses
        try:
            ipaddress.ip_address(self._to_address_string(source_ip))
            ipaddress.ip_address(self._to_address_string(destination_ip))
        except ValueError as exc:
            self._fail_job(f"Invalid IP address: {exc}", grouping="input-validation")
            raise ValueError(f"Invalid IP address: {exc}")

        # Initialize settings
        settings = NetworkPathSettings(
            source_ip=self._to_address_string(source_ip),
            destination_ip=self._to_address_string(destination_ip),
        )
        self.logger.info(
            f"Normalized settings: source_ip={settings.source_ip}, destination_ip={settings.destination_ip}",
            extra={"grouping": "settings"}
        )

        # Initialize workflow steps
        data_source = NautobotORMDataSource()
        validation_step = InputValidationStep(data_source)
        gateway_step = GatewayDiscoveryStep(data_source, settings.gateway_custom_field)
        next_hop_step = NextHopDiscoveryStep(data_source, settings)
        path_tracing_step = PathTracingStep(data_source, settings)

        try:
            # Step 1: Validate inputs
            self.logger.info("Starting input validation", extra={"grouping": "validation"})
            validation = validation_step.run(settings)
            self.logger.success("Input validation completed successfully", extra={"grouping": "validation"})
            self.job_result.log("Input validation completed.", level_choice=LogLevelChoices.LOG_SUCCESS)

            # Step 2: Locate gateway
            self.logger.info("Starting gateway discovery", extra={"grouping": "gateway-discovery"})
            gateway = gateway_step.run(validation)
            self.logger.success(f"Gateway discovery completed: {gateway.details}", extra={"grouping": "gateway-discovery"})
            self.job_result.log(f"Gateway discovery: {gateway.details}", level_choice=LogLevelChoices.LOG_SUCCESS)

            # Step 3: Initialize path tracing
            self.logger.info("Starting path tracing", extra={"grouping": "path-tracing"})
            path_result = path_tracing_step.run(validation, gateway)
            self.logger.success("Path tracing completed successfully", extra={"grouping": "path-tracing"})
            self.job_result.log("Path tracing completed.", level_choice=LogLevelChoices.LOG_SUCCESS)

            # Prepare result payload
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
                        "hops": [
                            {
                                "device_name": hop.device_name,
                                "interface_name": hop.interface_name,
                                "next_hop_ip": hop.next_hop_ip,
                                "egress_interface": hop.egress_interface,
                                "details": hop.details,
                            }
                            for hop in path.hops
                        ],
                        "reached_destination": path.reached_destination,
                        "issues": path.issues,
                    }
                    for path in path_result.paths
                ],
                "issues": path_result.issues,
            }

            # Store result
            self._store_path_result(result_payload)

            # Save result and mark success
            self.job_result.data = result_payload
            self.job_result.set_status(JobResultStatusChoices.STATUS_SUCCESS)
            self.job_result.save()
            self.logger.success(
                "Network path trace completed successfully",
                extra={"grouping": "job-completion", "object": self.job_result}
            )
            self.job_result.log(
                "Network path trace completed successfully.",
                level_choice=LogLevelChoices.LOG_SUCCESS
            )

            return result_payload

        except InputValidationError as exc:
            self._fail_job(f"Input validation failed: {exc}", grouping="validation")
        except GatewayDiscoveryError as exc:
            self._fail_job(f"Gateway discovery failed: {exc}", grouping="gateway-discovery")
        except NextHopDiscoveryError as exc:
            self._fail_job(f"Next-hop discovery failed: {exc}", grouping="next-hop-discovery")
        except PathTracingError as exc:
            self._fail_job(f"Path tracing failed: {exc}", grouping="path-tracing")
        except Exception as exc:
            self._fail_job(f"Unexpected error: {exc}", grouping="unexpected-error")
        finally:
            self.job_result.save()

    def _fail_job(self, message: str, grouping: str) -> None:
        """Fail the job with a given error message.

        Args:
            message (str): The error message to log.
            grouping (str): The log grouping for structured logging.
        """
        self.logger.failure(message, extra={"grouping": grouping, "object": self.job_result})
        self.job_result.log(message, level_choice=LogLevelChoices.LOG_FAILURE)
        self.job_result.set_status(JobResultStatusChoices.STATUS_FAILURE)
        self.job_result.save()
        raise ValueError(message)

    def _store_path_result(self, payload: dict) -> None:
        """Store the path tracing result in JobResult's custom_field_data.

        Args:
            payload (dict): The result payload to store.
        """
        try:
            CustomField.objects.get(name="network_path_trace_results")
        except ObjectDoesNotExist:
            self.logger.warning(
                "Custom field 'network_path_trace_results' not found; logging result instead",
                extra={"grouping": "result-storage", "object": self.job_result}
            )
            self.logger.info(
                f"Job result:\n{json.dumps(payload, indent=2)}",
                extra={"grouping": "result-storage", "object": self.job_result}
            )
            return

        self.job_result.custom_field_data["network_path_trace_results"] = payload
        self.job_result.save()

    @staticmethod
    def _to_address_string(value: str) -> str:
        """Normalize Nautobot job input to a plain string IP address.

        Args:
            value: Input value (string, e.g., '10.0.0.1/24').

        Returns:
            str: Normalized IP address without prefix (e.g., '10.0.0.1').
        """
        if isinstance(value, str):
            return value.split("/")[0]
        return str(value).split("/")[0]