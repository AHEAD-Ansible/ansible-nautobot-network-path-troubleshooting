"""Nautobot Job that orchestrates the network path tracing workflow."""

from __future__ import annotations

import json
import ipaddress

from nautobot.extras.jobs import IPAddressVar, Job
from nautobot.extras.models import CustomField
from django.core.exceptions import ObjectDoesNotExist

from .network_path_tracing import (
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


class NetworkPathTracerJob(Job):
    """Trace the network path between source and destination IPs."""

    class Meta:
        name = "Network Path Tracer"
        description = (
            "Trace the full network path from source to destination IP, "
            "including gateway discovery, next-hop lookups, and ECMP handling."
        )
        read_only = False

    source_ip = IPAddressVar(
        description="Source IP Address (e.g., server IP)",
        required=True,
    )
    destination_ip = IPAddressVar(
        description="Destination IP Address",
        required=True,
    )

    def run(self, data, commit):  # noqa: D401 - Nautobot Job signature
        """Execute the full network path tracing workflow."""
        # Log the start of the job with input IPs for debugging
        self.log_info(
            f"Starting network path tracing job with source_ip={data.get('source_ip', 'None')}, "
            f"destination_ip={data.get('destination_ip', 'None')}"
        )

        # Validate that input IPs are provided
        if not data.get("source_ip") or not data.get("destination_ip"):
            error_msg = "Missing source_ip or destination_ip"
            self.log_failure(error_msg)
            raise ValueError(error_msg)

        # Validate that input IPs are valid IPv4/IPv6 addresses
        try:
            ipaddress.ip_address(data["source_ip"])
            ipaddress.ip_address(data["destination_ip"])
        except ValueError as exc:
            error_msg = f"Invalid IP address: {exc}"
            self.log_failure(error_msg)
            raise

        # Initialize settings with normalized IP addresses
        settings = NetworkPathSettings(
            source_ip=self._to_address_string(data["source_ip"]),
            destination_ip=self._to_address_string(data["destination_ip"]),
        )
        self.log_info(
            f"Normalized settings: source_ip={settings.source_ip}, "
            f"destination_ip={settings.destination_ip}"
        )

        # Initialize workflow steps
        data_source = NautobotORMDataSource()
        validation_step = InputValidationStep(data_source)
        gateway_step = GatewayDiscoveryStep(data_source, settings.gateway_custom_field)
        next_hop_step = NextHopDiscoveryStep(data_source, settings)
        path_tracing_step = PathTracingStep(data_source, settings)

        try:
            # Step 1: Validate inputs
            self.log_info("Starting input validation")
            validation = validation_step.run(settings)
            self.log_info("Input validation completed successfully")

            # Step 2: Locate gateway
            self.log_info("Starting gateway discovery")
            gateway = gateway_step.run(validation)
            self.log_info(f"Gateway discovery completed: {gateway.details}")

            # Step 3: Initialize path tracing
            self.log_info("Starting path tracing")
            path_result = path_tracing_step.run(validation, gateway)
            self.log_info("Path tracing completed successfully")

            # Prepare result payload
            result_payload = {
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

            # Store result in JobResult custom field data
            self._store_path_result(result_payload)

            self.job_result.data = result_payload
            self.job_result.save()
            self.log_success("Network path trace completed successfully")

        except InputValidationError as exc:
            self.log_failure(f"Input validation failed: {exc}")
            raise
        except GatewayDiscoveryError as exc:
            self.log_failure(f"Gateway discovery failed: {exc}")
            raise
        except NextHopDiscoveryError as exc:
            self.log_failure(f"Next-hop discovery failed: {exc}")
            raise
        except PathTracingError as exc:
            self.log_failure(f"Path tracing failed: {exc}")
            raise
        except Exception as exc:
            self.log_failure(f"Unexpected error: {exc}")
            raise

    def _store_path_result(self, payload: dict):
        """Store the path tracing result in JobResult's custom_field_data."""
        try:
            CustomField.objects.get(name="network_path_trace_results")
        except ObjectDoesNotExist:
            self.log_warning(
                "Custom field 'network_path_trace_results' not found; logging result instead"
            )
            self.log_info(f"Job result:\n{json.dumps(payload, indent=2)}")
            return

        self.job_result.custom_field_data["network_path_trace_results"] = payload
        self.job_result.save()

    @staticmethod
    def _to_address_string(value) -> str:
        """Normalize Nautobot job input to a plain string IP address."""
        address = getattr(value, "address", value)
        if isinstance(address, str):
            return address.split("/")[0]
        return str(address).split("/")[0]