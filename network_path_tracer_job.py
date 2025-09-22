"""Nautobot Job that orchestrates the network path tracing workflow."""

from __future__ import annotations

from nautobot.core.jobs import IPAddressVar, Job

from network_path_tracing import (
    GatewayDiscoveryError,
    GatewayDiscoveryStep,
    InputValidationError,
    InputValidationStep,
    NetworkPathSettings,
    NautobotORMDataSource,
)


class NetworkPathTracerJob(Job):
    """Trace the network path between source and destination IPs."""

    class Meta:
        name = "Network Path Tracer"
        description = (
            "Validate source/destination IPs, locate the default gateway, and return "
            "structured JSON results for downstream troubleshooting."
        )
        read_only = False

    source_ip = IPAddressVar(
        description="Source IP Address (e.g. server IP)",
        required=True,
    )
    destination_ip = IPAddressVar(
        description="Destination IP Address",
        required=True,
    )

    def run(self, data, commit):  # noqa: D401 - Nautobot Job signature
        """Execute steps 1 and 2 of the network path tracing workflow."""

        settings = NetworkPathSettings(
            source_ip=self._to_address_string(data["source_ip"]),
            destination_ip=self._to_address_string(data["destination_ip"]),
        )

        data_source = NautobotORMDataSource()
        validation_step = InputValidationStep(data_source)
        gateway_step = GatewayDiscoveryStep(data_source, settings.gateway_custom_field)

        try:
            validation = validation_step.run(settings)
            gateway = gateway_step.run(validation)
        except InputValidationError as exc:
            self.log_failure(f"Input validation failed: {exc}")
            raise
        except GatewayDiscoveryError as exc:
            self.log_failure(f"Gateway discovery failed: {exc}")
            raise

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
        }

        self.job_result.data = result_payload
        self.job_result.save()
        self.log_success("Network path trace steps completed.")

    # ---------------------------------------------------------------------
    @staticmethod
    def _to_address_string(value) -> str:
        """Normalize Nautobot job input to a plain string IP address."""

        # IPAddressVar returns an IPAddress model instance; fall back to str().
        address = getattr(value, "address", value)
        if isinstance(address, str):
            return address.split("/")[0]
        return str(address).split("/")[0]

