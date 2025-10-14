"""Nautobot Job that collects interface statistics from a single device."""

from __future__ import annotations

from dataclasses import replace
from typing import Dict, Optional

from django.core.exceptions import ObjectDoesNotExist
from nautobot.apps.jobs import Job, MultiObjectVar, ObjectVar, register_jobs
from nautobot.dcim.models import Device, Interface
from nautobot.extras.choices import (
    JobResultStatusChoices,
    SecretsGroupAccessTypeChoices,
    SecretsGroupSecretTypeChoices,
)
from nautobot.extras.models import SecretsGroup
from nautobot.extras.secrets.exceptions import SecretError

from network_path_tracing import (
    InterfaceStatsService,
    InterfaceStats,
    NetworkPathSettings,
    NautobotORMDataSource,
)
from network_path_tracing.exceptions import InterfaceStatsError


@register_jobs
class InterfaceStatisticsJob(Job):
    """Gather interface statistics from a single device using the appropriate transport."""

    class Meta:
        name = "Interface Statistics Collector"
        description = "Collect interface statistics (status, counters) from a single device."
        read_only = True
        has_sensitive_variables = False
        field_order = ["secrets_group", "device", "interfaces"]

    secrets_group = ObjectVar(
        model=SecretsGroup,
        description="Secrets Group providing Generic username/password credentials for device access.",
        required=True,
    )
    device = ObjectVar(
        model=Device,
        description="Device to query for interface statistics.",
        required=True,
    )
    interfaces = MultiObjectVar(
        model=Interface,
        description="Interfaces to include (leave empty to collect stats for every interface on the device).",
        required=False,
        query_params={"device_id": "$device"},
    )

    @classmethod
    def as_form(cls, data=None, files=None, initial=None, approval_view=False):
        form = super().as_form(data=data, files=files, initial=initial, approval_view=approval_view)

        device_pk: Optional[str] = None
        if data and "device" in data:
            device_pk = data.get("device")
            if isinstance(device_pk, (list, tuple)):
                device_pk = device_pk[0]
            if not device_pk:
                device_pk = None
        elif initial and initial.get("device"):
            device_initial = initial["device"]
            if isinstance(device_initial, Device):
                device_pk = device_initial.pk
            else:
                device_pk = device_initial
                if not device_pk:
                    device_pk = None

        queryset = Interface.objects.none()
        if device_pk:
            try:
                device_obj = Device.objects.get(pk=device_pk)
            except (Device.DoesNotExist, ValueError, TypeError):
                queryset = Interface.objects.none()
            else:
                queryset = Interface.objects.filter(device=device_obj).order_by("name")

        form.fields["interfaces"].queryset = queryset
        return form

    def run(self, *, secrets_group: SecretsGroup, device: Device, interfaces, **kwargs) -> Dict[str, object]:
        """Execute the interface statistics collection workflow."""
        # Extract credentials from SecretsGroup
        self.logger.info(
            f"Starting interface statistics collection for device '{device}'",
            extra={"grouping": "interface-stats"},
        )
        access_type = SecretsGroupAccessTypeChoices.TYPE_GENERIC
        try:
            username = secrets_group.get_secret_value(
                access_type=access_type,
                secret_type=SecretsGroupSecretTypeChoices.TYPE_USERNAME,
                obj=device,
            )
        except ObjectDoesNotExist:
            self._fail_job(
                f"Secrets Group '{secrets_group}' does not define a Generic/username secret. "
                "Add the credential to the group or choose a different Secrets Group."
            )
            return {}
        except SecretError as exc:
            self._fail_job(f"Unable to retrieve username from Secrets Group '{secrets_group}': {exc.message}")
            return {}

        try:
            password = secrets_group.get_secret_value(
                access_type=access_type,
                secret_type=SecretsGroupSecretTypeChoices.TYPE_PASSWORD,
                obj=device,
            )
        except ObjectDoesNotExist:
            self._fail_job(
                f"Secrets Group '{secrets_group}' does not define a Generic/password secret. "
                "Add the credential to the group or choose a different Secrets Group."
            )
            return {}
        except SecretError as exc:
            self._fail_job(f"Unable to retrieve password from Secrets Group '{secrets_group}': {exc.message}")
            return {}

        # Validate interface selection
        selected_interfaces = list(interfaces) if interfaces else []
        if selected_interfaces:
            invalid = [iface for iface in selected_interfaces if iface.device_id != device.id]
            if invalid:
                names = ", ".join(iface.name for iface in invalid)
                self._fail_job(f"The following interfaces do not belong to device '{device.name}': {names}")
                return {}
            interface_names = sorted({iface.name for iface in selected_interfaces})
        else:
            interface_names = list(device.interfaces.values_list("name", flat=True))

        if not interface_names:
            self.logger.warning(f"No interfaces found on device '{device.name}'.", extra={"grouping": "interface-stats"})
            payload = {"device": device.name, "interfaces": {}}
            self.job_result.data = payload
            self.job_result.set_status(JobResultStatusChoices.STATUS_SUCCESS)
            return payload

        base_settings = NetworkPathSettings(
            source_ip="0.0.0.0",
            destination_ip="0.0.0.0",
        )

        settings = replace(
            base_settings,
            pa=replace(base_settings.pa, username=username, password=password),
            napalm=replace(base_settings.napalm, username=username, password=password),
            f5=replace(base_settings.f5, username=username, password=password),
        )

        data_source = NautobotORMDataSource()
        service = InterfaceStatsService(data_source, settings, logger=self.logger)
        try:
            stats = service.collect_by_device_name(device.name, interface_names)
        except InterfaceStatsError as exc:
            self.job_result.data = {
                "status": "failed",
                "error": str(exc),
                "error_type": type(exc).__name__,
            }
            self.job_result.set_status(JobResultStatusChoices.STATUS_FAILURE)
            raise RuntimeError(str(exc))
        except Exception as exc:  # pragma: no cover - defensive guard
            message = f"Unexpected error collecting interface statistics: {exc}"
            self.job_result.data = {
                "status": "failed",
                "error": str(exc),
                "error_type": type(exc).__name__,
                "message": message,
            }
            self.job_result.set_status(JobResultStatusChoices.STATUS_FAILURE)
            raise RuntimeError(message)

        if not isinstance(stats, dict):
            message = (
                f"Unexpected response type from interface stats service for '{device.name}': {type(stats).__name__}"
            )
            self.job_result.data = {
                "status": "failed",
                "error": message,
                "error_type": type(stats).__name__,
                "raw": repr(stats),
            }
            self.job_result.set_status(JobResultStatusChoices.STATUS_FAILURE)
            raise RuntimeError(message)

        self.logger.debug(
            f"Collected statistics for {len(stats)} interface entries on '{device.name}'",
            extra={"grouping": "interface-stats"},
        )

        payload_interfaces: Dict[str, Dict[str, object]] = {}
        stats_by_lower = {key.lower(): value for key, value in stats.items()}
        self.logger.debug(
            f"Raw statistics payload for '{device.name}': {stats}",
            extra={"grouping": "interface-stats"},
        )
        for name in interface_names:
            entry = stats.get(name)
            if entry is None:
                entry = stats_by_lower.get(name.lower())
            if isinstance(entry, Exception):
                payload_interfaces[name] = {
                    "error": str(entry),
                    "error_type": type(entry).__name__,
                }
                self.logger.warning(
                    f"Collector returned exception for interface '{name}' on '{device.name}': {entry}",
                    extra={"grouping": "interface-stats"},
                )
                continue
            if isinstance(entry, InterfaceStats):
                payload_interfaces[name] = entry.to_dict()
            elif isinstance(entry, dict):
                payload_interfaces[name] = entry
            else:
                payload_interfaces[name] = {}
                self.logger.debug(
                    f"No statistics returned for interface '{name}' on '{device.name}'",
                    extra={"grouping": "interface-stats"},
                )

        primary_ip = None
        if device.primary_ip and getattr(device.primary_ip, "address", None):
            primary_ip = str(device.primary_ip.address)

        payload = {
            "device": device.name,
            "primary_ip": primary_ip,
            "platform": getattr(device.platform, "name", None),
            "interfaces": payload_interfaces,
        }

        self.logger.debug(
            f"Final payload for '{device.name}': {payload}",
            extra={"grouping": "interface-stats"},
        )

        self.job_result.data = payload
        self.job_result.set_status(JobResultStatusChoices.STATUS_SUCCESS)
        return payload

    def _fail_job(self, message: str) -> None:
        """Utility method to fail the job with a readable message."""
        self.logger.failure(message)
        self.job_result.set_status(JobResultStatusChoices.STATUS_FAILURE)
        raise RuntimeError(message)
