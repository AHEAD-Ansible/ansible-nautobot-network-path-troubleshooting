"""Nautobot Job that validates interface administrative/operational state against live device data."""

from __future__ import annotations

from dataclasses import replace
from typing import Dict, List, Optional

from django.core.exceptions import ObjectDoesNotExist
from nautobot.apps.jobs import Job, ObjectVar, register_jobs
from nautobot.dcim.models import Device, Interface
from nautobot.extras.choices import (
    JobResultStatusChoices,
    SecretsGroupAccessTypeChoices,
    SecretsGroupSecretTypeChoices,
)
from nautobot.extras.models import SecretsGroup
from nautobot.extras.secrets.exceptions import SecretError

from network_path_tracing import (
    InterfaceStats,
    InterfaceStatsService,
    InterfaceStatsError,
    NetworkPathSettings,
    NautobotORMDataSource,
)


@register_jobs
class InterfaceComplianceJob(Job):
    """Compare Nautobot interface data with live device state collected via NAPALM."""

    class Meta:
        name = "Interface State Compliance"
        description = (
            "Log into a device via NAPALM, gather interface administrative/operational state, "
            "and compare it with the interface data stored in Nautobot."
        )
        read_only = True
        has_sensitive_variables = False
        field_order = ["secrets_group", "device"]

    secrets_group = ObjectVar(
        model=SecretsGroup,
        description="Secrets Group providing Generic username/password credentials.",
        required=True,
    )
    device = ObjectVar(
        model=Device,
        description="Device to validate against live state.",
        required=True,
    )

    def run(self, *, secrets_group: SecretsGroup, device: Device, **kwargs) -> Dict[str, object]:
        """Collect live interface state and compare it with Nautobot's representation."""
        self.logger.info(
            f"Starting interface compliance check for device '{device.name}'",
            extra={"grouping": "interface-compliance"},
        )

        try:
            device = Device.objects.get(pk=device.pk)
        except Device.DoesNotExist:
            self._fail_job(f"Device '{device}' no longer exists in Nautobot.")
            return {}

        username, password = self._get_credentials(secrets_group, device)

        interface_qs = (
            Interface.objects.filter(device=device)
            .select_related("status")
            .order_by("name")
        )
        interfaces = list(interface_qs)
        if not interfaces:
            self.logger.warning(
                f"No interfaces found on device '{device.name}'.",
                extra={"grouping": "interface-compliance"},
            )
            payload = {
                "device": device.name,
                "overall_status": "pass",
                "checked_interfaces": 0,
                "interfaces": [],
            }
            self.job_result.data = payload
            self.job_result.set_status(JobResultStatusChoices.STATUS_SUCCESS)
            return payload

        interface_names = [iface.name for iface in interfaces]
        self.logger.debug(
            f"Nautobot interface inventory for '{device.name}': {interface_names}",
            extra={"grouping": "interface-compliance"},
        )

        base_settings = NetworkPathSettings(source_ip="0.0.0.0", destination_ip="0.0.0.0")
        settings = replace(
            base_settings,
            napalm=replace(base_settings.napalm, username=username, password=password),
        )

        data_source = NautobotORMDataSource()
        service = InterfaceStatsService(data_source, settings, logger=self.logger)
        self.logger.debug(
            f"Collecting live interface data for '{device.name}' using NAPALM credentials from Secrets Group '{secrets_group}'.",
            extra={"grouping": "interface-compliance"},
        )

        try:
            stats = service.collect_by_device_name(device.name, interface_names)
        except InterfaceStatsError as exc:
            self._fail_job(f"Failed to collect live interface state: {exc}")
            return {}
        except Exception as exc:  # pragma: no cover - defensive guard
            self._fail_job(f"Unexpected error while collecting live state: {exc}")
            return {}

        stats_by_lower = {name.lower(): data for name, data in stats.items()}
        self.logger.debug(
            f"Live interface result keys for '{device.name}': {list(stats.keys())}",
            extra={"grouping": "interface-compliance"},
        )

        results: List[Dict[str, object]] = []
        differences_found = 0

        for iface in interfaces:
            live_entry = stats.get(iface.name) or stats_by_lower.get(iface.name.lower())
            mismatch_messages: List[str] = []
            live_admin: Optional[bool] = None
            live_oper: Optional[bool] = None
            live_detail: Dict[str, object] = {}

            if isinstance(live_entry, InterfaceStats):
                live_admin = live_entry.admin_up
                live_oper = live_entry.oper_up
                live_detail = live_entry.to_dict()
            elif isinstance(live_entry, dict):
                live_admin = _coerce_bool(live_entry.get("admin_up"))
                live_oper = _coerce_bool(live_entry.get("oper_up"))
                live_detail = dict(live_entry)
            elif live_entry is None:
                mismatch_messages.append("No live data returned for this interface.")
                live_detail = {}
            else:
                live_detail = {"raw": repr(live_entry)}
                mismatch_messages.append("Unrecognised live data structure.")

            if isinstance(live_detail, dict) and "error" in live_detail:
                mismatch_messages.append(f"Device reported error: {live_detail['error']}")  # pragma: no cover - defensive

            nb_admin_enabled = bool(getattr(iface, "enabled", True))
            if live_admin is None:
                mismatch_messages.append("Device did not report administrative state.")
            elif live_admin != nb_admin_enabled:
                mismatch_messages.append(
                    f"Admin mismatch (Nautobot enabled={nb_admin_enabled}, device admin_up={live_admin})"
                )

            expected_oper = self._expected_operational_state(iface)
            if expected_oper is not None:
                if live_oper is None:
                    mismatch_messages.append("Device did not report operational state.")
                elif live_oper != expected_oper:
                    mismatch_messages.append(
                        f"Operational mismatch (expected {expected_oper}, device oper_up={live_oper})"
                    )

            status_label = _extract_status_label(iface)

            if mismatch_messages:
                differences_found += 1
                self.logger.warning(
                    f"Interface '{iface.name}' mismatch: {', '.join(mismatch_messages)}",
                    extra={"grouping": "interface-compliance"},
                )
            else:
                self.logger.debug(
                    f"Interface '{iface.name}' compliant (admin_up={live_admin}, oper_up={live_oper}).",
                    extra={"grouping": "interface-compliance"},
                )

            results.append(
                {
                    "interface": iface.name,
                    "status": "fail" if mismatch_messages else "pass",
                    "nautobot": {
                        "enabled": nb_admin_enabled,
                        "status": status_label,
                        "expected_oper_up": expected_oper,
                    },
                    "device": {
                        "admin_up": live_admin,
                        "oper_up": live_oper,
                        "details": live_detail,
                    },
                    "differences": mismatch_messages,
                }
            )

        overall_status = "pass" if differences_found == 0 else "fail"
        payload = {
            "device": device.name,
            "overall_status": overall_status,
            "checked_interfaces": len(interfaces),
            "interfaces": results,
        }

        self.job_result.data = payload
        if differences_found == 0:
            self.job_result.set_status(JobResultStatusChoices.STATUS_SUCCESS)
            self.logger.success(
                f"Interface compliance passed for device '{device.name}'.",
                extra={"grouping": "interface-compliance"},
            )
        else:
            self.job_result.set_status(JobResultStatusChoices.STATUS_FAILURE)
            self.logger.failure(
                f"Interface compliance failed for device '{device.name}' ({differences_found} mismatches).",
                extra={"grouping": "interface-compliance"},
            )

        return payload

    def _get_credentials(self, secrets_group: SecretsGroup, device: Device) -> tuple[str, str]:
        """Retrieve username/password from the Secrets Group."""
        access_type = SecretsGroupAccessTypeChoices.TYPE_GENERIC

        username: Optional[str] = None
        password: Optional[str] = None

        try:
            username = secrets_group.get_secret_value(
                access_type=access_type,
                secret_type=SecretsGroupSecretTypeChoices.TYPE_USERNAME,
                obj=device,
            )
        except ObjectDoesNotExist:
            self._fail_job(
                f"Secrets Group '{secrets_group}' does not define a Generic/username secret."
            )
        except SecretError as exc:
            self._fail_job(f"Unable to retrieve username: {exc.message}")

        try:
            password = secrets_group.get_secret_value(
                access_type=access_type,
                secret_type=SecretsGroupSecretTypeChoices.TYPE_PASSWORD,
                obj=device,
            )
        except ObjectDoesNotExist:
            self._fail_job(
                f"Secrets Group '{secrets_group}' does not define a Generic/password secret."
            )
        except SecretError as exc:
            self._fail_job(f"Unable to retrieve password: {exc.message}")

        # The calls above will raise via _fail_job on error.
        assert username is not None
        assert password is not None
        return username, password

    @staticmethod
    def _expected_operational_state(interface) -> Optional[bool]:
        """Infer expected operational state from the interface's status (if any)."""
        status = getattr(interface, "status", None)
        candidates: List[str] = []
        for attr in ("slug", "value", "name", "label"):
            value = getattr(status, attr, None)
            if value:
                candidates.append(str(value))
        if status:
            candidates.append(str(status))

        normalized = {value.strip().lower() for value in candidates if value}
        if normalized & {"active", "connected", "in-service", "up"}:
            return True
        if normalized & {"planned", "offline", "decommissioned", "down", "failed", "disabled"}:
            return False
        return None

    def _fail_job(self, message: str) -> None:
        """Fail the job with a descriptive message."""
        self.logger.failure(message)
        self.job_result.set_status(JobResultStatusChoices.STATUS_FAILURE)
        raise RuntimeError(message)


def _coerce_bool(value: object) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "up", "enabled", "yes", "on"}:
            return True
        if lowered in {"false", "down", "disabled", "no", "off"}:
            return False
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return bool(value)
    return None


def _extract_status_label(interface) -> Optional[str]:
    status = getattr(interface, "status", None)
    if not status:
        return None
    for attr in ("label", "name", "value", "slug"):
        value = getattr(status, attr, None)
        if value:
            return str(value)
    return str(status)


__all__ = ["InterfaceComplianceJob"]
