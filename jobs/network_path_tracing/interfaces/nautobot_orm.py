"""Concrete Nautobot data source implementation backed by the ORM."""

from __future__ import annotations

from typing import Any, Optional

from django.core.exceptions import FieldError

from .nautobot import (
    IPAddressRecord,
    NautobotDataSource,
    PrefixRecord,
    DeviceRecord,
    RedundancyMember,
    RedundancyResolution,
)

try:
    from nautobot.ipam.models import IPAddress, Prefix
    from nautobot.dcim.models import Device, InterfaceRedundancyGroupAssociation
except Exception:
    IPAddress = None
    Prefix = None
    Device = None
    InterfaceRedundancyGroupAssociation = None


class NautobotORMDataSource(NautobotDataSource):
    """Retrieve data directly from Nautobot's Django models."""

    def get_ip_address(self, address: str) -> Optional[IPAddressRecord]:
        """Return the IPAddress record for the given address.

        Args:
            address (str): IP address without prefix (e.g., '10.0.0.1').

        Returns:
            Optional[IPAddressRecord]: The IP address record, or None if not found.
        """
        if IPAddress is None:
            raise RuntimeError("Nautobot is not available in this environment")
        ip_obj = IPAddress.objects.filter(host=address).first()
        if ip_obj is None:
            return None
        return self._build_ip_record(ip_obj, override_address=address)

    def get_most_specific_prefix(self, address: str) -> Optional[PrefixRecord]:
        """Return the most specific prefix containing the supplied address.

        Args:
            address (str): IP address to find the containing prefix for.

        Returns:
            Optional[PrefixRecord]: The most specific prefix, or None if not found.
        """
        if Prefix is None:
            raise RuntimeError("Nautobot is not available in this environment")
        prefix_obj = (
            Prefix.objects.filter(network__net_contains_or_equals=address)
            .order_by("-prefix_length")
            .first()
        )
        if prefix_obj is None:
            return None
        status = prefix_obj.status.name if getattr(prefix_obj, "status", None) else None
        return PrefixRecord(
            id=str(prefix_obj.pk),
            prefix=str(prefix_obj.prefix),
            status=status,
        )

    def find_gateway_ip(self, prefix: PrefixRecord, custom_field: str) -> Optional[IPAddressRecord]:
        """Return the gateway IP within the prefix tagged via custom_field.

        Args:
            prefix (PrefixRecord): The prefix to search for a gateway.
            custom_field (str): The custom field name (e.g., 'network_gateway').

        Returns:
            Optional[IPAddressRecord]: The gateway IP record, or None if not found.
        """
        if IPAddress is None:
            raise RuntimeError("Nautobot is not available in this environment")
        prefix_obj = None
        if Prefix is None:
            raise RuntimeError("Nautobot is not available in this environment")
        if prefix.id:
            prefix_obj = Prefix.objects.filter(pk=prefix.id).first()
        elif prefix.prefix:
            prefix_obj = Prefix.objects.filter(network__net_equals=prefix.prefix).first()
        if prefix_obj is None:
            return None
        filter_kwargs = {"parent": prefix_obj}
        if custom_field:
            filter_kwargs[f"_custom_field_data__{custom_field}"] = True
        ip_obj = IPAddress.objects.filter(**filter_kwargs).first()
        if ip_obj is None:
            return None
        return self._build_ip_record(ip_obj)

    def get_device(self, name: str) -> Optional[DeviceRecord]:
        """Return the Device record for the given name.

        Args:
            name (str): The device name to look up.

        Returns:
            Optional[DeviceRecord]: The device record, or None if not found.
        """
        if Device is None:
            raise RuntimeError("Nautobot is not available in this environment")
        device_obj = Device.objects.filter(**{"name": name}).select_related("primary_ip4", "platform").first()
        if not device_obj:
            return None
        primary_ip = None
        if device_obj.primary_ip4:
            primary_ip = str(device_obj.primary_ip4.host)
        platform_slug = None
        platform_name = None
        napalm_driver = None
        if device_obj.platform:
            platform = device_obj.platform
            platform_name = getattr(platform, "name", None)
            platform_slug = getattr(platform, "slug", None) or getattr(platform, "identifier", None)
            network_mappings = getattr(platform, "network_driver_mappings", None)
            if isinstance(network_mappings, dict):
                napalm_driver = network_mappings.get("napalm") or network_mappings.get("napalm", None)
            if not napalm_driver:
                napalm_driver = getattr(platform, "napalm_driver", None)
            if not platform_slug and isinstance(napalm_driver, str):
                platform_slug = napalm_driver
        return DeviceRecord(
            name=device_obj.name,
            primary_ip=primary_ip,
            platform_slug=platform_slug,
            platform_name=platform_name,
            napalm_driver=napalm_driver,
        )

    def get_interface_ip(self, device_name: str, interface_name: str) -> Optional[IPAddressRecord]:
        """Return the first IP assigned to ``device_name``/``interface_name``.

        Args:
            device_name: Device name as stored in Nautobot.
            interface_name: Interface name on the device.

        Returns:
            Optional[IPAddressRecord]: Interface IP record if present.
        """
        if IPAddress is None:
            raise RuntimeError("Nautobot is not available in this environment")
        if not device_name or not interface_name:
            return None

        query_variants = [
            {
                "interface_assignments__interface__device__name": device_name,
                "interface_assignments__interface__name": interface_name,
            },
            {
                "interfaces__device__name": device_name,
                "interfaces__name": interface_name,
            },
            {
                "assigned_object__device__name": device_name,
                "assigned_object__name": interface_name,
            },
        ]

        for filter_kwargs in query_variants:
            try:
                ip_obj = IPAddress.objects.filter(**filter_kwargs).first()
            except FieldError:
                continue
            if ip_obj:
                return self._build_ip_record(ip_obj)

        return None

    def resolve_redundant_gateway(self, address: str) -> Optional[RedundancyResolution]:
        """Resolve gateway device/interface from interface redundancy groups (e.g., HSRP)."""

        if IPAddress is None or InterfaceRedundancyGroupAssociation is None:
            return None

        ip_obj = (
            IPAddress.objects.filter(host=address)
            .prefetch_related("interface_redundancy_groups")
            .first()
        )
        if ip_obj is None:
            return None

        groups_manager = getattr(ip_obj, "interface_redundancy_groups", None)
        if not groups_manager:
            return None

        try:
            groups = list(groups_manager.all())
        except Exception:  # pragma: no cover - defensive for older Nautobot
            return None
        if not groups:
            return None

        assignments_qs = InterfaceRedundancyGroupAssociation.objects.filter(
            interface_redundancy_group__in=groups
        ).select_related("interface__device")

        if not assignments_qs:
            return None

        enriched_assignments: list[tuple[InterfaceRedundancyGroupAssociation, int, str, str]] = []
        for assignment in assignments_qs:
            interface = getattr(assignment, "interface", None)
            device = getattr(interface, "device", None) if interface else None
            device_name = getattr(device, "name", None)
            interface_name = getattr(interface, "name", None)
            if not device_name or not interface_name:
                continue
            priority_value = getattr(assignment, "priority", None)
            try:
                priority = int(priority_value)
            except (TypeError, ValueError):
                priority = -1
            enriched_assignments.append((assignment, priority, device_name, interface_name))

        if not enriched_assignments:
            return None

        enriched_assignments.sort(key=lambda item: (-item[1], item[2], item[3]))
        chosen_assignment = None
        for assignment, priority, device_name, interface_name in enriched_assignments:
            if priority < 0:
                continue
            chosen_assignment = (assignment, priority, device_name, interface_name)
            break

        if chosen_assignment is None:
            chosen_assignment = enriched_assignments[0]

        assignment_obj, _, _, _ = chosen_assignment

        interface = getattr(assignment_obj, "interface", None)
        device = getattr(interface, "device", None) if interface else None

        preferred_record = IPAddressRecord(
            address=str(ip_obj.host),
            prefix_length=int(ip_obj.mask_length),
            device_name=getattr(device, "name", None),
            interface_name=getattr(interface, "name", None),
        )

        members: list[RedundancyMember] = []
        for assignment, priority, device_name, interface_name in enriched_assignments:
            members.append(
                RedundancyMember(
                    device_name=device_name,
                    interface_name=interface_name,
                    priority=priority if priority >= 0 else None,
                    is_preferred=(
                        device_name == preferred_record.device_name
                        and interface_name == preferred_record.interface_name
                    ),
                )
            )

        return RedundancyResolution(
            preferred=preferred_record,
            members=tuple(members),
        )

    def _build_ip_record(self, ip_obj: Any, override_address: Optional[str] = None) -> IPAddressRecord:
        """Build an IPAddressRecord from ORM data.

        Args:
            ip_obj: The IPAddress model instance.
            override_address (Optional[str]): Optional address to override the model’s host.

        Returns:
            IPAddressRecord: The constructed IP address record.
        """
        address = override_address or str(ip_obj.host)
        prefix_length = int(ip_obj.mask_length)
        device_name = None
        interface_name = None
        # Access the first related interface (if any)
        interface = None
        if hasattr(ip_obj, "assigned_object") and ip_obj.assigned_object is not None:
            interface = ip_obj.assigned_object
        elif hasattr(ip_obj, "interface") and ip_obj.interface is not None:
            interface = ip_obj.interface
        elif hasattr(ip_obj, "interfaces"):
            interface = ip_obj.interfaces.first()
        if interface:
            interface_name = getattr(interface, "name", None) or getattr(interface, "display", None)
            if getattr(interface, "device", None):
                device_name = getattr(interface.device, "name", None)
        return IPAddressRecord(
            address=address,
            prefix_length=prefix_length,
            device_name=device_name,
            interface_name=interface_name,
        )
