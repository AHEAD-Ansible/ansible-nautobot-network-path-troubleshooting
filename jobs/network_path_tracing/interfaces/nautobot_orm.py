"""Concrete Nautobot data source implementation backed by the ORM."""

from __future__ import annotations

from typing import Any, Optional

from .nautobot import IPAddressRecord, NautobotDataSource, PrefixRecord, DeviceRecord

try:
    from nautobot.ipam.models import IPAddress, Prefix
    from nautobot.dcim.models import Device
except Exception:
    IPAddress = None
    Prefix = None
    Device = None


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
        ip_obj = (
            IPAddress.objects.filter(host=address)
            .select_related("device", "assigned_object")
            .prefetch_related("assigned_object__device", "assigned_object__virtual_machine")
            .first()
        )
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
            Prefix.objects.filter(prefix__net_contains_or_equals=address)
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
        prefix_obj = Prefix.objects.filter(prefix=prefix.prefix).first() if Prefix else None
        if prefix_obj is None:
            return None
        filter_kwargs = {f"custom_field_data__{custom_field}": True, "parent": prefix_obj}
        ip_obj = (
            IPAddress.objects.filter(**filter_kwargs)
            .select_related("device", "assigned_object")
            .prefetch_related("assigned_object__device", "assigned_object__virtual_machine")
            .first()
        )
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
        device_obj = (
            Device.objects.filter(name=name)
            .select_related("primary_ip4", "platform")
            .first()
        )
        if not device_obj:
            return None
        primary_ip = None
        if device_obj.primary_ip4:
            primary_ip = str(device_obj.primary_ip4.host)
        platform_slug = None
        platform_name = None
        if device_obj.platform:
            platform_slug = device_obj.platform.slug
            platform_name = device_obj.platform.name
        return DeviceRecord(
            name=device_obj.name,
            primary_ip=primary_ip,
            platform_slug=platform_slug,
            platform_name=platform_name,
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
        device_name = getattr(ip_obj.device, "name", None) if getattr(ip_obj, "device", None) else None
        interface_name = None
        assigned = getattr(ip_obj, "assigned_object", None)
        if assigned is not None:
            interface_name = getattr(assigned, "name", None) or getattr(assigned, "display", None)
            if not device_name and getattr(assigned, "device", None):
                device_name = getattr(assigned.device, "name", None)
            if not device_name and getattr(assigned, "virtual_machine", None):
                device_name = getattr(assigned.virtual_machine, "name", None)
        return IPAddressRecord(
            address=address,
            prefix_length=prefix_length,
            device_name=device_name,
            interface_name=interface_name,
        )