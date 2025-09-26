"""Concrete Nautobot data source implementation backed by the ORM."""

from __future__ import annotations

from typing import Any, Optional

from .nautobot import IPAddressRecord, NautobotDataSource, PrefixRecord, DeviceRecord

try:
    from nautobot.ipam.models import IPAddress, Prefix
    from nautobot.dcim.models import Device, Interface
except Exception:
    IPAddress = None
    Prefix = None
    Device = None
    Interface = None


class NautobotORMDataSource(NautobotDataSource):
    """Retrieve data directly from Nautobot's Django models."""

    def get_ip_address(self, address: str) -> Optional[IPAddressRecord]:
        """Return the IPAddress record for the given address."""
        if IPAddress is None:
            raise RuntimeError("Nautobot is not available in this environment")
        ip_obj = IPAddress.objects.filter(host=address).first()
        if ip_obj is None:
            return None
        return self._build_ip_record(ip_obj, override_address=address)

    def get_most_specific_prefix(self, address: str) -> Optional[PrefixRecord]:
        """Return the most specific prefix containing the supplied address."""
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
        """Return the gateway IP within the prefix tagged via custom_field."""
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
        """Return the Device record for the given name."""
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

    def get_interface(self, device_name: str, interface_name: str) -> Optional[Any]:
        """Return the Interface record for the given device and interface name."""
        if Interface is None:
            raise RuntimeError("Nautobot is not available in this environment")
        interface_obj = Interface.objects.filter(device__name=device_name, name=interface_name).first()
        return interface_obj

    def _build_ip_record(self, ip_obj: Any, override_address: Optional[str] = None) -> IPAddressRecord:
        """Build an IPAddressRecord from ORM data."""
        address = override_address or str(ip_obj.host)
        prefix_length = int(ip_obj.mask_length)
        device_name = None
        interface_name = None
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