"""Nautobot data source that talks to the REST API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import requests

from ..config import NautobotAPISettings
from .nautobot import IPAddressRecord, NautobotDataSource, PrefixRecord, DeviceRecord


@dataclass
class NautobotAPISession:
    """Thin wrapper around a requests session configured for Nautobot."""
    settings: NautobotAPISettings

    def __post_init__(self) -> None:
        if not self.settings.is_configured():
            raise RuntimeError("Nautobot API settings are not configured")
        self._session = requests.Session()
        self._session.headers.update({"Authorization": f"Token {self.settings.token}"})

    def get(self, path: str, **kwargs) -> requests.Response:
        url = urljoin(self.settings.base_url.rstrip("/") + "/", path.lstrip("/"))
        response = self._session.get(url, verify=self.settings.verify_ssl, timeout=30, **kwargs)
        response.raise_for_status()
        return response

    def get_json(self, path: str, **kwargs) -> Dict[str, Any]:
        return self.get(path, **kwargs).json()


class NautobotAPIDataSource(NautobotDataSource):
    """Retrieve Nautobot information over the REST API."""
    def __init__(self, settings: NautobotAPISettings) -> None:
        self._session = NautobotAPISession(settings)

    def get_ip_address(self, address: str) -> Optional[IPAddressRecord]:
        params = {"address": address, "limit": 1}
        response = self._session.get("/api/ipam/ip-addresses/", params=params)
        payload = response.json()
        results = payload.get("results", [])
        if not results:
            return None
        record = self._expand_ip_record(results[0])
        return self._build_ip_record(record, override_address=address)

    def get_most_specific_prefix(self, address: str) -> Optional[PrefixRecord]:
        params = {"contains": address, "limit": 50}
        response = self._session.get("/api/ipam/prefixes/", params=params)
        payload = response.json()
        results = payload.get("results", [])
        if not results:
            return None
        best = max(results, key=lambda item: item.get("prefix_length", 0))
        status = best.get("status")
        if isinstance(status, dict):
            status_name = status.get("value") or status.get("name") or status.get("label")
        else:
            status_name = status
        return PrefixRecord(
            id=str(best.get("id")) if best.get("id") else None,
            prefix=str(best.get("prefix")),
            status=status_name,
        )

    def find_gateway_ip(self, prefix: PrefixRecord, custom_field: str) -> Optional[IPAddressRecord]:
        parent_value = self._ensure_prefix_id(prefix)
        params = {"parent": parent_value, f"cf_{custom_field}": True, "limit": 10}
        payload = self._session.get_json("/api/ipam/ip-addresses/", params=params)
        results = payload.get("results", [])
        if not results:
            return None
        record = self._expand_ip_record(results[0])
        return self._build_ip_record(record)

    def get_device(self, name: str) -> Optional[DeviceRecord]:
        params = {"name": name, "limit": 1, "depth": 1}
        payload = self._session.get_json("/api/dcim/devices/", params=params)
        results = payload.get("results", [])
        if not results:
            return None
        device = results[0]
        primary_ip = None
        primary_ip4 = device.get("primary_ip4")
        if isinstance(primary_ip4, dict):
            primary_ip = self._strip_prefix(primary_ip4.get("address"))
        platform = device.get("platform")
        platform_slug = None
        platform_name = None
        if isinstance(platform, dict):
            platform_slug = platform.get("slug")
            platform_name = platform.get("name")
        return DeviceRecord(
            name=str(device.get("name") or device.get("display") or name),
            primary_ip=primary_ip,
            platform_slug=platform_slug,
            platform_name=platform_name,
        )

    def _ensure_prefix_id(self, prefix: PrefixRecord) -> str:
        if prefix.id:
            return prefix.id
        params = {"prefix": prefix.prefix, "limit": 1}
        payload = self._session.get_json("/api/ipam/prefixes/", params=params)
        results = payload.get("results", [])
        if results:
            result = results[0]
            prefix_id = result.get("id")
            if prefix_id:
                return str(prefix_id)
        return prefix.prefix

    def _expand_ip_record(self, record: dict) -> dict:
        if isinstance(record.get("assigned_object"), dict) and record.get("assigned_object"):
            return record
        record_id = record.get("id")
        if not record_id:
            return record
        try:
            expanded = self._session.get_json(f"/api/ipam/ip-addresses/{record_id}/", params={"depth": 1})
        except requests.RequestException:
            return record
        return expanded if isinstance(expanded, dict) else record

    def _build_ip_record(self, record: dict, override_address: Optional[str] = None) -> IPAddressRecord:
        address_value = override_address or record.get("host") or record.get("address", "")
        prefix_length = (
            record.get("mask_length")
            or record.get("prefix_length")
            or self._extract_prefix_length(address_value)
            or self._extract_prefix_length(record.get("address"))
            or 32
        )
        address_str = self._strip_prefix(address_value)
        if not address_str:
            address_str = self._strip_prefix(record.get("address"))
        device_name, interface_name = self._resolve_assignment_details(record)
        return IPAddressRecord(
            address=address_str,
            prefix_length=int(prefix_length),
            device_name=device_name,
            interface_name=interface_name,
        )

    @staticmethod
    def _extract_prefix_length(value: Optional[str]) -> Optional[int]:
        if isinstance(value, str) and "/" in value:
            try:
                return int(value.split("/")[1])
            except (ValueError, IndexError):
                return None
        return None

    @staticmethod
    def _strip_prefix(value: Optional[str]) -> str:
        if not isinstance(value, str):
            return ""
        return value.split("/")[0]

    def _resolve_assignment_details(self, record: dict) -> tuple[Optional[str], Optional[str]]:
        device_name: Optional[str] = None
        interface_name: Optional[str] = None
        assigned = record.get("assigned_object")
        if isinstance(assigned, dict):
            interface_name = assigned.get("name") or assigned.get("display") or interface_name
            device_name = self._extract_name_from_relationship(assigned.get("device")) or device_name
            url = assigned.get("url")
            if (not device_name or not interface_name) and isinstance(url, str) and url:
                related_device, related_interface = self._resolve_names_from_url(url)
                device_name = device_name or related_device
                interface_name = interface_name or related_interface
            if device_name and interface_name:
                return device_name, interface_name
        interfaces = record.get("interfaces") or []
        if interfaces:
            related_device, related_interface = self._resolve_names_from_interfaces(interfaces)
            device_name = device_name or related_device
            interface_name = interface_name or related_interface
            if device_name or interface_name:
                return device_name, interface_name
        if not device_name:
            device_name = self._fetch_device_name_via_api(record)
        if not device_name:
            device_name = self._lookup_device_by_primary_ip(record)
        return device_name, interface_name

    def _fetch_device_name_via_api(self, record: dict) -> Optional[str]:
        assigned_type = record.get("assigned_object_type")
        assigned_id = record.get("assigned_object_id")
        if not assigned_type or not assigned_id:
            return None
        endpoint = self._endpoint_for_assigned_object(assigned_type)
        if not endpoint:
            return None
        try:
            related = self._session.get_json(f"{endpoint}{assigned_id}/")
        except requests.RequestException:
            return None
        device = related.get("device")
        if isinstance(device, dict):
            name = device.get("name") or device.get("display")
            if name:
                return name
        vm = related.get("virtual_machine")
        if isinstance(vm, dict):
            name = vm.get("name") or vm.get("display")
            if name:
                return name
        return related.get("name") or related.get("display")

    def _endpoint_for_assigned_object(self, assigned_type: str) -> Optional[str]:
        mapping = {
            "dcim.interface": "/api/dcim/interfaces/",
            "virtualization.vminterface": "/api/virtualization/interfaces/",
            "dcim.frontport": "/api/dcim/front-ports/",
            "dcim.rearport": "/api/dcim/rear-ports/",
        }
        return mapping.get(assigned_type)

    def _resolve_names_from_interfaces(self, interfaces: list[dict]) -> tuple[Optional[str], Optional[str]]:
        for iface in interfaces:
            url = iface.get("url")
            if not isinstance(url, str) or not url:
                continue
            device_name, interface_name = self._resolve_names_from_url(url)
            if device_name or interface_name:
                return device_name, interface_name
        return None, None

    def _resolve_names_from_url(self, url: str) -> tuple[Optional[str], Optional[str]]:
        try:
            payload = self._session.get_json(url, params={"depth": 1})
        except requests.RequestException:
            return None, None
        return self._extract_names_from_payload(payload)

    def _lookup_device_by_primary_ip(self, record: dict) -> Optional[str]:
        address = record.get("address")
        if not isinstance(address, str):
            return None
        ip, _, _ = address.partition("/")
        if not ip:
            return None
        search_patterns = [
            ("/api/dcim/devices/", {"primary_ip4_id": record.get("id")}),
            ("/api/dcim/devices/", {"primary_ip6_id": record.get("id")}),
            ("/api/dcim/devices/", {"primary_ip4": ip}),
            ("/api/dcim/devices/", {"primary_ip6": ip}),
            ("/api/dcim/devices/", {"primary_ip": ip}),
            ("/api/virtualization/virtual-machines/", {"primary_ip4_id": record.get("id")}),
            ("/api/virtualization/virtual-machines/", {"primary_ip6_id": record.get("id")}),
            ("/api/virtualization/virtual-machines/", {"primary_ip4": ip}),
            ("/api/virtualization/virtual-machines/", {"primary_ip6": ip}),
            ("/api/virtualization/virtual-machines/", {"primary_ip": ip}),
        ]
        for endpoint, params in search_patterns:
            query = {k: v for k, v in params.items() if v}
            if not query:
                continue
            try:
                payload = self._session.get_json(endpoint, params={**query, "limit": 1})
            except requests.RequestException:
                continue
            results = payload.get("results", [])
            if results:
                result = results[0]
                name = result.get("name") or result.get("display")
                if name:
                    return name
        return None

    @staticmethod
    def _extract_name_from_relationship(related: Any) -> Optional[str]:
        if isinstance(related, dict):
            return related.get("name") or related.get("display")
        if isinstance(related, str):
            return related
        return None

    def _extract_names_from_payload(self, payload: dict) -> tuple[Optional[str], Optional[str]]:
        interface_name = payload.get("name") or payload.get("display")
        device_name = self._extract_name_from_relationship(payload.get("device"))
        if not device_name:
            device_name = self._extract_name_from_relationship(payload.get("virtual_machine"))
        return device_name, interface_name