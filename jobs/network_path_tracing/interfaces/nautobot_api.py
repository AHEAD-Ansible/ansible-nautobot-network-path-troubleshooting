"""Nautobot data source that talks to the REST API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import requests

from ..config import NautobotAPISettings
from .nautobot import (
    IPAddressRecord,
    NautobotDataSource,
    PrefixRecord,
    DeviceRecord,
    RedundancyMember,
    RedundancyResolution,
)


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
        """Fetch data from the Nautobot API."""
        url = urljoin(self.settings.base_url.rstrip("/") + "/", path.lstrip("/"))
        response = self._session.get(url, verify=self.settings.verify_ssl, timeout=30, **kwargs)
        response.raise_for_status()
        return response

    def get_json(self, path: str, **kwargs) -> Dict[str, Any]:
        """Fetch JSON data from the Nautobot API."""
        return self.get(path, **kwargs).json()


class NautobotAPIDataSource(NautobotDataSource):
    """Retrieve Nautobot information over the REST API."""
    def __init__(self, settings: NautobotAPISettings) -> None:
        self._session = NautobotAPISession(settings)

    def get_ip_address(self, address: str) -> Optional[IPAddressRecord]:
        """Return the IPAddress record for the given address."""
        params = {"address": address, "limit": 1}
        response = self._session.get("/api/ipam/ip-addresses/", params=params)
        payload = response.json()
        results = payload.get("results", [])
        if not results:
            return None
        record = self._expand_ip_record(results[0])
        return self._build_ip_record(record, override_address=address)

    def get_most_specific_prefix(self, address: str) -> Optional[PrefixRecord]:
        """Return the most specific prefix containing the supplied address."""
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
        """Return the gateway IP within the prefix tagged via custom_field."""
        parent_value = self._ensure_prefix_id(prefix)
        params = {"parent": parent_value, f"cf_{custom_field}": True, "limit": 10}
        payload = self._session.get_json("/api/ipam/ip-addresses/", params=params)
        results = payload.get("results", [])
        if not results:
            return None
        record = self._expand_ip_record(results[0])
        return self._build_ip_record(record)

    def get_device(self, name: str) -> Optional[DeviceRecord]:
        """Return the Device record for the given name."""
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
        napalm_driver = None
        if isinstance(platform, dict):
            platform_slug = platform.get("slug") or platform.get("identifier")
            platform_name = platform.get("name")
            mappings = platform.get("network_driver_mappings")
            if isinstance(mappings, dict):
                napalm_driver = mappings.get("napalm") or mappings.get("napalm", None)
            napalm_driver = napalm_driver or platform.get("napalm_driver")
            if not platform_slug and napalm_driver:
                platform_slug = napalm_driver
        return DeviceRecord(
            name=str(device.get("name") or device.get("display") or name),
            primary_ip=primary_ip,
            platform_slug=platform_slug,
            platform_name=platform_name,
            napalm_driver=napalm_driver,
        )

    def get_interface_ip(self, device_name: str, interface_name: str) -> Optional[IPAddressRecord]:
        """Return IP information for the requested device/interface pair."""
        if not device_name or not interface_name:
            return None

        params = {
            "device": device_name,
            "name": interface_name,
            "limit": 1,
            "depth": 1,
        }
        try:
            payload = self._session.get_json("/api/dcim/interfaces/", params=params)
        except requests.RequestException:
            return None

        results = payload.get("results", [])
        if not results:
            return None

        interface = results[0]
        ip_assignments = interface.get("ip_addresses") or []
        if not ip_assignments:
            return None

        ip_entry = ip_assignments[0]
        ip_id = ip_entry.get("id")
        if not ip_id:
            address = ip_entry.get("address")
            if not address:
                return None
            return IPAddressRecord(
                address=self._strip_prefix(address),
                prefix_length=self._extract_prefix_length(address) or 32,
                device_name=device_name,
                interface_name=interface_name,
            )

        try:
            record = self._session.get_json(f"/api/ipam/ip-addresses/{ip_id}/", params={"depth": 1})
        except requests.RequestException:
            return None

        return self._build_ip_record(record)


    def resolve_redundant_gateway(self, address: str) -> Optional[RedundancyResolution]:
        """Resolve gateway details via interface-redundancy groups over the REST API."""
        if not address:
            return None

        record: Optional[dict] = None
        assignments: list[dict] = []
        group_ids: set[str] = set()

        ip_payload = self._fetch_ip_with_redundancy(address)
        ip_record: Optional[dict] = None
        if ip_payload:
            record, groups = ip_payload
            ip_record = record
            if groups:
                group_ids.update(self._group_ids_from_payload(groups))

        extra_groups = self._fetch_groups_by_virtual_ip(address, ip_record)
        if extra_groups:
            group_ids.update(self._group_ids_from_payload(extra_groups))
            if record is None:
                for group in extra_groups:
                    record = self._expand_group_virtual_ip(group)
                    if record:
                        break

        for group_id in group_ids:
            assignments.extend(self._fetch_redundancy_assignments(group_id))
            if record is None:
                detail = self._fetch_group_detail(group_id)
                if detail:
                    record = self._expand_group_virtual_ip(detail) or record

        if not assignments:
            return None

        enriched: list[tuple[Optional[int], str, str]] = []
        best: Optional[tuple[int, str, str, str, str]] = None
        for item in assignments:
            interface = item.get("interface") or {}
            device = interface.get("device") or {}
            interface_name = interface.get("name") or interface.get("display")
            device_name = device.get("name") or device.get("display")
            if not interface_name or not device_name:
                device_name, interface_name = self._expand_interface_names(
                    interface, device_name, interface_name
                )
            if not interface_name or not device_name:
                continue
            priority_raw = item.get("priority")
            try:
                priority_value = int(priority_raw)
            except (TypeError, ValueError):
                priority_value = -1
            enriched.append((
                priority_value if priority_value >= 0 else None,
                device_name,
                interface_name,
            ))
            sort_key = (-priority_value, device_name, interface_name)
            if best is None or sort_key < best[:3]:
                best = (*sort_key, device_name, interface_name)

        if best is None:
            return None

        device_name, interface_name = best[3], best[4]

        if record is None:
            record = {
                "address": address,
                "prefix_length": self._extract_prefix_length(address) or 32,
            }

        prefix_length = (
            record.get("mask_length")
            or record.get("prefix_length")
            or self._extract_prefix_length(record.get("address"))
            or self._extract_prefix_length(address)
            or 32
        )
        ip_address = self._strip_prefix(record.get("address")) or address

        preferred_record = IPAddressRecord(
            address=ip_address,
            prefix_length=int(prefix_length),
            device_name=device_name,
            interface_name=interface_name,
        )

        members: list[RedundancyMember] = []
        for priority, member_device, member_interface in enriched:
            members.append(
                RedundancyMember(
                    device_name=member_device,
                    interface_name=member_interface,
                    priority=priority,
                    is_preferred=(
                        member_device == device_name and member_interface == interface_name
                    ),
                )
            )

        return RedundancyResolution(preferred=preferred_record, members=tuple(members))

    def _group_ids_from_payload(self, groups: Any) -> set[str]:
        """Extract set of redundancy-group IDs from API payload values."""
        ids: set[str] = set()
        for group in groups or []:
            if isinstance(group, dict):
                group_id = group.get("id")
                if group_id:
                    ids.add(str(group_id))
            elif isinstance(group, str):
                trimmed = group.rstrip("/")
                if trimmed:
                    ids.add(trimmed.split("/")[-1])
        return ids

    def _expand_interface_names(
        self,
        interface: dict,
        current_device: Optional[str],
        current_interface: Optional[str],
    ) -> tuple[Optional[str], Optional[str]]:
        """Return enriched device/interface names for a redundancy assignment interface."""

        device_name = current_device
        interface_name = current_interface
        url = interface.get("url") if isinstance(interface, dict) else None
        interface_id = interface.get("id") if isinstance(interface, dict) else None

        try_endpoints = []
        if url:
            try_endpoints.append((url, {}))
        if interface_id:
            try_endpoints.append((f"/api/dcim/interfaces/{interface_id}/", {"depth": 1}))

        for endpoint, params in try_endpoints:
            try:
                payload = self._session.get_json(endpoint, params=params or {"depth": 1})
            except requests.RequestException:
                continue
            if not isinstance(payload, dict):
                continue
            extracted_device = self._extract_name_from_relationship(payload.get("device"))
            extracted_interface = payload.get("name") or payload.get("display")
            device_name = device_name or extracted_device
            interface_name = interface_name or extracted_interface
            if device_name and interface_name:
                break

        if not (device_name and interface_name) and isinstance(interface, dict):
            parent = interface.get("parent")
            if isinstance(parent, dict):
                device_name = device_name or self._extract_name_from_relationship(parent.get("device"))
                interface_name = interface_name or parent.get("name") or parent.get("display")

        return device_name, interface_name

    def _fetch_ip_with_redundancy(self, address: str) -> Optional[tuple[dict, list[dict]]]:
        params = {"address": address, "limit": 1, "depth": 1}
        try:
            payload = self._session.get_json("/api/ipam/ip-addresses/", params=params)
        except requests.RequestException:
            payload = None
        results = (payload or {}).get("results", []) if payload else []
        if not results and "/" not in address:
            params["address"] = f"{address}/32"
            try:
                payload = self._session.get_json("/api/ipam/ip-addresses/", params=params)
            except requests.RequestException:
                return None
            results = payload.get("results", []) if payload else []
        if not results:
            return None
        record = results[0]
        groups = record.get("interface_redundancy_groups") or []
        return record, groups

    def _fetch_groups_by_virtual_ip(self, address: str, ip_record: Optional[dict]) -> list[dict]:
        query_values = [address]
        if "/" not in address:
            query_values.append(f"{address}/32")
        if ip_record:
            ip_id = ip_record.get("id")
            ip_url = ip_record.get("url") or ip_record.get("absolute_url")
            if ip_id:
                query_values.append(str(ip_id))
                query_values.append(f"/api/ipam/ip-addresses/{ip_id}/")
            if ip_url:
                query_values.append(ip_url)
        collected: dict[str, dict] = {}
        for value in query_values:
            for field in ("virtual_ip", "virtual_ip_id"):
                params = {field: value, "limit": 10, "depth": 1}
                try:
                    payload = self._session.get_json(
                        "/api/dcim/interface-redundancy-groups/", params=params
                    )
                except requests.RequestException:
                    continue
                if not isinstance(payload, dict):
                    continue
                for group in payload.get("results", []) or []:
                    if isinstance(group, dict):
                        group_id = group.get("id")
                        if group_id is not None:
                            collected[str(group_id)] = group
        return list(collected.values())

    def _expand_group_virtual_ip(self, group: Any) -> Optional[dict]:
        if isinstance(group, str):
            detail = self._fetch_group_detail(group.rstrip("/").split("/")[-1])
            return self._expand_group_virtual_ip(detail) if detail else None
        if not isinstance(group, dict):
            return None
        virtual_ip = group.get("virtual_ip")
        if isinstance(virtual_ip, dict):
            ip_id = virtual_ip.get("id")
            if ip_id:
                try:
                    return self._session.get_json(f"/api/ipam/ip-addresses/{ip_id}/", params={"depth": 1})
                except requests.RequestException:
                    return virtual_ip
            return virtual_ip
        return None

    def _fetch_group_detail(self, group_id: Optional[str]) -> Optional[dict]:
        if not group_id:
            return None
        try:
            return self._session.get_json(f"/api/dcim/interface-redundancy-groups/{group_id}/", params={"depth": 1})
        except requests.RequestException:
            return None

    def _fetch_redundancy_assignments(self, group_id: Optional[str]) -> list[dict]:
        if not group_id:
            return []
        assignments: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for field in ("interface_redundancy_group", "interface_redundancy_group_id"):
            params = {field: group_id, "limit": 200, "depth": 1}
            try:
                payload = self._session.get_json("/api/dcim/interface-redundancy-group-associations/", params=params)
            except requests.RequestException:
                continue
            if not isinstance(payload, dict):
                continue
            for item in payload.get("results", []) or []:
                interface = item.get("interface") or {}
                key = (str(item.get("id") or interface.get("id")), field)
                if key in seen:
                    continue
                seen.add(key)
                assignments.append(item)
        if assignments:
            return assignments
        detail = self._fetch_group_detail(group_id)
        if not detail:
            return []
        inline = detail.get("interface_redundancy_group_associations") or []
        if not inline:
            inline = detail.get("interfaces") or []
        normalized: list[dict] = []
        for entry in inline:
            if not isinstance(entry, dict):
                continue
            interface = entry.get("interface") or entry
            priority = entry.get("priority")
            through = entry.get("through_attributes") or {}
            if priority is None:
                priority = through.get("priority")
            normalized.append({"interface": interface, "priority": priority})
        return normalized

    def _ensure_prefix_id(self, prefix: PrefixRecord) -> str:
        """Resolve the prefix ID or fall back to prefix string."""
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
        """Expand IP record with detailed data if needed."""
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
        """Build an IPAddressRecord from API data."""
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
        """Extract prefix length from an address string."""
        if isinstance(value, str) and "/" in value:
            try:
                return int(value.split("/")[1])
            except (ValueError, IndexError):
                return None
        return None

    @staticmethod
    def _strip_prefix(value: Optional[str]) -> str:
        """Strip prefix length from an address string."""
        if not isinstance(value, str):
            return ""
        return value.split("/")[0]

    def _resolve_assignment_details(self, record: dict) -> tuple[Optional[str], Optional[str]]:
        """Resolve device and interface names from IP record."""
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

        if not device_name or not interface_name:
            api_device, api_interface = self._fetch_assignment_names_via_api(record)
            device_name = device_name or api_device
            interface_name = interface_name or api_interface
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
            device_name = self._lookup_device_by_primary_ip(record)
        return device_name, interface_name

    def _fetch_assignment_names_via_api(self, record: dict) -> tuple[Optional[str], Optional[str]]:
        assigned_type = record.get("assigned_object_type")
        assigned_id = record.get("assigned_object_id")
        if not assigned_type or not assigned_id:
            return None, None
        endpoint = self._endpoint_for_assigned_object(assigned_type)
        if not endpoint:
            return None, None
        try:
            related = self._session.get_json(f"{endpoint}{assigned_id}/", params={"depth": 1})
        except requests.RequestException:
            return None, None
        device_name, interface_name = self._extract_names_from_payload(related)
        if not interface_name:
            interface_name = related.get("name") or related.get("display")
        return device_name, interface_name

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

    @staticmethod
    def _extract_name_from_relationship(related: Any) -> Optional[str]:
        if isinstance(related, dict):
            return related.get("name") or related.get("display")
        if isinstance(related, str):
            return related
        return None

    def _lookup_device_by_primary_ip(self, record: dict) -> Optional[str]:
        ip_id = record.get("id")
        address = record.get("address") or record.get("host")
        stripped_address = self._strip_prefix(address)
        query_values: list[str] = []
        if ip_id:
            query_values.append(str(ip_id))
        if stripped_address:
            query_values.append(stripped_address)
        if not query_values:
            return None
        params = {"primary_ip4": query_values, "limit": 1, "depth": 0}
        try:
            payload = self._session.get_json("/api/dcim/devices/", params=params)
        except requests.RequestException:
            return None
        results = payload.get("results", [])
        if not results:
            return None
        device = results[0]
        return device.get("name") or device.get("display")

    def _extract_names_from_payload(self, payload: dict) -> tuple[Optional[str], Optional[str]]:
        """Extract device and interface names from API payload."""
        interface_name = payload.get("name") or payload.get("display")
        device_name = self._extract_name_from_relationship(payload.get("device"))
        if not device_name:
            device_name = self._extract_name_from_relationship(payload.get("virtual_machine"))
        return device_name, interface_name
