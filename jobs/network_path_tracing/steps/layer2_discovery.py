"""Optional layer-2 discovery helpers for NAPALM-capable devices."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Sequence

from ..config import NetworkPathSettings
from ..interfaces.nautobot import DeviceRecord, NautobotDataSource
from ..interfaces.juniper import is_junos_device, junos_cli_arp_entry, junos_cli_mac_entry

try:
    import napalm  # noqa: F401  # pragma: no cover - imported to satisfy type checkers
except ImportError:  # pragma: no cover - handled by caller
    napalm = None  # type: ignore


@dataclass(frozen=True)
class Layer2Hop:
    """Structured description of an intermediate layer-2 device."""

    device_name: Optional[str]
    ingress_interface: Optional[str]
    egress_interface: Optional[str]
    mac_address: Optional[str]
    port_description: Optional[str] = None
    gateway_interface: Optional[str] = None
    details: Optional[str] = None

    def as_dict(self) -> Dict[str, Optional[str]]:
        """Return a JSON-serialisable payload."""
        return {
            "device_name": self.device_name,
            "ingress_interface": self.ingress_interface,
            "egress_interface": self.egress_interface,
            "mac_address": self.mac_address,
            "port_description": self.port_description,
            "gateway_interface": self.gateway_interface,
            "details": self.details,
        }


class Layer2Discovery:
    """Follow LLDP/MAC breadcrumbs to model intermediate layer-2 hops."""

    def __init__(
        self,
        *,
        napalm_module,
        settings: NetworkPathSettings,
        data_source: NautobotDataSource,
        logger,
        select_driver: Callable[[DeviceRecord], str],
        driver_attempts: Callable[[str], Sequence[str]],
        optional_args_for: Callable[[str], Dict[str, object]],
        collect_lldp_neighbors: Callable[[object, Optional[str]], Dict[str, List[Dict[str, Optional[str]]]]],
        normalize_interface: Callable[[Optional[str]], Optional[str]],
        normalize_hostname: Callable[[Optional[str]], Optional[str]],
    ) -> None:
        self._napalm = napalm_module
        self._settings = settings
        self._data_source = data_source
        self._logger = logger
        self._select_driver = select_driver
        self._driver_attempts = driver_attempts
        self._optional_args_for = optional_args_for
        self._collect_lldp_neighbors = collect_lldp_neighbors
        self._normalize_interface = normalize_interface
        self._normalize_hostname = normalize_hostname

    def discover(
        self,
        *,
        initial_device: DeviceRecord,
        initial_conn,
        initial_driver_name: str,
        initial_lldp_neighbors: Dict[str, List[Dict[str, Optional[str]]]],
        egress_interface: Optional[str],
        next_hop_ip: Optional[str],
    ) -> List[Layer2Hop]:
        """Return up to ``layer2_max_depth`` layer-2 hops bridging to ``next_hop_ip``."""

        if not self._settings.enable_layer2_discovery:
            return []
        napalm_settings = self._settings.napalm_settings()
        if napalm_settings is None:
            return []
        if not self._napalm:
            return []
        if not egress_interface or not next_hop_ip:
            return []

        layer2_hops: List[Layer2Hop] = []
        visited_targets: set[tuple[str, str]] = set()

        current_device = initial_device
        current_conn = initial_conn
        current_driver_name = initial_driver_name
        current_neighbors = initial_lldp_neighbors
        current_interface = egress_interface
        target_mac: Optional[str] = None

        opened_connections: List[object] = []

        try:
            for depth in range(max(0, self._settings.layer2_max_depth)):
                if target_mac is None:
                    current_arp_entry = self._lookup_arp_entry(
                        current_conn,
                        next_hop_ip,
                        current_device,
                        current_interface,
                    )
                    if not current_arp_entry:
                        break
                    target_mac = (
                        (current_arp_entry.get("mac") or current_arp_entry.get("mac_address") or "").lower()
                    )
                    if not target_mac:
                        break
                    mac_entry_on_current = self._lookup_mac_entry(current_conn, target_mac, current_device)
                    if mac_entry_on_current:
                        mac_interface = mac_entry_on_current.get("interface") or mac_entry_on_current.get("port")
                        if mac_interface:
                            if self._logger:
                                self._logger.debug(
                                    "Layer2Discovery remapped %s ARP interface %s to MAC interface %s",
                                    current_device.name if current_device else "unknown",
                                    current_arp_entry.get("interface"),
                                    mac_interface,
                                    extra={"grouping": "layer2-discovery"},
                                )
                            current_interface = mac_interface
                        elif self._logger:
                            self._logger.debug(
                                "Layer2Discovery found MAC entry without interface on %s: %s",
                                current_device.name if current_device else "unknown",
                                mac_entry_on_current,
                                extra={"grouping": "layer2-discovery"},
                            )
                    elif self._logger:
                        self._logger.debug(
                            "Layer2Discovery could not find MAC %s on %s",
                            target_mac,
                            current_device.name if current_device else "unknown",
                            extra={"grouping": "layer2-discovery"},
                        )

                neighbors_map = self._normalize_neighbor_map(current_neighbors)
                candidate_neighbors = self._candidate_neighbors_for_interface(neighbors_map, current_interface)
                neighbor_found = False

                for neighbor_info in candidate_neighbors:
                    neighbor_name = neighbor_info.get("hostname")
                    if not neighbor_name:
                        continue
                    normalized_neighbor = self._normalize_hostname(neighbor_name)
                    if not normalized_neighbor:
                        continue

                    neighbor_device = self._data_source.get_device(neighbor_name)
                    if not neighbor_device or not neighbor_device.primary_ip:
                        if self._logger:
                            self._logger.debug(
                                "Skipping neighbor %s due to missing device record or primary IP",
                                neighbor_name,
                                extra={"grouping": "layer2-discovery"},
                            )
                        continue

                    owner_record = self._data_source.get_ip_address(next_hop_ip)
                    if owner_record and self._normalize_hostname(owner_record.device_name) == normalized_neighbor:
                        if self._logger:
                            self._logger.debug(
                                "%s already owns %s; stopping at layer-3 boundary",
                                neighbor_name,
                                next_hop_ip,
                                extra={"grouping": "layer2-discovery"},
                            )
                        continue

                    neighbor_driver = self._select_driver(neighbor_device)
                    neighbor_conn = self._open_napalm_connection(
                        device=neighbor_device,
                        driver_name=neighbor_driver,
                        napalm_settings=napalm_settings,
                    )
                    if neighbor_conn is None:
                        if self._logger:
                            self._logger.debug(
                                "Failed to open NAPALM connection to %s; trying next neighbor",
                                neighbor_name,
                                extra={"grouping": "layer2-discovery"},
                            )
                        continue
                    opened_connections.append(neighbor_conn)

                    try:
                        neighbor_mac_entry = self._lookup_mac_entry(neighbor_conn, target_mac, neighbor_device)
                        neighbor_neighbors_raw = self._collect_lldp_neighbors(neighbor_conn, neighbor_device.name)
                    except Exception as exc:  # pragma: no cover - defensive logging
                        if self._logger:
                            self._logger.debug(
                            f"Layer 2 discovery failed on '{neighbor_device.name}': {exc}",
                            extra={"grouping": "layer2-discovery"},
                        )
                        continue

                    if not neighbor_mac_entry:
                        if self._logger:
                            self._logger.debug(
                                "%s does not have MAC %s in its table; skipping",
                                neighbor_device.name,
                                target_mac,
                                extra={"grouping": "layer2-discovery"},
                            )
                        continue

                    egress_on_neighbor = neighbor_mac_entry.get("interface") or neighbor_mac_entry.get("port")
                    if not egress_on_neighbor:
                        if self._logger:
                            self._logger.debug(
                                "MAC entry on %s lacks interface/port info; skipping",
                                neighbor_device.name,
                                extra={"grouping": "layer2-discovery"},
                            )
                        continue

                    normalized_egress = self._normalize_interface(egress_on_neighbor) or (egress_on_neighbor or "")
                    visit_key = (normalized_neighbor, normalized_egress)
                    if visit_key in visited_targets:
                        if self._logger:
                            self._logger.debug(
                                "Already visited neighbor %s via %s; skipping",
                                neighbor_device.name,
                                egress_on_neighbor,
                                extra={"grouping": "layer2-discovery"},
                            )
                        continue

                    mac_text = target_mac or "unknown"
                    details = f"Layer 2 hop resolved via LLDP/MAC on '{neighbor_device.name}' (MAC {mac_text})."
                    ingress_on_neighbor = neighbor_info.get("port") or neighbor_info.get("port_description")
                    layer2_hops.append(
                        Layer2Hop(
                            device_name=neighbor_device.name,
                            ingress_interface=ingress_on_neighbor,
                            egress_interface=egress_on_neighbor,
                            mac_address=target_mac,
                            port_description=neighbor_info.get("port_description"),
                            gateway_interface=current_interface,
                            details=details,
                        )
                    )

                    owner_record = self._data_source.get_ip_address(next_hop_ip)
                    if owner_record and self._normalize_hostname(owner_record.device_name) == normalized_neighbor:
                        neighbor_found = True
                        break

                    visited_targets.add(visit_key)
                    current_device = neighbor_device
                    current_conn = neighbor_conn
                    current_driver_name = neighbor_driver
                    current_neighbors = neighbor_neighbors_raw
                    current_interface = egress_on_neighbor
                    neighbor_found = True
                    break

                if not neighbor_found:
                    break
        finally:
            for conn in opened_connections:
                try:
                    conn.close()
                except Exception:  # pragma: no cover - connection cleanup best effort
                    pass

        return layer2_hops

    def _normalize_neighbor_map(
        self,
        neighbors: Optional[Dict[str, List[Dict[str, Optional[str]]]]],
    ) -> Dict[str, List[Dict[str, Optional[str]]]]:
        """Return LLDP neighbors indexed by normalized interface name."""

        normalized: Dict[str, List[Dict[str, Optional[str]]]] = {}
        if not neighbors:
            return normalized
        for local_if, entries in neighbors.items():
            key = self._normalize_interface(local_if)
            if not key:
                continue
            normalized[key] = list(entries or [])
        return normalized

    def _select_neighbor_for_interface(
        self,
        neighbors: Dict[str, List[Dict[str, Optional[str]]]],
        interface: Optional[str],
    ) -> Optional[Dict[str, Optional[str]]]:
        """Return the first LLDP neighbor associated with ``interface``."""

        if not interface:
            return None
        normalized = self._normalize_interface(interface)
        if not normalized:
            return None
        candidates = neighbors.get(normalized, [])
        return candidates[0] if candidates else None

    def _candidate_neighbors_for_interface(
        self,
        neighbors: Dict[str, List[Dict[str, Optional[str]]]],
        interface: Optional[str],
    ) -> List[Dict[str, Optional[str]]]:
        """Return prioritized LLDP neighbor entries for ``interface``."""

        ordered: List[Dict[str, Optional[str]]] = []
        seen: set[int] = set()
        normalized_target = self._normalize_interface(interface)
        normalized_target_base: Optional[str] = None
        if normalized_target and "." in normalized_target:
            candidate = normalized_target.split(".", 1)[0]
            if candidate and candidate != normalized_target:
                normalized_target_base = candidate

        def _push(entry: Dict[str, Optional[str]], priority: int) -> None:
            key = id(entry)
            if key in seen:
                return
            seen.add(key)
            entry.setdefault("_priority", priority)
            ordered.append(entry)

        for target in (normalized_target, normalized_target_base):
            if target and target in neighbors:
                for entry in neighbors.get(target, []):
                    _push(entry, 0)

        for local_if, entries in neighbors.items():
            normalized_local = self._normalize_interface(local_if)
            for entry in entries:
                if normalized_target and normalized_target.startswith("po") and normalized_local and normalized_local.startswith(("gi", "eth", "et", "te", "fa")):
                    _push(entry, 1)
                else:
                    _push(entry, 2)

        ordered.sort(key=lambda e: (e.get("_priority", 99), str(e.get("local_interface") or "")))
        for entry in ordered:
            entry.pop("_priority", None)
        return ordered

    def _lookup_arp_entry(
        self,
        device_conn,
        ip_address: str,
        device: Optional[DeviceRecord],
        interface: Optional[str] = None,
    ) -> Optional[Dict[str, str]]:
        """Return ARP entry for ``ip_address`` if present."""

        if not device_conn:
            return None

        vrf_hint = self._interface_vrf(device, interface)
        if vrf_hint and self._logger:
            self._logger.debug(
                "Attempting ARP lookup for %s in VRF '%s' on %s",
                ip_address,
                vrf_hint,
                device.name if device else "unknown",
                extra={"grouping": "layer2-discovery"},
            )

        entry = self._lookup_arp_table(device_conn, ip_address, device, vrf_hint)
        if entry:
            return entry

        if vrf_hint:
            entry = self._lookup_cisco_cli_arp(device_conn, ip_address, vrf_hint)
            if entry:
                return entry

        return None

    def _lookup_arp_table(
        self,
        device_conn,
        ip_address: str,
        device: Optional[DeviceRecord],
        vrf_hint: Optional[str],
    ) -> Optional[Dict[str, str]]:
        """Search ARP table (optionally scoped to VRF) for ``ip_address``."""

        vrf_candidates: List[Optional[str]] = []
        normalized_vrf = self._normalize_vrf(vrf_hint)
        if normalized_vrf:
            vrf_candidates.append(normalized_vrf)
        vrf_candidates.append(None)

        for vrf in vrf_candidates:
            try:
                if vrf:
                    arp_table = device_conn.get_arp_table(vrf=vrf)
                else:
                    arp_table = device_conn.get_arp_table()
            except TypeError:
                if vrf:
                    continue
                if device and is_junos_device(device):
                    return junos_cli_arp_entry(device_conn, ip_address, logger=self._logger)
                continue
            except NotImplementedError:
                if vrf:
                    continue
                if device and is_junos_device(device):
                    return junos_cli_arp_entry(device_conn, ip_address, logger=self._logger)
                return None
            except Exception as exc:  # pragma: no cover - defensive logging
                if self._logger:
                    self._logger.debug(
                        f"ARP lookup failed on device connection: {exc}",
                        extra={"grouping": "layer2-discovery"},
                    )
                continue

            entry = self._find_in_arp_table(arp_table, ip_address)
            if entry:
                return entry

        return None

    def _lookup_cisco_cli_arp(self, device_conn, ip_address: str, vrf: Optional[str]) -> Optional[Dict[str, str]]:
        """Attempt VRF-scoped ARP lookup using Cisco-style CLI JSON."""

        vrf_value = self._normalize_vrf(vrf)
        if not vrf_value or not hasattr(device_conn, "cli"):
            return None

        command = f"show ip arp vrf {vrf_value} {ip_address} | json"
        try:
            response = device_conn.cli([command])
        except Exception as exc:  # pragma: no cover - defensive logging
            if self._logger:
                self._logger.debug(
                    f"VRF-specific ARP CLI failed for '{command}': {exc}",
                    extra={"grouping": "layer2-discovery"},
                )
            return None

        payload = response.get(command) if isinstance(response, dict) else None
        if payload is None:
            return None

        try:
            data = json.loads(payload) if isinstance(payload, str) else payload
        except Exception as exc:  # pragma: no cover - defensive logging
            if self._logger:
                self._logger.debug(
                    f"VRF-specific ARP CLI JSON decode failed for '{command}': {exc}",
                    extra={"grouping": "layer2-discovery"},
                )
            return None

        return self._parse_cisco_arp_payload(data, ip_address)

    @staticmethod
    def _find_in_arp_table(arp_table, ip_address: str) -> Optional[Dict[str, str]]:
        """Return ARP entry from ``arp_table`` if present."""

        if not isinstance(arp_table, Iterable):
            return None
        for entry in arp_table:
            if not isinstance(entry, dict):
                continue
            ip_value = entry.get("ip") or entry.get("ip_address") or entry.get("address")
            if ip_value == ip_address:
                return entry
        return None

    def _interface_vrf(self, device: Optional[DeviceRecord], interface: Optional[str]) -> Optional[str]:
        """Return VRF name for ``device``/``interface`` via Nautobot data."""

        if not device or not interface:
            return None

        interface_candidates = [interface]
        if self._normalize_interface:
            normalized = self._normalize_interface(interface)
            if normalized and normalized not in interface_candidates:
                interface_candidates.append(normalized)

        for candidate in interface_candidates:
            try:
                record = self._data_source.get_interface_ip(device.name, candidate)
            except Exception:
                continue
            if record and record.vrf:
                return record.vrf
        return None

    def _parse_cisco_arp_payload(self, payload: object, ip_address: str) -> Optional[Dict[str, str]]:
        """Parse Cisco-style JSON ARP payloads and return the entry for ``ip_address``."""

        if not isinstance(payload, dict):
            return None

        vrf_table = payload.get("TABLE_vrf") or {}
        vrf_nodes = self._as_list(vrf_table.get("ROW_vrf"))
        if not vrf_nodes:
            vrf_nodes = [payload]

        for vrf_node in vrf_nodes:
            if not isinstance(vrf_node, dict):
                continue
            adj_table = vrf_node.get("TABLE_adj") or vrf_node.get("TABLE_arp") or {}
            for entry in self._as_list(adj_table.get("ROW_adj") or adj_table.get("ROW_arp")):
                if not isinstance(entry, dict):
                    continue
                ip_value = entry.get("ip-addr-out") or entry.get("ip") or entry.get("address")
                if ip_value != ip_address:
                    continue
                return {
                    "ip": ip_value,
                    "mac": entry.get("mac") or entry.get("hwaddr") or entry.get("mac-addr") or entry.get("mac_address"),
                    "interface": entry.get("intf-out") or entry.get("interface") or entry.get("outgoing-interface"),
                }

        return None

    @staticmethod
    def _normalize_vrf(vrf: Optional[str]) -> Optional[str]:
        """Normalize VRF names to meaningful values."""

        if vrf is None:
            return None
        vrf_value = str(vrf).strip()
        if not vrf_value or vrf_value.lower() in {"default", "global"}:
            return None
        return vrf_value

    @staticmethod
    def _as_list(value) -> List:
        """Normalize a value into a list."""

        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    def _lookup_mac_entry(
        self,
        device_conn,
        mac_address: str,
        device: Optional[DeviceRecord],
    ) -> Optional[Dict[str, str]]:
        """Return MAC table entry for ``mac_address`` if present."""

        if not device_conn:
            return None
        try:
            mac_table = device_conn.get_mac_address_table()
        except NotImplementedError:
            if device and is_junos_device(device):
                return junos_cli_mac_entry(device_conn, mac_address, logger=self._logger)
            return None
        except Exception as exc:  # pragma: no cover - defensive logging
            if self._logger:
                self._logger.debug(
                    f"MAC lookup failed on device connection: {exc}",
                    extra={"grouping": "layer2-discovery"},
                )
            return None

        if not isinstance(mac_table, Iterable):
            return None
        target = mac_address.lower()
        for entry in mac_table:
            if not isinstance(entry, dict):
                continue
            mac_value = (entry.get("mac") or entry.get("mac_address") or "").lower()
            if mac_value == target:
                return entry
        return None

    def _open_napalm_connection(
        self,
        *,
        device: DeviceRecord,
        driver_name: str,
        napalm_settings,
    ):
        """Return an opened NAPALM connection for ``device`` or None."""

        for candidate in self._driver_attempts(driver_name):
            try:
                driver = self._napalm.get_network_driver(candidate)
            except Exception:  # pragma: no cover - fallback handling
                continue
            optional_args = self._optional_args_for(candidate)
            try:
                connection = driver(
                    hostname=device.primary_ip,
                    username=napalm_settings.username,
                    password=napalm_settings.password,
                    optional_args=optional_args,
                )
                connection.open()
                if self._logger:
                    self._logger.debug(
                        f"Opened layer-2 discovery session to {device.name} using driver '{candidate}'",
                        extra={"grouping": "layer2-discovery"},
                    )
                return connection
            except Exception as exc:
                if self._logger:
                    self._logger.warning(
                        f"Failed to open layer-2 discovery session to {device.name} with driver '{candidate}': {exc}",
                        extra={"grouping": "layer2-discovery"},
                    )
                continue
        return None
