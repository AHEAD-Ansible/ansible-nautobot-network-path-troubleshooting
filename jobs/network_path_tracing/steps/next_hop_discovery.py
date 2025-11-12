"""Step 3: Next-hop discovery on the current device."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

import requests

from ..config import NetworkPathSettings
from ..exceptions import NextHopDiscoveryError
from ..interfaces.nautobot import DeviceRecord, NautobotDataSource
from ..interfaces.palo_alto import PaloAltoClient, _parse_vlan_members
from ..interfaces.f5_bigip import F5Client, F5APIError
from .gateway_discovery import GatewayDiscoveryResult
from .input_validation import InputValidationResult
from .layer2_discovery import Layer2Discovery

try:
    import napalm
except ImportError:
    napalm = None


@dataclass(frozen=True)
class NextHopDiscoveryResult:
    """Outcome of the next-hop discovery workflow."""
    found: bool
    next_hops: List[dict]
    details: Optional[str] = None


class NextHopDiscoveryStep:
    """Discover the next-hop(s) from the current device to the destination.

    Handles Palo Alto devices via their API and other platforms via NAPALM.
    Ensures robust platform detection to avoid incorrect driver usage.
    """

    _NXOS_DRIVERS = {"nxos", "nxos_ssh"}
    _PALO_ALTO_INDICATORS = {"palo", "panos", "palo_alto"}
    _F5_INDICATORS = {"f5", "bigip"}

    def __init__(
        self,
        data_source: NautobotDataSource,
        settings: NetworkPathSettings,
        logger: Optional[logging.Logger] = None,
    ):
        self._data_source = data_source
        self._settings = settings
        self._logger = logger
        self._cache: Dict[Tuple[str, str], NextHopDiscoveryResult | str] = {}
        self._lldp_cache: Dict[str, Dict[str, List[Dict[str, Optional[str]]]]] = {}
        self._ip_device_cache: Dict[str, Optional[str]] = {}
        self._palo_lldp_cache: Dict[str, Dict[str, List[Dict[str, Optional[str]]]]] = {}
        self._palo_arp_cache: Dict[str, Dict[str, Dict[str, Optional[str]]]] = {}
        self._palo_mac_cache: Dict[str, Dict[str, Dict[str, Optional[str]]]] = {}
        self._palo_vlan_member_cache: Dict[str, List[str]] = {}
        self._layer2_helper: Optional[Layer2Discovery] = None

    def run(self, validation: InputValidationResult, gateway: GatewayDiscoveryResult) -> NextHopDiscoveryResult:
        """Execute next-hop discovery for the destination IP.

        Args:
            validation: Input validation result containing source/destination IPs.
            gateway: Gateway discovery result with device and interface details.

        Returns:
            NextHopDiscoveryResult: Result containing next-hop details or errors.

        Raises:
            NextHopDiscoveryError: If device, IP, or interface is missing, or lookup fails.
        """
        if not gateway.found or not gateway.gateway or not gateway.gateway.device_name:
            raise NextHopDiscoveryError("No gateway device available for next-hop lookup")

        device = self._data_source.get_device(gateway.gateway.device_name)
        if not device:
            raise NextHopDiscoveryError(f"Device '{gateway.gateway.device_name}' not found in Nautobot")
        if not device.primary_ip:
            raise NextHopDiscoveryError(f"No primary/management IP found for device '{device.name}'")
        ingress_if = gateway.gateway.interface_name
        if not ingress_if:
            raise NextHopDiscoveryError("No ingress interface known for gateway")

        cache_key = (device.name, validation.destination_ip)
        cached = self._cache.get(cache_key)
        if cached is not None:
            if isinstance(cached, NextHopDiscoveryResult):
                return cached
            raise NextHopDiscoveryError(cached)

        # Check if device is Palo Alto based on platform_slug or platform_name
        platform_slug_lower = (device.platform_slug or "").lower()
        platform_name_lower = (device.platform_name or "").lower()
        is_palo_alto = self._is_palo_alto_device(device)
        is_f5 = any(
            indicator in platform_slug_lower or indicator in platform_name_lower
            for indicator in self._F5_INDICATORS
        )

        if is_palo_alto:
            if self._logger:
                self._logger.info(
                    f"Detected Palo Alto device '{device.name}' (platform: {device.platform_slug or device.platform_name})",
                    extra={"grouping": "next-hop-discovery"},
                )
            try:
                result = self._run_palo_alto_lookup(device, ingress_if, validation.destination_ip)
                self._cache[cache_key] = result
                return result
            except NextHopDiscoveryError as exc:
                self._cache[cache_key] = str(exc)
                raise
        elif is_f5:
            if self._logger:
                self._logger.info(
                    f"Detected F5 BIG-IP device '{device.name}' (platform: {device.platform_slug or device.platform_name})",
                    extra={"grouping": "next-hop-discovery"},
                )
            try:
                result = self._run_f5_lookup(device, ingress_if, validation.destination_ip)
                self._cache[cache_key] = result
                return result
            except NextHopDiscoveryError as exc:
                self._cache[cache_key] = str(exc)
                raise
        else:
            if self._logger:
                self._logger.info(
                    f"Using NAPALM for device '{device.name}' (platform: {device.platform_slug or device.platform_name})",
                    extra={"grouping": "next-hop-discovery"},
                )
            try:
                result = self._run_napalm_lookup(device, ingress_if, validation.destination_ip)
                self._cache[cache_key] = result
                return result
            except NextHopDiscoveryError as exc:
                self._cache[cache_key] = str(exc)
                raise

    def _run_palo_alto_lookup(self, device: DeviceRecord, ingress_if: str, destination_ip: str) -> NextHopDiscoveryResult:
        """Perform next-hop lookup for Palo Alto devices using their API.

        Args:
            device: Device record from Nautobot.
            ingress_if: Ingress interface name (e.g., 'ethernet1/12').
            destination_ip: Destination IP to look up.

        Returns:
            NextHopDiscoveryResult: Result with next-hop and egress interface.

        Raises:
            NextHopDiscoveryError: If credentials, virtual router, or lookup fails.
        """
        pa_settings = self._settings.pa_settings()
        if not pa_settings:
            raise NextHopDiscoveryError("Palo Alto credentials not configured (set PA_USERNAME and PA_PASSWORD)")

        client = PaloAltoClient(
            host=device.primary_ip,
            verify_ssl=pa_settings.verify_ssl,
            timeout=10,
            logger=self._logger,
        )

        try:
            api_key = client.keygen(pa_settings.username, pa_settings.password)
        except RuntimeError as exc:
            raise NextHopDiscoveryError(f"Authentication failed for '{device.primary_ip}': {exc}") from exc

        vr = client.get_virtual_router_for_interface(api_key, ingress_if)
        if not vr:
            raise NextHopDiscoveryError(f"No virtual-router found for interface '{ingress_if}' on '{device.name}'")

        try:
            # Try FIB lookup first, but merge in route-lookup data if the FIB misses anything.
            fib_result = client.fib_lookup(api_key, vr, destination_ip)
            merged = dict(fib_result)
            fallback_used = False

            if not merged.get("next_hop") or not merged.get("egress_interface"):
                try:
                    route_result = client.route_lookup(api_key, vr, destination_ip)
                except RuntimeError as route_exc:
                    if self._logger:
                        self._logger.warning(
                            f"Route-lookup fallback failed on '{device.name}' (VR '{vr}'): {route_exc}",
                            extra={"grouping": "next-hop-discovery"},
                        )
                    route_result = {}
                else:
                    if not merged.get("next_hop") and route_result.get("next_hop"):
                        merged["next_hop"] = route_result["next_hop"]
                        fallback_used = True
                    if not merged.get("egress_interface") and route_result.get("egress_interface"):
                        merged["egress_interface"] = route_result["egress_interface"]
                        fallback_used = True

            found = bool(merged.get("next_hop") or merged.get("egress_interface"))
            detail = f"Resolved using virtual-router '{vr}' on '{device.name}'"
            if fallback_used:
                detail += " (route-lookup fallback)"

            hop_payload: Dict[str, object] = {
                "next_hop_ip": merged.get("next_hop"),
                "egress_interface": merged.get("egress_interface"),
            }

            hop_type = self._classify_palo_alto_hop(
                client=client,
                api_key=api_key,
                device=device,
                egress_interface=merged.get("egress_interface"),
                next_hop_ip=merged.get("next_hop"),
            )
            if hop_type:
                hop_payload["hop_type"] = hop_type
            if self._settings.enable_layer2_discovery:
                layer2_path = self._discover_palo_layer2_path(
                    client=client,
                    api_key=api_key,
                    device=device,
                    egress_interface=merged.get("egress_interface"),
                    target_ip=merged.get("next_hop") or destination_ip,
                )
                if layer2_path:
                    hop_payload["layer2_hops"] = layer2_path

            return NextHopDiscoveryResult(
                found=found,
                next_hops=[hop_payload],
                details=detail,
            )
        except RuntimeError as exc:
            raise NextHopDiscoveryError(f"Next-hop lookup failed for '{destination_ip}': {exc}") from exc

    def _run_f5_lookup(self, device: DeviceRecord, ingress_if: str, destination_ip: str) -> NextHopDiscoveryResult:
        """Perform next-hop lookup for F5 BIG-IP devices."""
        if not device.primary_ip:
            raise NextHopDiscoveryError(f"No management IP found for F5 device '{device.name}'")

        f5_settings = self._settings.f5_settings()
        if not f5_settings:
            raise NextHopDiscoveryError("F5 credentials not configured (set F5_USERNAME and F5_PASSWORD)")

        client = F5Client(
            host=device.primary_ip,
            username=f5_settings.username,
            password=f5_settings.password,
            verify_ssl=f5_settings.verify_ssl,
        )

        try:
            summary = client.collect_destination_summary(
                destination_ip,
                partitions=f5_settings.partitions_list(),
                ingress_hint=ingress_if,
            )
        except (requests.RequestException, F5APIError) as exc:
            raise NextHopDiscoveryError(f"F5 API lookup failed for '{device.name}': {exc}") from exc

        extras = summary.as_dict()
        hop_next_ip = summary.next_hop_ip or destination_ip
        egress_interface = summary.egress_interface

        return NextHopDiscoveryResult(
            found=True,
            next_hops=[
                {
                    "next_hop_ip": hop_next_ip,
                    "egress_interface": egress_interface,
                    **extras,
                }
            ],
            details=f"Resolved via F5 API on '{device.name}'",
        )

    def _run_napalm_lookup(self, device: DeviceRecord, ingress_if: str, destination_ip: str) -> NextHopDiscoveryResult:
        """Perform next-hop lookup using NAPALM for non-Palo Alto devices.

        Args:
            device: Device record from Nautobot.
            ingress_if: Ingress interface name.
            destination_ip: Destination IP to look up.

        Returns:
            NextHopDiscoveryResult: Result with next-hop and egress interface.

        Raises:
            NextHopDiscoveryError: If NAPALM is unavailable, credentials are missing, or lookup fails.
        """
        if napalm is None:
            raise NextHopDiscoveryError("NAPALM is not installed; cannot perform lookup for non-Palo Alto device")

        napalm_settings = self._settings.napalm_settings()
        if not napalm_settings:
            raise NextHopDiscoveryError("NAPALM credentials not configured (set NAPALM_USERNAME and NAPALM_PASSWORD)")

        driver_name = self._select_napalm_driver(device)
        last_error: Optional[Exception] = None

        for candidate in self._driver_attempts(driver_name):
            try:
                driver = napalm.get_network_driver(candidate)
                if self._logger:
                    self._logger.info(
                        f"Connecting to {device.name} with NAPALM driver '{candidate}'",
                        extra={"grouping": "next-hop-discovery"},
                    )

                optional_args = self._optional_args_for(candidate)
                with driver(
                    hostname=device.primary_ip,
                    username=napalm_settings.username,
                    password=napalm_settings.password,
                    optional_args=optional_args,
                ) as device_conn:
                    lldp_neighbors = self._collect_lldp_neighbors(device_conn, device.name)
                    layer2_helper = self._build_layer2_helper()
                    if candidate in self._NXOS_DRIVERS:
                        next_hops = self._collect_nxos_routes(device_conn, destination_ip, ingress_if)
                        details = f"Resolved via NX-OS CLI on '{device.name}'"
                    else:
                        next_hops = self._collect_generic_routes(device_conn, destination_ip)
                        details = f"Resolved via NAPALM on '{device.name}'"

                    self._annotate_hops_with_lldp(
                        next_hops=next_hops,
                        lldp_neighbors=lldp_neighbors,
                    )

                    if not next_hops:
                        return NextHopDiscoveryResult(
                            found=False,
                            next_hops=[],
                            details=f"No route found for '{destination_ip}' on '{device.name}'",
                        )

                    if layer2_helper and lldp_neighbors:
                        for hop_payload in next_hops:
                            hop_next_ip = hop_payload.get("next_hop_ip")
                            hop_egress = hop_payload.get("egress_interface")
                            target_ip = hop_next_ip or destination_ip
                            layer2_path = layer2_helper.discover(
                                initial_device=device,
                                initial_conn=device_conn,
                                initial_driver_name=candidate,
                                initial_lldp_neighbors=lldp_neighbors,
                                egress_interface=hop_egress,
                                next_hop_ip=target_ip,
                            )
                            if layer2_path:
                                hop_payload["layer2_hops"] = [hop.as_dict() for hop in layer2_path]

                    return NextHopDiscoveryResult(
                        found=True,
                        next_hops=next_hops,
                        details=details,
                    )
            except Exception as exc:
                last_error = exc
                if self._logger:
                    self._logger.warning(
                        f"NAPALM driver '{candidate}' failed for {device.name}: {exc}",
                        extra={"grouping": "next-hop-discovery"},
                    )
                continue

        raise NextHopDiscoveryError(f"NAPALM lookup failed for '{device.name}': {last_error}")

    def _driver_attempts(self, initial: str) -> List[str]:
        """Order the NAPALM driver names to try, with fallbacks.

        Args:
            initial: Initial driver name to try.

        Returns:
            List of driver names to attempt.
        """
        attempts = [initial]
        if initial == "nxos":
            attempts.append("nxos_ssh")
        elif initial == "nxos_ssh":
            attempts.append("nxos")
        return attempts

    @staticmethod
    def _optional_args_for(driver_name: str) -> dict:
        """Return driver-specific optional arguments for NAPALM.

        Args:
            driver_name: Name of the NAPALM driver.

        Returns:
            Dictionary of optional arguments.
        """
        if driver_name == "nxos":
            return {"port": 443, "verify": False}
        if driver_name == "nxos_ssh":
            return {"port": 22}
        if driver_name in {"ios", "eos", "junos", "arista_eos", "cisco_ios"}:
            return {"port": 22}
        return {}

    def _select_napalm_driver(self, device: DeviceRecord) -> str:
        """Determine the appropriate NAPALM driver name for a device.

        Args:
            device: Device record from Nautobot.

        Returns:
            NAPALM driver name (defaults to 'ios' if unknown).
        """
        driver_map = {
            "ios": "ios",
            "cisco_ios": "ios",
            "nxos": "nxos",
            "nxos_ssh": "nxos_ssh",
            "cisco_nxos": "nxos",
            "eos": "eos",
            "arista_eos": "eos",
            "junos": "junos",
        }

        if device.napalm_driver:
            normalized = device.napalm_driver.lower()
            return driver_map.get(normalized, device.napalm_driver)

        for candidate in (device.platform_slug, device.platform_name):
            if isinstance(candidate, str):
                normalized = candidate.lower()
                if normalized in driver_map:
                    return driver_map[normalized]

        return "ios"

    @staticmethod
    def _collect_generic_routes(device_conn, destination_ip: str) -> List[dict]:
        """Collect next-hop information using NAPALM's get_route_to().

        Args:
            device_conn: NAPALM device connection.
            destination_ip: Destination IP to look up.

        Returns:
            List of dictionaries with next-hop and egress interface details.
        """
        try:
            route_table = device_conn.get_route_to(destination=destination_ip)
        except Exception as exc:
            raise NextHopDiscoveryError(f"get_route_to failed: {exc}") from exc

        next_hops: List[dict] = []
        for routes in route_table.values():
            entries: List[dict] = []
            if isinstance(routes, list):
                entries = [entry for entry in routes if isinstance(entry, dict)]
            elif isinstance(routes, dict):
                entries = [routes]
            if not entries:
                continue
            for route_info in entries:
                next_hop_ip = route_info.get("next_hop") or route_info.get("nh")
                egress_if = (
                    route_info.get("outgoing_interface")
                    or route_info.get("interface")
                    or route_info.get("gateway")
                )
                if next_hop_ip or egress_if:
                    next_hops.append(
                        {
                            "next_hop_ip": next_hop_ip,
                            "egress_interface": egress_if,
                        }
                    )
        return next_hops

    def _collect_nxos_routes(self, device_conn, destination_ip: str, ingress_if: str) -> List[dict]:
        """Collect next-hop information for NX-OS platforms via CLI JSON.

        Args:
            device_conn: NAPALM device connection.
            destination_ip: Destination IP to look up.
            ingress_if: Ingress interface name.

        Returns:
            List of dictionaries with next-hop and egress interface details.
        """
        vrf_candidates: List[Optional[str]] = []
        interface_vrf = self._detect_nxos_interface_vrf(device_conn, ingress_if)
        if interface_vrf:
            vrf_candidates.append(interface_vrf)

        vrf_candidates.append(None)

        all_vrfs = self._fetch_nxos_vrfs(device_conn)
        for vrf in all_vrfs:
            if vrf not in vrf_candidates:
                vrf_candidates.append(vrf)

        for vrf in vrf_candidates:
            command = (
                f"show ip route {destination_ip} | json"
                if vrf in (None, "default")
                else f"show ip route vrf {vrf} {destination_ip} | json"
            )
            data = self._run_nxos_cli(device_conn, command)
            if data is None:
                continue
            hops = self._parse_nxos_route_payload(data)
            if hops:
                return hops

        return self._collect_generic_routes(device_conn, destination_ip)

    def _run_nxos_cli(self, device_conn, command: str) -> Optional[dict]:
        """Run an NX-OS CLI command and return parsed JSON data.

        Args:
            device_conn: NAPALM device connection.
            command: CLI command to execute.

        Returns:
            Parsed JSON data or None if the command fails.
        """
        try:
            response = device_conn.cli([command])
        except Exception as exc:
            if self._logger:
                self._logger.info(
                    f"NX-OS CLI lookup failed for '{command}': {exc}",
                    extra={"grouping": "next-hop-discovery"},
                )
            return None

        raw_payload = response.get(command)
        if raw_payload is None:
            if self._logger:
                self._logger.info(
                    f"NX-OS CLI returned no payload for '{command}'",
                    extra={"grouping": "next-hop-discovery"},
                )
            return None

        try:
            if isinstance(raw_payload, str):
                return json.loads(raw_payload)
            if isinstance(raw_payload, dict):
                return raw_payload
            raise ValueError(f"Unsupported NX-OS CLI payload type: {type(raw_payload)}")
        except (json.JSONDecodeError, ValueError) as exc:
            if self._logger:
                self._logger.info(
                    f"NX-OS JSON parsing failed for '{command}': {exc}",
                    extra={"grouping": "next-hop-discovery"},
                )
            return None

    def _parse_nxos_route_payload(self, data: dict) -> List[dict]:
        """Translate NX-OS JSON route payload into generic next-hop entries.

        Args:
            data: Parsed JSON data from NX-OS CLI.

        Returns:
            List of dictionaries with next-hop and egress interface details.
        """
        def as_list(value):
            if isinstance(value, list):
                return value
            if value is None:
                return []
            return [value]

        results = []
        vrf_table = data.get("TABLE_vrf", {})
        for vrf_node in as_list(vrf_table.get("ROW_vrf")):
            addr_tables = []
            if "TABLE_addr" in vrf_node:
                addr_tables.append(("TABLE_addr", "ROW_addr"))
            if "TABLE_addrf" in vrf_node:
                addr_tables.append(("TABLE_addrf", "ROW_addrf"))
            if not addr_tables:
                addr_tables.append((None, None))

            for table_key, row_key in addr_tables:
                table_obj = vrf_node.get(table_key) if table_key else vrf_node
                if not isinstance(table_obj, dict):
                    continue
                addr_rows = as_list(table_obj.get(row_key)) if row_key else [table_obj]
                for addr in addr_rows:
                    prefixes = []
                    if isinstance(addr, dict) and "TABLE_prefix" in addr:
                        prefixes = as_list(addr.get("TABLE_prefix", {}).get("ROW_prefix"))
                    elif isinstance(addr, dict):
                        prefixes = [addr]
                    else:
                        continue

                    for prefix in prefixes:
                        if not isinstance(prefix, dict):
                            continue
                        path_table = prefix.get("TABLE_path", {}) if isinstance(prefix.get("TABLE_path"), dict) else {}
                        for path in as_list(path_table.get("ROW_path")):
                            if not isinstance(path, dict):
                                continue
                            next_hop = (
                                path.get("nexthop")
                                or path.get("nhaddr")
                                or path.get("ipnexthop")
                            )
                            interface = (
                                path.get("ifname")
                                or path.get("ifname_out")
                                or path.get("interface")
                            )
                            best_flag = str(path.get("ubest", "")).lower()
                            is_best = best_flag in {"true", "1", "yes"}
                            results.append(
                                {
                                    "next_hop": next_hop,
                                    "interface": interface,
                                    "is_best": is_best,
                                }
                            )

        if not results:
            return []

        best_results = [entry for entry in results if entry["is_best"]]
        chosen = best_results or results

        next_hops = []
        for entry in chosen:
            if entry["next_hop"] or entry["interface"]:
                next_hops.append(
                    {
                        "next_hop_ip": entry["next_hop"],
                        "egress_interface": entry["interface"],
                    }
                )
        return next_hops

    def _fetch_nxos_vrfs(self, device_conn) -> List[str]:
        """Return a list of VRF names configured on the NX-OS device.

        Args:
            device_conn: NAPALM device connection.

        Returns:
            List of VRF names, excluding 'management'.
        """
        command = "show vrf | json"
        data = self._run_nxos_cli(device_conn, command)
        if not data:
            return []

        vrfs = []
        def as_list(value):
            if isinstance(value, list):
                return value
            if value:
                return [value]
            return []

        table = data.get("TABLE_vrf", {})
        for vrf in as_list(table.get("ROW_vrf")):
            name = vrf.get("vrf_name")
            if isinstance(name, str) and name.lower() != "management":
                vrfs.append(name)
        return vrfs

    def _detect_nxos_interface_vrf(self, device_conn, interface: str) -> Optional[str]:
        """Return the VRF name associated with an interface, if any.

        Args:
            device_conn: NAPALM device connection.
            interface: Interface name to check.

        Returns:
            VRF name or None if not found or interface is empty.
        """
        if not interface:
            return None

        command = f"show ip interface {interface} | json"
        data = self._run_nxos_cli(device_conn, command)
        if not data:
            return None

        table = data.get("TABLE_intf", {})
        def as_list(value):
            if isinstance(value, list):
                return value
            if value:
                return [value]
            return []

        for entry in as_list(table.get("ROW_intf")):
            vrf = entry.get("vrf") or entry.get("vrf_name") or entry.get("vrf_id")
            if isinstance(vrf, str) and vrf.lower() != "default":
                return vrf
        return None

    def _collect_lldp_neighbors(
        self,
        device_conn,
        device_name: Optional[str],
    ) -> Dict[str, List[Dict[str, Optional[str]]]]:
        """Return LLDP neighbors keyed by local interface."""

        cache_key = device_name or getattr(device_conn, "hostname", None)
        if cache_key and cache_key in self._lldp_cache:
            return self._lldp_cache[cache_key]

        neighbors: Dict[str, List[Dict[str, Optional[str]]]] = {}

        detail = self._safe_get_lldp_neighbors_detail(device_conn)
        if detail:
            neighbors = self._normalize_lldp_detail(detail)
        else:
            basic = self._safe_get_lldp_neighbors(device_conn)
            if basic:
                neighbors = self._normalize_lldp_basic(basic)

        if cache_key:
            self._lldp_cache[cache_key] = neighbors
        return neighbors

    def _safe_get_lldp_neighbors_detail(
        self, device_conn
    ) -> Optional[Dict[str, Iterable[Dict[str, object]]]]:
        """Best-effort retrieval of detailed LLDP data."""

        getter = getattr(device_conn, "get_lldp_neighbors_detail", None)
        if not callable(getter):
            return None
        try:
            return getter()
        except NotImplementedError:
            return None
        except Exception as exc:  # pragma: no cover - defensive logging
            if self._logger:
                self._logger.debug(
                    f"LLDP detail lookup failed: {exc}",
                    extra={"grouping": "next-hop-discovery"},
                )
            return None

    def _safe_get_lldp_neighbors(
        self, device_conn
    ) -> Optional[Dict[str, Iterable[Dict[str, object]]]]:
        """Best-effort retrieval of basic LLDP data."""

        getter = getattr(device_conn, "get_lldp_neighbors", None)
        if not callable(getter):
            return None
        try:
            return getter()
        except NotImplementedError:
            return None
        except Exception as exc:  # pragma: no cover - defensive logging
            if self._logger:
                self._logger.debug(
                    f"LLDP lookup failed: {exc}",
                    extra={"grouping": "next-hop-discovery"},
                )
            return None

    @staticmethod
    def _normalize_lldp_detail(
        detail: Dict[str, Iterable[Dict[str, object]]]
    ) -> Dict[str, List[Dict[str, Optional[str]]]]:
        normalized: Dict[str, List[Dict[str, Optional[str]]]] = {}
        for local_if, entries in detail.items():
            if not isinstance(entries, Iterable):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                hostname = (
                    entry.get("remote_system_name")
                    or entry.get("remote_chassis_id")
                    or entry.get("remote_system_description")
                )
                port = (
                    entry.get("remote_port")
                    or entry.get("remote_port_id")
                    or entry.get("remote_port_desc")
                )
                if not hostname and not port:
                    continue
                normalized.setdefault(local_if, []).append(
                    {
                        "hostname": str(hostname) if hostname else None,
                        "port": str(port) if port else None,
                        "local_interface": local_if,
                    }
                )
        return normalized

    @staticmethod
    def _normalize_lldp_basic(
        basic: Dict[str, Iterable[Dict[str, object]]]
    ) -> Dict[str, List[Dict[str, Optional[str]]]]:
        normalized: Dict[str, List[Dict[str, Optional[str]]]] = {}
        for local_if, entries in basic.items():
            if not isinstance(entries, Iterable):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                hostname = entry.get("hostname")
                port = entry.get("port")
                if not hostname and not port:
                    continue
                normalized.setdefault(local_if, []).append(
                    {
                        "hostname": str(hostname) if hostname else None,
                        "port": str(port) if port else None,
                        "local_interface": local_if,
                    }
                )
        return normalized

    def _annotate_hops_with_lldp(
        self,
        *,
        next_hops: List[Dict[str, object]],
        lldp_neighbors: Dict[str, List[Dict[str, Optional[str]]]],
    ) -> None:
        """Classify hops as layer2/layer3 based on LLDP evidence."""

        if not next_hops:
            return

        neighbor_matches: Dict[str, List[Dict[str, Optional[str]]]] = {}
        for local_if, entries in lldp_neighbors.items():
            normalized = self._normalize_interface(local_if)
            if not normalized:
                continue
            neighbor_matches.setdefault(normalized, []).extend(entries)

        for hop in next_hops:
            next_ip = hop.get("next_hop_ip")
            egress_if = hop.get("egress_interface")
            hop_type: Optional[str] = None
            matched_neighbor: Optional[Dict[str, Optional[str]]] = None

            if egress_if:
                normalized_if = self._normalize_interface(egress_if)
                candidates = neighbor_matches.get(normalized_if, [])
                matched_neighbor = self._match_lldp_neighbor(
                    neighbors=candidates,
                    next_hop_ip=next_ip,
                )

            if matched_neighbor:
                hop_type = "layer2+layer3" if next_ip else "layer2"
            elif next_ip:
                hop_type = "layer3"

            if hop_type:
                hop["hop_type"] = hop_type

    def discover_layer2_path(
        self,
        *,
        device_name: Optional[str],
        egress_interface: Optional[str],
        target_ip: Optional[str],
    ) -> List[Dict[str, Optional[str]]]:
        """Return serialized Layer2Hop entries from ``device_name`` toward ``target_ip``."""

        if not self._settings.enable_layer2_discovery:
            return []
        if not device_name or not egress_interface or not target_ip:
            return []

        if self._logger:
            self._logger.debug(
                "Discovering layer2 path from %s via %s toward %s",
                device_name,
                egress_interface,
                target_ip,
                extra={"grouping": "layer2-discovery"},
            )

        device = self._data_source.get_device(device_name)
        if not device or not device.primary_ip:
            return []

        if self._is_palo_alto_device(device):
            pa_settings = self._settings.pa_settings()
            if pa_settings is None:
                return []
            client = PaloAltoClient(
                host=device.primary_ip,
                verify_ssl=pa_settings.verify_ssl,
                timeout=10,
                logger=self._logger,
            )
            try:
                api_key = client.keygen(pa_settings.username, pa_settings.password)
            except RuntimeError as exc:
                if self._logger:
                    self._logger.debug(
                        f"Palo Alto keygen failed for '{device.name}': {exc}",
                        extra={"grouping": "layer2-discovery"},
                    )
                return []
            return self._discover_palo_layer2_path(
                client=client,
                api_key=api_key,
                device=device,
                egress_interface=egress_interface,
                target_ip=target_ip,
            )

        helper = self._build_layer2_helper()
        if helper is None:
            if self._logger:
                self._logger.debug(
                    "Layer2 helper unavailable for %s", device_name, extra={"grouping": "layer2-discovery"}
                )
            return []

        napalm_settings = self._settings.napalm_settings()
        if napalm_settings is None:
            return []
        if napalm is None:
            return []

        driver_name = self._select_napalm_driver(device)
        for candidate in self._driver_attempts(driver_name):
            try:
                driver = napalm.get_network_driver(candidate)
            except Exception:
                continue
            optional_args = self._optional_args_for(candidate)
            try:
                with driver(
                    hostname=device.primary_ip,
                    username=napalm_settings.username,
                    password=napalm_settings.password,
                    optional_args=optional_args,
                ) as device_conn:
                    neighbors = self._collect_lldp_neighbors(device_conn, device.name)
                    hops = helper.discover(
                        initial_device=device,
                        initial_conn=device_conn,
                        initial_driver_name=candidate,
                        initial_lldp_neighbors=neighbors,
                        egress_interface=egress_interface,
                        next_hop_ip=target_ip,
                    )
                    if hops:
                        return [hop.as_dict() for hop in hops]
            except Exception as exc:  # pragma: no cover - best effort
                if self._logger:
                    self._logger.debug(
                        f"Layer 2 discovery retry failed for '{device.name}': {exc}",
                        extra={"grouping": "layer2-discovery"},
                    )
                continue
        return []

    def _build_layer2_helper(self) -> Optional[Layer2Discovery]:
        """Return a cached Layer2Discovery helper if possible."""

        if self._layer2_helper is not None:
            return self._layer2_helper
        if not self._settings.enable_layer2_discovery:
            return None
        if napalm is None:
            return None

        helper = Layer2Discovery(
            napalm_module=napalm,
            settings=self._settings,
            data_source=self._data_source,
            logger=self._logger,
            select_driver=self._select_napalm_driver,
            driver_attempts=self._driver_attempts,
            optional_args_for=self._optional_args_for,
            collect_lldp_neighbors=self._collect_lldp_neighbors,
            normalize_interface=self._normalize_interface,
            normalize_hostname=self._normalize_hostname,
        )
        self._layer2_helper = helper
        return helper

    def _discover_palo_layer2_path(
        self,
        *,
        client: PaloAltoClient,
        api_key: str,
        device: DeviceRecord,
        egress_interface: Optional[str],
        target_ip: Optional[str],
    ) -> List[Dict[str, Optional[str]]]:
        """Return serialized layer-2 hops derived from Palo Alto LLDP/ARP data."""

        if not self._settings.enable_layer2_discovery:
            return []
        if self._settings.layer2_max_depth <= 0:
            return []
        if not egress_interface or not target_ip:
            return []
        egress_norm = self._normalize_interface(egress_interface)
        if not egress_norm:
            return []

        neighbors = self._get_palo_lldp_neighbors(client, api_key, device.name)

        arp_table = self._get_palo_arp_table(client, api_key, device.name)
        arp_entry = arp_table.get(target_ip)
        if not arp_entry:
            return []
        mac_addr = (arp_entry.get("mac") or arp_entry.get("mac_address") or "").strip()
        if not mac_addr:
            return []
        mac_addr_norm = mac_addr.upper()

        arp_if_norm = self._normalize_interface(arp_entry.get("interface"))

        if arp_if_norm and arp_if_norm == egress_norm:
            if "vlan" not in egress_norm:
                if self._logger:
                    self._logger.debug(
                        "Skipping Palo Alto layer-2 discovery on %s; egress %s matches ARP interface %s",
                        device.name,
                        egress_interface,
                        arp_entry.get("interface"),
                        extra={"grouping": "layer2-discovery"},
                    )
                return []

        interfaces_to_query: List[str] = []
        interface_aliases: Dict[str, str] = {}

        def _add_interface(alias: Optional[str]) -> None:
            if not alias:
                return
            norm = self._normalize_interface(alias)
            if not norm:
                return
            if norm not in interface_aliases:
                interface_aliases[norm] = alias
            if norm not in interfaces_to_query:
                interfaces_to_query.append(norm)

        _add_interface(egress_interface)
        if arp_if_norm and arp_entry.get("interface"):
            _add_interface(arp_entry.get("interface"))
        elif arp_if_norm:
            _add_interface(arp_if_norm)

        vlan_members: List[str] = []
        if egress_norm and "vlan" in egress_norm:
            vlan_members = self._get_palo_vlan_members(
                client=client,
                api_key=api_key,
                device_name=device.name,
                vlan_interface=egress_interface,
            )
            for member in vlan_members:
                _add_interface(member)
            if self._logger and vlan_members:
                self._logger.debug(
                    "Augmented VLAN interface %s with members %s for %s",
                    egress_interface,
                    vlan_members,
                    device.name,
                    extra={"grouping": "layer2-discovery"},
                )

        chosen_neighbors: Optional[List[Dict[str, Optional[str]]]] = None
        resolved_gateway_interface: Optional[str] = None
        for iface in interfaces_to_query:
            if not iface:
                continue
            candidate_list = neighbors.get(iface)
            if candidate_list:
                chosen_neighbors = candidate_list
                resolved_gateway_interface = interface_aliases.get(iface, iface)
                break
        if chosen_neighbors is None:
            if self._logger:
                self._logger.debug(
                    "No LLDP neighbors match interfaces %s on %s",
                    interfaces_to_query,
                    device.name,
                    extra={"grouping": "layer2-discovery"},
                )
            return []
        if resolved_gateway_interface is None:
            resolved_gateway_interface = interface_aliases.get(egress_norm, egress_interface) or egress_interface

        neighbors_for_helper: Dict[str, List[Dict[str, Optional[str]]]] = {
            key: list(entries or []) for key, entries in neighbors.items()
        }
        if egress_norm and egress_norm not in neighbors_for_helper:
            neighbors_for_helper[egress_norm] = list(chosen_neighbors)
        if arp_if_norm and arp_if_norm not in neighbors_for_helper and chosen_neighbors:
            neighbors_for_helper[arp_if_norm] = list(chosen_neighbors)
        for member in vlan_members:
            member_norm = self._normalize_interface(member)
            if (
                member_norm
                and member_norm in neighbors
                and egress_norm
                and egress_norm not in neighbors_for_helper
            ):
                neighbors_for_helper[egress_norm] = list(neighbors[member_norm])

        layer2_helper = self._build_layer2_helper()
        napalm_settings = self._settings.napalm_settings()

        if layer2_helper and napalm_settings:
            class _PaloNapalmAdapter:
                def __init__(self, arp_rows: List[Dict[str, Optional[str]]]) -> None:
                    self._arp_rows = list(arp_rows or [])

                def get_arp_table(self) -> List[Dict[str, Optional[str]]]:
                    return list(self._arp_rows)

                def get_mac_address_table(self) -> List[Dict[str, Optional[str]]]:
                    return []

            adapter = _PaloNapalmAdapter(list(arp_table.values()))
            try:
                hops = layer2_helper.discover(
                    initial_device=device,
                    initial_conn=adapter,
                    initial_driver_name="palo_alto",
                    initial_lldp_neighbors=neighbors_for_helper,
                    egress_interface=egress_interface,
                    next_hop_ip=target_ip,
                )
            except Exception as exc:  # pragma: no cover - defensive logging
                if self._logger:
                    self._logger.debug(
                        "Palo Alto layer-2 helper failed for %s: %s",
                        device.name,
                        exc,
                        extra={"grouping": "layer2-discovery"},
                    )
            else:
                if hops:
                    serialized: List[Dict[str, Optional[str]]] = []
                    for index, hop in enumerate(hops):
                        payload = hop.as_dict()
                        if index == 0 and resolved_gateway_interface:
                            payload["gateway_interface"] = resolved_gateway_interface
                        serialized.append(payload)
                    return serialized

        neighbor = self._match_lldp_neighbor(chosen_neighbors, target_ip)
        if not neighbor:
            neighbor = chosen_neighbors[0]
        if not neighbor:
            return []

        neighbor_name = neighbor.get("hostname")
        if not neighbor_name:
            neighbor_name = neighbor.get("port") or f"layer2-neighbor-{device.name}"
        neighbor_name = str(neighbor_name)

        mac_table = self._get_palo_mac_table(client, api_key, device.name)
        mac_entry = mac_table.get(mac_addr.upper())
        egress_on_neighbor = None
        if mac_entry and mac_entry.get("interface"):
            egress_norm_candidate = self._normalize_interface(mac_entry.get("interface"))
            egress_on_neighbor = interface_aliases.get(egress_norm_candidate, mac_entry.get("interface"))

        if not egress_on_neighbor and self._logger:
            self._logger.debug(
                "Palo Alto layer-2 hop missing downstream egress for %s (MAC %s); leaving egress unset",
                neighbor_name,
                mac_addr_norm,
                extra={"grouping": "layer2-discovery"},
            )

        ingress_on_neighbor = neighbor.get("port")
        if ingress_on_neighbor and ingress_on_neighbor.isdigit():
            ingress_on_neighbor = None
        if not ingress_on_neighbor:
            ingress_on_neighbor = neighbor.get("port_description") or neighbor.get("port")

        details = (
            f"Layer 2 hop resolved via LLDP/MAC on '{neighbor_name or 'unknown'}' "
            f"(MAC {mac_addr_norm})."
        )

        if self._logger:
            self._logger.debug(
                "Derived Palo Alto layer-2 hop (fallback): device=%s ingress=%s egress=%s mac=%s",
                neighbor_name,
                ingress_on_neighbor,
                egress_on_neighbor,
                mac_addr_norm,
                extra={"grouping": "layer2-discovery"},
            )

        return [
            {
                "device_name": neighbor_name,
                "ingress_interface": ingress_on_neighbor,
                "egress_interface": egress_on_neighbor,
                "mac_address": mac_addr_norm,
                "gateway_interface": resolved_gateway_interface or egress_interface,
                "details": details,
            }
        ]

    def _classify_palo_alto_hop(
        self,
        *,
        client: PaloAltoClient,
        api_key: str,
        device: DeviceRecord,
        egress_interface: Optional[str],
        next_hop_ip: Optional[str],
    ) -> Optional[str]:
        """Return hop classification based on LLDP/ARP evidence for Palo Alto devices."""

        hop_type: Optional[str] = None
        lldp_neighbor: Optional[Dict[str, Optional[str]]] = None
        arp_entry: Optional[Dict[str, Optional[str]]] = None
        egress_norm = self._normalize_interface(egress_interface)

        if egress_norm:
            neighbors = self._get_palo_lldp_neighbors(client, api_key, device.name)
            candidates = neighbors.get(egress_norm, [])
            lldp_neighbor = self._match_lldp_neighbor(candidates, next_hop_ip)

        if next_hop_ip:
            arp_table = self._get_palo_arp_table(client, api_key, device.name)
            candidate = arp_table.get(next_hop_ip)
            if candidate:
                if egress_norm:
                    candidate_norm = self._normalize_interface(candidate.get("interface"))
                    if candidate_norm and candidate_norm != egress_norm:
                        candidate = None
                arp_entry = candidate

        if lldp_neighbor:
            hop_type = "layer2+layer3" if next_hop_ip else "layer2"
        elif arp_entry:
            hop_type = "layer2+layer3"
        elif next_hop_ip:
            hop_type = "layer3"

        return hop_type

    def _get_palo_lldp_neighbors(
        self,
        client: PaloAltoClient,
        api_key: str,
        device_name: str,
    ) -> Dict[str, List[Dict[str, Optional[str]]]]:
        """Return cached LLDP neighbors for the Palo Alto device."""

        cache_key = f"{device_name}::lldp"
        cached = self._palo_lldp_cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            raw_neighbors = client.get_lldp_neighbors(api_key)
        except RuntimeError as exc:
            raw_neighbors = {}
            if self._logger:
                self._logger.debug(
                    f"Palo Alto LLDP retrieval failed for '{device_name}': {exc}",
                    extra={"grouping": "next-hop-discovery"},
                )

        normalized: Dict[str, List[Dict[str, Optional[str]]]] = {}
        for local_if, entries in (raw_neighbors or {}).items():
            normalized_if = self._normalize_interface(local_if)
            if not normalized_if:
                continue
            sanitized: List[Dict[str, Optional[str]]] = []
            for entry in entries or []:
                remote_port = entry.get("port")
                port_description = entry.get("port_description")
                sanitized.append(
                    {
                        "hostname": entry.get("hostname"),
                        "port": port_description or remote_port,
                        "port_id": remote_port,
                        "port_description": port_description,
                        "management_ip": entry.get("management_ip"),
                        "local_interface": entry.get("local_interface") or local_if,
                    }
                )
            if sanitized:
                normalized[normalized_if] = sanitized

        self._palo_lldp_cache[cache_key] = normalized
        return normalized

    def _get_palo_mac_table(
        self,
        client: PaloAltoClient,
        api_key: str,
        device_name: str,
    ) -> Dict[str, Dict[str, Optional[str]]]:
        """Return cached MAC address table entries keyed by MAC."""

        cache_key = f"{device_name}::mac"
        cached = self._palo_mac_cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            entries = client.get_mac_table(api_key)
        except RuntimeError as exc:
            entries = []
            if self._logger:
                self._logger.debug(
                    f"Palo Alto MAC retrieval failed for '{device_name}': {exc}",
                    extra={"grouping": "layer2-discovery"},
                )

        table: Dict[str, Dict[str, Optional[str]]] = {}
        for entry in entries or []:
            mac = entry.get("mac")
            if not mac:
                continue
            table[mac.upper()] = {
                "mac": mac,
                "interface": entry.get("interface"),
                "vlan": entry.get("vlan"),
                "age": entry.get("age"),
            }

        self._palo_mac_cache[cache_key] = table
        return table

    def _get_palo_vlan_members(
        self,
        *,
        client: PaloAltoClient,
        api_key: str,
        device_name: str,
        vlan_interface: str,
    ) -> List[str]:
        """Return member interfaces for the VLAN carrying ``vlan_interface``."""

        cache_key = f"{device_name}::vlan::{vlan_interface}"
        cached = self._palo_vlan_member_cache.get(cache_key)
        if cached is not None:
            return cached

        members = client.vlan_members_for_interface(api_key, vlan_interface)
        if not members:
            vlan_iface_norm = self._normalize_interface(vlan_interface) or vlan_interface.lower()
            iface_token = vlan_iface_norm.replace("vlan.", "").replace("vlan-", "")
            for candidate in (iface_token, f"vlan.{iface_token}", f"vlan-{iface_token}"):
                if candidate == vlan_interface or not candidate:
                    continue
                members = client.vlan_members_for_interface(api_key, candidate)
                if members:
                    break

        if not members and self._logger:
            self._logger.debug(
                "VLAN member lookup failed for '%s' interface '%s'",
                device_name,
                vlan_interface,
                extra={"grouping": "layer2-discovery"},
            )

        self._palo_vlan_member_cache[cache_key] = members
        return members

    def _get_palo_arp_table(
        self,
        client: PaloAltoClient,
        api_key: str,
        device_name: str,
    ) -> Dict[str, Dict[str, Optional[str]]]:
        """Return cached ARP table entries keyed by IP."""

        cache_key = f"{device_name}::arp"
        cached = self._palo_arp_cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            entries = client.get_arp_table(api_key)
        except RuntimeError as exc:
            entries = []
            if self._logger:
                self._logger.debug(
                    f"Palo Alto ARP retrieval failed for '{device_name}': {exc}",
                    extra={"grouping": "next-hop-discovery"},
                )

        table: Dict[str, Dict[str, Optional[str]]] = {}
        for entry in entries or []:
            ip_addr = entry.get("ip")
            if not ip_addr:
                continue
            table[ip_addr] = {
                "ip": ip_addr,
                "interface": entry.get("interface"),
                "mac": entry.get("mac"),
                "vlan": entry.get("vlan"),
                "age": entry.get("age"),
            }

        self._palo_arp_cache[cache_key] = table
        return table

    def _match_lldp_neighbor(
        self,
        neighbors: Optional[List[Dict[str, Optional[str]]]],
        next_hop_ip: Optional[str],
    ) -> Optional[Dict[str, Optional[str]]]:
        """Return matching LLDP neighbor for the next hop device, if any."""

        if not neighbors:
            return None

        target_name: Optional[str] = None
        if next_hop_ip:
            target_name = self._lookup_device_name_for_ip(next_hop_ip)

        if target_name:
            normalized_target = self._normalize_hostname(target_name)
            for neighbor in neighbors:
                hostname = neighbor.get("hostname")
                if hostname and self._normalize_hostname(hostname) == normalized_target:
                    return neighbor
            return None

        if next_hop_ip:
            return None
        return neighbors[0]

    def _lookup_device_name_for_ip(self, ip_addr: str) -> Optional[str]:
        """Return Nautobot device name for IP, with caching."""

        if ip_addr in self._ip_device_cache:
            return self._ip_device_cache[ip_addr]

        device_record = self._data_source.get_ip_address(ip_addr)
        device_name = device_record.device_name if device_record else None
        self._ip_device_cache[ip_addr] = device_name
        return device_name

    def _is_palo_alto_device(self, device: DeviceRecord) -> bool:
        """Return True if ``device`` appears to be a Palo Alto platform."""

        for candidate in (device.platform_slug, device.platform_name):
            if isinstance(candidate, str):
                token = candidate.lower()
                if any(indicator in token for indicator in self._PALO_ALTO_INDICATORS):
                    return True
        return False

    @staticmethod
    def _normalize_hostname(name: Optional[str]) -> Optional[str]:
        if not isinstance(name, str):
            return None
        token = name.strip().lower()
        if not token:
            return None
        return token.split(".")[0]

    @staticmethod
    def _normalize_interface(name: Optional[str]) -> Optional[str]:
        if not isinstance(name, str):
            return None
        token = name.strip().lower().replace(" ", "")
        return token or None
