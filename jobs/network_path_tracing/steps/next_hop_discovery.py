"""Step 3: next-hop discovery on the current device."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Optional, List, Dict, Tuple

from ..config import NetworkPathSettings
from ..exceptions import NextHopDiscoveryError
from ..interfaces.nautobot import NautobotDataSource, DeviceRecord
from ..interfaces.palo_alto import PaloAltoClient
from .gateway_discovery import GatewayDiscoveryResult
from .input_validation import InputValidationResult

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
    """Discover the next-hop(s) from the current device to the destination."""

    _NXOS_DRIVERS = {"nxos", "nxos_ssh"}

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

    def run(self, validation: InputValidationResult, gateway: GatewayDiscoveryResult) -> NextHopDiscoveryResult:
        """Execute the next-hop discovery for the destination IP."""
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

        if device.platform_slug == "panos":
            try:
                result = self._run_palo_alto_lookup(device, ingress_if, validation.destination_ip)
            except NextHopDiscoveryError as exc:
                self._cache[cache_key] = str(exc)
                raise
            self._cache[cache_key] = result
            return result

        try:
            result = self._run_napalm_lookup(device, ingress_if, validation.destination_ip)
        except NextHopDiscoveryError as exc:
            self._cache[cache_key] = str(exc)
            raise
        self._cache[cache_key] = result
        return result

    def _run_palo_alto_lookup(self, device: DeviceRecord, ingress_if: str, destination_ip: str) -> NextHopDiscoveryResult:
        """Perform next-hop lookup for Palo Alto devices."""
        pa_settings = self._settings.pa_settings()
        if not pa_settings:
            raise NextHopDiscoveryError("Palo Alto credentials not configured (set PA_USERNAME and PA_PASSWORD)")
        client = PaloAltoClient(host=device.primary_ip, verify_ssl=pa_settings.verify_ssl, timeout=10)
        try:
            api_key = client.keygen(pa_settings.username, pa_settings.password)
        except RuntimeError as exc:
            raise NextHopDiscoveryError(f"Authentication failed for '{device.primary_ip}': {exc}") from exc
        vr = client.get_virtual_router_for_interface(api_key, ingress_if)
        if not vr:
            raise NextHopDiscoveryError(f"No virtual-router found for interface '{ingress_if}' on '{device.name}'")
        try:
            res = client.fib_lookup(api_key, vr, destination_ip)
            if not (res["next_hop"] or res["egress_interface"]):
                res = client.route_lookup(api_key, vr, destination_ip)
            return NextHopDiscoveryResult(
                found=bool(res["next_hop"] or res["egress_interface"]),
                next_hops=[{"next_hop_ip": res["next_hop"], "egress_interface": res["egress_interface"]}],
                details=f"Resolved using virtual-router '{vr}' on '{device.name}'"
            )
        except RuntimeError as exc:
            raise NextHopDiscoveryError(f"Next-hop lookup failed for '{destination_ip}': {exc}") from exc

    def _run_napalm_lookup(self, device: DeviceRecord, ingress_if: str, destination_ip: str) -> NextHopDiscoveryResult:
        """Perform next-hop lookup using NAPALM."""

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
                    if candidate in self._NXOS_DRIVERS:
                        next_hops = self._collect_nxos_routes(device_conn, destination_ip, ingress_if)
                        details = f"Resolved via NX-OS CLI on '{device.name}'"
                    else:
                        next_hops = self._collect_generic_routes(device_conn, destination_ip)
                        details = f"Resolved via NAPALM on '{device.name}'"

                    if not next_hops:
                        return NextHopDiscoveryResult(
                            found=False,
                            next_hops=[],
                            details=f"No route found for '{destination_ip}' on '{device.name}'",
                        )

                    return NextHopDiscoveryResult(
                        found=True,
                        next_hops=next_hops,
                        details=details,
                    )
            except Exception as exc:  # noqa: BLE001 - escalate after fallbacks
                last_error = exc
                if self._logger:
                    self._logger.warning(
                        f"NAPALM driver '{candidate}' failed for {device.name}: {exc}",
                        extra={"grouping": "next-hop-discovery"},
                    )
                continue

        raise NextHopDiscoveryError(
            f"NAPALM lookup failed for '{device.name}': {last_error}"
        )

    def _driver_attempts(self, initial: str) -> List[str]:
        """Order the driver names to try, adding sensible fallbacks."""

        attempts = [initial]
        if initial == "nxos":
            attempts.append("nxos_ssh")
        elif initial == "nxos_ssh":
            attempts.append("nxos")
        return attempts

    @staticmethod
    def _optional_args_for(driver_name: str) -> dict:
        """Return driver-specific optional arguments."""

        if driver_name == "nxos":
            return {"port": 443, "verify": False}
        if driver_name == "nxos_ssh":
            return {"port": 22}
        if driver_name in {"ios", "eos", "junos", "arista_eos", "cisco_ios"}:
            return {"port": 22}
        return {}

    def _select_napalm_driver(self, device: DeviceRecord) -> str:
        """Determine the appropriate NAPALM driver name for a device."""

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
        """Collect next-hop information using get_route_to()."""

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
        """Collect next-hop information for NX-OS platforms via CLI JSON."""

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
        """Run an NX-OS CLI command and return parsed JSON data."""

        try:
            response = device_conn.cli([command])
        except Exception as exc:  # pragma: no cover - transport errors fallback to generic handler
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
        """Translate NX-OS JSON route payload into generic next-hop entries."""

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
        """Return a list of VRF names configured on the NX-OS device."""

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
        """Return the VRF name associated with an interface, if any."""

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
