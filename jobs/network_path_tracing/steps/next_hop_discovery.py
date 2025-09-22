"""Step 3: next-hop discovery on the current device."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List

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
    def __init__(self, data_source: NautobotDataSource, settings: NetworkPathSettings):
        self._data_source = data_source
        self._settings = settings

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
        if device.platform_slug == "panos":
            return self._run_palo_alto_lookup(device, ingress_if, validation.destination_ip)
        return self._run_napalm_lookup(device, ingress_if, validation.destination_ip)

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
        driver_map = {
            "ios": "ios",
            "nxos": "nxos",
            "eos": "eos",
            "junos": "junos",
        }
        driver_name = driver_map.get(device.platform_slug, "ios")
        try:
            driver = napalm.get_network_driver(driver_name)
            with driver(
                hostname=device.primary_ip,
                username=napalm_settings.username,
                password=napalm_settings.password,
                optional_args={"port": 22}
            ) as device_conn:
                route = device_conn.get_route_to(destination=destination_ip)
                next_hops = []
                for prefix, routes in route.items():
                    for route_info in routes.get("next_hop", []):
                        next_hop_ip = route_info.get("next_hop")
                        egress_if = route_info.get("outgoing_interface")
                        if next_hop_ip or egress_if:
                            next_hops.append({"next_hop_ip": next_hop_ip, "egress_interface": egress_if})
                if not next_hops:
                    return NextHopDiscoveryResult(
                        found=False,
                        next_hops=[],
                        details=f"No route found for '{destination_ip}' on '{device.name}'"
                    )
                return NextHopDiscoveryResult(
                    found=True,
                    next_hops=next_hops,
                    details=f"Resolved via NAPALM on '{device.name}'"
                )
        except Exception as exc:
            raise NextHopDiscoveryError(f"NAPALM lookup failed for '{device.name}': {exc}") from exc