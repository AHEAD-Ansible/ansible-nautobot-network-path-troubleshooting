"""F5 BIG-IP helper client for next-hop discovery."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import requests
import urllib3


class F5APIError(RuntimeError):
    """Raised when the BIG-IP API returns an error."""


def _split_ip_rd(addr: str) -> Tuple[str, Optional[int]]:
    """Split an F5 address like '10.1.2.3%2' into (ip, route_domain)."""
    if "%" in addr:
        ip_part, rd_part = addr.split("%", 1)
        try:
            return ip_part, int(rd_part)
        except ValueError:
            return ip_part, None
    return addr, None


def _strip_rd_from_vs_destination(dest: str) -> Tuple[str, Optional[int], Optional[int]]:
    """Return (ip, route_domain, port) extracted from a destination string."""
    d = dest.split("/")[-1]
    if ":" not in d:
        return d, None, None
    ip_rd, port_str = d.rsplit(":", 1)
    ip_str, rd = _split_ip_rd(ip_rd)
    try:
        port = int(port_str)
    except ValueError:
        port = None
    return ip_str, rd, port


def _net_contains_ip(cidr: str, candidate: str) -> bool:
    """Return True if candidate lies within cidr, ignoring route-domain syntax."""
    try:
        network = ipaddress.ip_network(cidr.split("%")[0], strict=False)
        return ipaddress.ip_address(candidate) in network
    except Exception:
        return False


@dataclass(frozen=True)
class F5NextHopSummary:
    """Structured payload describing how a BIG-IP will reach a destination."""

    destination_ip: str
    pools_containing_member: List[str] = field(default_factory=list)
    virtual_servers: List[Dict[str, Optional[str]]] = field(default_factory=list)
    next_hop_ip: Optional[str] = None
    ingress_vlan: Optional[str] = None
    ingress_interface: Optional[str] = None
    egress_vlan: Optional[str] = None
    egress_interface: Optional[str] = None
    egress_self_ip: Optional[str] = None
    egress_self_ip_address: Optional[str] = None

    def as_dict(self) -> Dict[str, object]:
        """Return a JSON-serialisable representation."""
        return {
            "pools_containing_member": list(self.pools_containing_member),
            "virtual_servers": list(self.virtual_servers),
            "ingress_vlan": self.ingress_vlan,
            "ingress_interface": self.ingress_interface,
            "egress_vlan": self.egress_vlan,
            "egress_interface": self.egress_interface,
            "egress_self_ip": self.egress_self_ip,
            "egress_self_ip_address": self.egress_self_ip_address,
        }


class F5Client:
    """Minimal BIG-IP REST client tailored for next-hop discovery."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        verify_ssl: bool = True,
        timeout: int = 10,
    ) -> None:
        self.base = f"https://{host}/mgmt"
        self._session = requests.Session()
        self._session.verify = verify_ssl
        self._timeout = timeout
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._login(username, password)

    def _login(self, username: str, password: str) -> None:
        """Authenticate and store the session token."""
        url = f"{self.base}/shared/authn/login"
        payload = {
            "username": username,
            "password": password,
            "loginProviderName": "tmos",
        }
        response = self._session.post(url, json=payload, timeout=self._timeout)
        response.raise_for_status()
        try:
            token = response.json()["token"]["token"]
        except (KeyError, ValueError) as exc:
            raise F5APIError("Unable to acquire BIG-IP auth token") from exc
        self._session.headers.update({"X-F5-Auth-Token": token})

    def _get(self, path: str, params: Optional[Dict[str, object]] = None) -> Dict[str, object]:
        """Issue a GET request and return the JSON payload."""
        url = f"{self.base}{path}"
        response = self._session.get(url, params=params, timeout=self._timeout)
        response.raise_for_status()
        return response.json()

    # ---- Raw collectors -------------------------------------------------

    def get_pools_with_members(self) -> Dict[str, object]:
        return self._get("/tm/ltm/pool", params={"expandSubcollections": "true"})

    def get_virtuals(self) -> Dict[str, object]:
        return self._get("/tm/ltm/virtual")

    def get_virtual_addresses(self) -> Dict[str, object]:
        return self._get("/tm/ltm/virtual-address")

    def get_self_ips(self) -> Dict[str, object]:
        return self._get("/tm/net/self")

    def get_vlans(self) -> Dict[str, object]:
        return self._get("/tm/net/vlan", params={"expandSubcollections": "true"})

    def get_static_routes(self) -> Dict[str, object]:
        return self._get("/tm/net/route")

    # ---- High-level orchestration --------------------------------------

    def collect_destination_summary(
        self,
        destination_ip: str,
        *,
        partitions: Optional[Sequence[str]] = None,
        ingress_hint: Optional[str] = None,
    ) -> F5NextHopSummary:
        """Return routing metadata for reaching destination_ip on the BIG-IP."""
        pools_doc = self.get_pools_with_members()
        vips_doc = self.get_virtuals()
        va_doc = self.get_virtual_addresses()
        self_doc = self.get_self_ips()
        vlan_doc = self.get_vlans()
        routes_doc = self.get_static_routes()

        pool_hits = _find_pools_for_ip(pools_doc, destination_ip, partitions)
        pool_names = [hit["pool_name"] for hit in pool_hits]

        vs_hits = _find_virtuals_for_pools(vips_doc, pool_names)
        va_index = _index_virtual_addresses(va_doc)
        vs_summaries: List[Dict[str, Optional[str]]] = []
        vs_vlan_candidates: List[str] = []
        rd_from_member: Optional[int] = None
        for hit in pool_hits:
            member_addr = hit["member"].get("address") or hit["member"].get("name", "")
            _, rd_from_member = _split_ip_rd(member_addr or destination_ip)

        for vs in vs_hits:
            vip_ip, rd, _ = _strip_rd_from_vs_destination(vs.get("destination", ""))
            va = va_index.get((vip_ip, rd)) or va_index.get((vip_ip, None))
            vs_vlan_candidates.extend(_extract_vs_vlans(vs))
            virtual_address = vip_ip
            if not virtual_address and va:
                virtual_address = _normalize_token(va.get("fullPath") or va.get("name"))
            vs_summaries.append(
                {
                    "name": vs.get("fullPath") or vs.get("name"),
                    "virtual_address": virtual_address,
                }
            )

        self_list = _index_self_ips(self_doc)
        vlan_index = _index_vlans_with_ports(vlan_doc)
        directly_connected = next(
            (s for s in self_list if _net_contains_ip(s["raw"]["address"], destination_ip)),
            None,
        )

        egress_vlan = None
        egress_self = None
        next_hop_ip: Optional[str] = None

        if directly_connected:
            egress_vlan = directly_connected["vlan"]
            egress_self = directly_connected
            next_hop_ip = destination_ip
        else:
            route = _longest_match_route(routes_doc, destination_ip, rd_from_member)
            if route:
                next_hop_ip = route.get("gw")
                if next_hop_ip:
                    egress_vlan, egress_self = _choose_egress_vlan_and_self(self_list, next_hop_ip, rd_from_member)
                else:
                    net = route.get("network")
                    for s in self_list:
                        if _net_contains_ip(net, s["ip"]):
                            egress_vlan = s["vlan"]
                            egress_self = s
                            break

        ingress_vlan, ingress_interface = _resolve_ingress_vlan(
            vlan_index,
            vs_vlan_candidates,
            ingress_hint,
        )

        egress_interface = None
        if egress_vlan:
            vlan_entry = vlan_index.get(egress_vlan)
            if vlan_entry:
                egress_interface = _select_interface(vlan_entry)

        return F5NextHopSummary(
            destination_ip=destination_ip,
            pools_containing_member=pool_names,
            virtual_servers=vs_summaries,
            next_hop_ip=next_hop_ip,
            ingress_vlan=ingress_vlan,
            ingress_interface=ingress_interface,
            egress_vlan=egress_vlan,
            egress_interface=egress_interface,
            egress_self_ip=egress_self["fullPath"] if egress_self else None,
            egress_self_ip_address=egress_self["raw"]["address"] if egress_self else None,
        )


def _find_pools_for_ip(
    pools_doc: Dict[str, object],
    dest_ip: str,
    partitions: Optional[Sequence[str]] = None,
) -> List[Dict[str, object]]:
    matches: List[Dict[str, object]] = []
    items = pools_doc.get("items", []) if isinstance(pools_doc, dict) else []
    for pool in items:
        if partitions and pool.get("partition") not in partitions:
            continue
        members = (
            pool.get("membersReference", {}).get("items", [])
            or pool.get("members", [])
            or []
        )
        for member in members:
            addr = member.get("address")
            if not addr:
                name = member.get("name", "")
                addr = name.split("%")[0].split(":")[0].split("/")[-1]
            member_ip, _ = _split_ip_rd(addr)
            if member_ip == dest_ip:
                matches.append(
                    {
                        "pool_name": pool.get("fullPath") or pool.get("name"),
                        "pool_partition": pool.get("partition"),
                        "member": member,
                    }
                )
                break
    return matches


def _find_virtuals_for_pools(
    virtuals_doc: Dict[str, object],
    pool_fullpaths: Iterable[str],
) -> List[Dict[str, object]]:
    hits: List[Dict[str, object]] = []
    pool_set = {p for p in pool_fullpaths if p}
    items = virtuals_doc.get("items", []) if isinstance(virtuals_doc, dict) else []
    for vs in items:
        pool_ref = vs.get("pool")
        if pool_ref and pool_ref in pool_set:
            hits.append(vs)
    return hits


def _index_virtual_addresses(va_doc: Dict[str, object]) -> Dict[Tuple[str, Optional[int]], Dict[str, object]]:
    index: Dict[Tuple[str, Optional[int]], Dict[str, object]] = {}
    items = va_doc.get("items", []) if isinstance(va_doc, dict) else []
    for va in items:
        ip, rd = _split_ip_rd(va.get("address", ""))
        if ip:
            index[(ip, rd)] = va
    return index


def _index_self_ips(self_doc: Dict[str, object]) -> List[Dict[str, object]]:
    out: List[Dict[str, object]] = []
    items = self_doc.get("items", []) if isinstance(self_doc, dict) else []
    for entry in items:
        addr = entry.get("address")
        if not addr or ":" in addr:
            continue
        ip_str = addr.split("/")[0]
        ip_base, rd = _split_ip_rd(ip_str)
        try:
            network = ipaddress.ip_network(
                addr.replace(f"%{rd}" if rd is not None else "", ""),
                strict=False,
            )
        except Exception:
            continue
        floating = entry.get("floating", False)
        if isinstance(floating, str):
            floating = floating.lower() in {"true", "enabled", "yes"}
        out.append(
            {
                "raw": entry,
                "network": network,
                "ip": ip_base,
                "rd": rd,
                "vlan": entry.get("vlan"),
                "floating": floating,
                "fullPath": entry.get("fullPath") or entry.get("name"),
            }
        )
    return out


def _index_vlans_with_ports(vlan_doc: Dict[str, object]) -> Dict[str, Dict[str, object]]:
    index: Dict[str, Dict[str, object]] = {}
    items = vlan_doc.get("items", []) if isinstance(vlan_doc, dict) else []
    for vlan in items:
        interfaces = []
        raw_ifaces = (
            vlan.get("interfacesReference", {}).get("items", [])
            or vlan.get("interfaces", [])
            or []
        )
        for iface in raw_ifaces:
            name = iface.get("name")
            if not name:
                continue
            tagged = iface.get("tagged")
            if isinstance(tagged, str):
                tagged = tagged.lower() in {"true", "enabled", "yes"}
            interfaces.append(name.strip())
        full_path = vlan.get("fullPath") or vlan.get("name")
        index[full_path] = {
            "interfaces": interfaces,
            "name": vlan.get("name") or _normalize_token(full_path),
        }
    return index


def _normalize_token(value: Optional[str]) -> Optional[str]:
    if not isinstance(value, str):
        return None
    token = value.split("/")[-1]
    return token or value


def _extract_vs_vlans(vs: Dict[str, object]) -> List[str]:
    candidates: List[str] = []
    vlans_ref = vs.get("vlansReference", {})
    ref_items = vlans_ref.get("items") if isinstance(vlans_ref, dict) else None
    if isinstance(ref_items, list):
        for item in ref_items:
            if isinstance(item, dict):
                path = item.get("fullPath") or item.get("name")
                if path:
                    candidates.append(path)
            elif isinstance(item, str):
                candidates.append(item)
    vlans = vs.get("vlans")
    if isinstance(vlans, list):
        for entry in vlans:
            if isinstance(entry, dict):
                path = entry.get("fullPath") or entry.get("name")
                if path:
                    candidates.append(path)
            elif isinstance(entry, str):
                candidates.append(entry)
    elif isinstance(vlans, str):
        candidates.append(vlans)
    return candidates


def _match_vlan(vlan_index: Dict[str, Dict[str, object]], token: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not token:
        return None, None
    normalized = _normalize_token(token)
    for vlan_path, entry in vlan_index.items():
        entry_name = _normalize_token(entry.get("name"))
        vlan_name = _normalize_token(vlan_path)
        if token == vlan_path or normalized == vlan_name or (entry_name and normalized == entry_name):
            return vlan_path, _select_interface(entry)
        interfaces = entry.get("interfaces", []) or []
        if normalized and normalized in interfaces:
            return vlan_path, normalized
    return None, None


def _resolve_ingress_vlan(
    vlan_index: Dict[str, Dict[str, object]],
    candidates: Sequence[str],
    hint: Optional[str],
) -> Tuple[Optional[str], Optional[str]]:
    vlan, iface = _match_vlan(vlan_index, hint)
    if vlan:
        return vlan, iface
    for candidate in candidates:
        vlan, iface = _match_vlan(vlan_index, candidate)
        if vlan:
            return vlan, iface
    return None, None


def _select_interface(entry: Dict[str, object], preferred: Optional[str] = None) -> Optional[str]:
    interfaces = entry.get("interfaces", []) or []
    if preferred and preferred in interfaces:
        return preferred
    return interfaces[0] if interfaces else None


def _longest_match_route(
    routes_doc: Dict[str, object],
    dest_ip: str,
    rd: Optional[int],
) -> Optional[Dict[str, object]]:
    target = ipaddress.ip_address(dest_ip)
    best = None
    best_prefix = -1
    items = routes_doc.get("items", []) if isinstance(routes_doc, dict) else []
    for route in items:
        network = route.get("network")
        if not network or ":" in network:
            continue
        net_ip = network.split("%")[0]
        mask = network.split("/")[-1]
        try:
            net = ipaddress.ip_network(f"{net_ip}/{mask}", strict=False)
        except Exception:
            continue
        route_rd = None
        if "%" in network:
            try:
                route_rd = int(network.split("%")[1].split("/")[0])
            except Exception:
                route_rd = None
        if rd is not None and route_rd is not None and rd != route_rd:
            continue
        if target in net and net.prefixlen > best_prefix:
            best = route
            best_prefix = net.prefixlen
    return best


def _choose_egress_vlan_and_self(
    self_list: Iterable[Dict[str, object]],
    gw_ip: str,
    rd: Optional[int],
) -> Tuple[Optional[str], Optional[Dict[str, object]]]:
    vlan = None
    candidates: List[Dict[str, object]] = []
    for self_ip in self_list:
        if rd is not None and self_ip["rd"] is not None and rd != self_ip["rd"]:
            continue
        if _net_contains_ip(self_ip["raw"]["address"], gw_ip):
            vlan = self_ip["vlan"]
            candidates.append(self_ip)
    if not vlan:
        return None, None
    floating = [entry for entry in candidates if entry["floating"]]
    best = floating[0] if floating else candidates[0]
    return vlan, best


__all__ = ["F5APIError", "F5Client", "F5NextHopSummary"]
