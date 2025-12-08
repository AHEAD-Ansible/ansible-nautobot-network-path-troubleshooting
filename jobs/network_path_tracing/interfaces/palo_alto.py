"""Palo Alto API client for next-hop lookups."""

from __future__ import annotations

import logging
import urllib.parse
import urllib3
import requests
import xml.etree.ElementTree as ET
from typing import List, Optional, Dict, Iterable


def _parse_pan_xml(text: str) -> ET.Element:
    """Parse XML response from Palo Alto API."""
    root = ET.fromstring(text)
    status = root.get("status")
    if status == "error":
        msg = (
            root.findtext(".//msg")
            or root.findtext(".//line")
            or root.findtext(".//message")
            or "Unknown error"
        )
        raise RuntimeError(f"Palo Alto API error: {msg}")
    return root


def _first_text_from_nodes(nodes: Iterable[ET.Element]) -> Optional[str]:
    """Return the first non-empty text from the provided nodes (including their children)."""
    for node in nodes:
        if node is None:
            continue
        if node.text and node.text.strip():
            return node.text.strip()
        for attr_val in node.attrib.values():
            if isinstance(attr_val, str) and attr_val.strip():
                return attr_val.strip()
        for child in node.iter():
            if child is node:
                continue
            if child.text and child.text.strip():
                return child.text.strip()
            for attr_val in child.attrib.values():
                if isinstance(attr_val, str) and attr_val.strip():
                    return attr_val.strip()
    return None


def _find_first_text(root: ET.Element, *xpaths: str) -> Optional[str]:
    """Find the first non-empty text in the given xpaths (searching descendants as needed)."""
    for xp in xpaths:
        matches = list(root.findall(xp))
        if not matches:
            single = root.find(xp)
            if single is not None:
                matches = [single]
        text = _first_text_from_nodes(matches)
        if text:
            return text
    return None


def _extract_next_hop_bundle(root: ET.Element) -> Dict[str, Optional[str]]:
    """Extract next-hop and egress interface from XML."""
    candidates = list(root.findall(".//result"))
    if not candidates:
        candidates = list(root.findall(".//entry"))
    if not candidates:
        candidates = [root]

    nh: Optional[str] = None
    egress: Optional[str] = None

    for candidate in candidates:
        if nh is None:
            nh = _find_first_text(
                candidate,
                ".//nexthop",
                ".//nexthop-ip",
                ".//ip-next-hop",
                "./ip-next-hop",
                ".//nexthop//ip",
                ".//nexthop//ip-address",
                "./ip",
                ".//ip",
                ".//next-hop",
                ".//via",
                ".//gw",
            )
        if egress is None:
            egress = _find_first_text(
                candidate,
                ".//egress-interface",
                ".//egress-if",
                "./egress-interface",
                ".//interface",
                "./interface",
                ".//egress",
                ".//oif",
                ".//nexthop//interface",
            )
        if nh and egress:
            break
    return {"next_hop": nh, "egress_interface": egress}


def _parse_lldp_neighbors(root: ET.Element) -> Dict[str, List[Dict[str, Optional[str]]]]:
    """Return LLDP neighbors keyed by local interface."""

    neighbors: Dict[str, List[Dict[str, Optional[str]]]] = {}
    for interface_entry in root.findall(".//entry"):
        local_if = interface_entry.get("name") or _find_first_text(
            interface_entry,
            "./local/interface",
            ".//local/interface",
            "./local/port-id",
            ".//local/port-id",
        )
        if not local_if:
            continue

        neighbor_entries = interface_entry.findall("./neighbors/entry") or interface_entry.findall(".//neighbors/entry")
        for neighbor_entry in neighbor_entries:
            hostname = _find_first_text(
                neighbor_entry,
                "./system-name",
                ".//system-name",
                ".//peer-device",
                ".//device-name",
                ".//chassis-name",
                ".//system",
                ".//remote-system-name",
            )
            remote_port = _find_first_text(
                neighbor_entry,
                "./port-id",
                ".//port-id",
                "./port",
                ".//port",
            )
            remote_port_desc = _find_first_text(
                neighbor_entry,
                "./port-description",
                ".//port-description",
                ".//remote-port-description",
            )
            mgmt_ip: Optional[str] = None
            for addr_entry in neighbor_entry.findall(".//management-address/entry"):
                candidate = addr_entry.get("name") or (addr_entry.text or "").strip()
                if candidate:
                    mgmt_ip = candidate.strip()
                    break
            if not mgmt_ip:
                mgmt_ip = _find_first_text(neighbor_entry, ".//management-address/entry")

            neighbors.setdefault(local_if, []).append(
                {
                    "hostname": hostname,
                    "port": remote_port,
                    "port_description": remote_port_desc,
                    "management_ip": mgmt_ip,
                    "local_interface": local_if,
                }
            )
    return neighbors


def _parse_arp_entries(root: ET.Element) -> List[Dict[str, Optional[str]]]:
    """Return ARP entries from the provided XML."""

    entries: List[Dict[str, Optional[str]]] = []
    for entry in root.findall(".//result//entry"):
        ip_addr = _find_first_text(entry, "./ip", ".//ip")
        if not ip_addr:
            continue
        interface = _find_first_text(entry, "./interface", ".//interface", "./if", ".//if")
        mac = _find_first_text(entry, "./mac", ".//mac", "./mac-address", ".//mac-address", ".//hwaddr")
        vlan = _find_first_text(entry, "./vlan", ".//vlan")
        age = _find_first_text(entry, "./ttl", ".//ttl", "./age", ".//age")
        entries.append(
            {
                "ip": ip_addr,
                "interface": interface,
                "mac": mac,
                "vlan": vlan,
                "age": age,
            }
        )
    return entries


def _parse_mac_entries(root: ET.Element) -> List[Dict[str, Optional[str]]]:
    """Return MAC address table entries from the provided XML."""

    entries: List[Dict[str, Optional[str]]] = []
    for entry in root.findall(".//result//entry"):
        mac = _find_first_text(entry, "./mac", ".//mac")
        if not mac:
            continue
        interface = _find_first_text(entry, "./interface", ".//interface", "./port", ".//port")
        vlan = _find_first_text(entry, "./vlan", ".//vlan")
        age = _find_first_text(entry, "./age", ".//age")
        entries.append(
            {
                "mac": mac,
                "interface": interface,
                "vlan": vlan,
                "age": age,
            }
        )
    return entries


def _parse_vlan_members(root: ET.Element) -> Dict[str, List[str]]:
    """Return mapping of vlan-interface -> list of member interfaces."""

    mapping: Dict[str, List[str]] = {}
    entries = root.findall(".//result//entry")
    if entries:
        for entry in entries:
            vlan_iface = _find_first_text(entry, "./vlan-interface", ".//vlan-interface")
            if not vlan_iface:
                vlan_iface = entry.get("name")
            members = [
                member.text.strip()
                for member in entry.findall(".//interface/member")
                if member is not None and member.text and member.text.strip()
            ]
            if vlan_iface and members:
                mapping[vlan_iface] = members
    else:
        members = [
            member.text.strip()
            for member in root.findall(".//result//interface/member")
            if member is not None and member.text and member.text.strip()
        ]
        if members:
            mapping["__interface_only__"] = members
    return mapping


class PaloAltoClient:
    """Client for interacting with Palo Alto devices via API."""
    def __init__(self, host: str, verify_ssl: bool, timeout: int = 10, logger: Optional[logging.Logger] = None):
        self.host = host
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.timeout = timeout
        self.logger = logger
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._client_vsys: Optional[str] = None
        self._vlan_member_cache: Dict[str, List[str]] = {}

    def _get(self, url: str) -> requests.Response:
        """Perform an HTTP GET request."""
        return self.session.get(url, timeout=self.timeout)

    def _show(self, url: str) -> requests.Response:
        """Perform an HTTP SHOW request."""
        return self.session.show(url, timeout=self.timeout)

    def keygen(self, username: str, password: str) -> str:
        """Generate an API key for Palo Alto."""
        url = (
            f"https://{self.host}/api/?type=keygen"
            f"&user={urllib.parse.quote(username, safe='')}"
            f"&password={urllib.parse.quote(password, safe='')}"
        )
        r = self._get(url)
        root = _parse_pan_xml(r.text)
        key = _find_first_text(root, ".//key")
        if not key:
            raise RuntimeError("API key not found in response.")
        return key

    def set_client_vsys(self, vsys: Optional[str]) -> None:
        """Set VSYS parameter for subsequent API calls."""

        self._client_vsys = vsys

    def get_virtual_router_for_interface(self, api_key: str, interface: str) -> str:
        """Get the virtual router for a given interface, defaulting to 'default'."""
        xpath = "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router"
        safe_chars = "/:[]@=.-'"
        quoted_xpath = urllib.parse.quote(xpath, safe=safe_chars)
        url = self._build_config_url(api_key, xpath)
        r = self._get(url)
        root = _parse_pan_xml(r.text)
        if self.logger:
            self.logger.debug(
                f"VR XML response for interface '{interface}': {ET.tostring(root, encoding='unicode')}",
                extra={"grouping": "next-hop-discovery"}
            )
        for vr in root.findall(".//virtual-router/entry"):
            vr_name = vr.get("name")
            members = [m.text.strip() for m in vr.findall(".//interface/member") if m.text and m.text.strip()]
            if interface in members:
                if self.logger:
                    self.logger.info(
                        f"Found VR '{vr_name}' for interface '{interface}'",
                        extra={"grouping": "next-hop-discovery"}
                    )
                return vr_name
        if self.logger:
            self.logger.warning(
                f"No VR found for interface '{interface}'; defaulting to 'default' virtual router",
                extra={"grouping": "next-hop-discovery"}
            )
        return "default"

    def op(self, api_key: str, cmd_xml: str) -> ET.Element:
        """Execute an operational command."""
        params = {
            "type": "op",
            "cmd": cmd_xml,
            "key": api_key,
        }
        self._inject_vsys_param(params)
        if self.logger:
            self.logger.debug(
                "Palo Alto op call cmd=%s vsys=%s",
                cmd_xml,
                params.get("vsys"),
                extra={"grouping": "layer2-discovery"},
            )
        url = f"https://{self.host}/api/"
        response = self.session.get(url, params=params, timeout=self.timeout)
        return _parse_pan_xml(response.text)

    def config_show(self, api_key: str, xpath: str) -> ET.Element:
        """Execute a config show operation for the supplied XPath."""

        params = {
            "type": "config",
            "action": "show",
            "xpath": xpath,
            "key": api_key,
        }
        self._inject_vsys_param(params)
        if self.logger:
            self.logger.debug(
                "Palo Alto config show xpath=%s vsys=%s",
                xpath,
                params.get("vsys"),
                extra={"grouping": "layer2-discovery"},
            )
        url = f"https://{self.host}/api/"
        response = self.session.get(url, params=params, timeout=self.timeout)
        return _parse_pan_xml(response.text)

    def _build_config_url(self, api_key: str, xpath: str) -> str:
        params = {
            "type": "config",
            "action": "get",
            "xpath": xpath,
            "key": api_key,
        }
        self._inject_vsys_param(params)
        query = urllib.parse.urlencode(params)
        sanitized_params = dict(params)
        if "key" in sanitized_params:
            sanitized_params["key"] = "***redacted***"
        sanitized_query = urllib.parse.urlencode(sanitized_params)
        if self.logger:
            self.logger.debug(
                "Palo Alto config request type=%s action=%s url=%s",
                params.get("type"),
                params.get("action"),
                f"https://{self.host}/api/?{sanitized_query}",
                extra={"grouping": "next-hop-discovery"},
            )
        return f"https://{self.host}/api/?{query}"

    def _inject_vsys_param(self, params: Dict[str, str]) -> None:
        """Add vsys parameter if the client is scoped."""

        if self._client_vsys:
            params.setdefault("vsys", self._client_vsys)

    def vlan_members_for_interface(self, api_key: str, vlan_if: str) -> List[str]:
        """Return physical member interfaces for a VLAN SVI."""

        cache_key = vlan_if
        if cache_key in self._vlan_member_cache:
            return list(self._vlan_member_cache[cache_key])

        base = "/config/devices/entry[@name='localhost.localdomain']"

        def _extract_members(root: ET.Element) -> List[str]:
            members = [
                member.text.strip()
                for member in root.findall(".//member")
                if member is not None and member.text and member.text.strip()
            ]
            return members

        members: List[str] = []
        vlan_name: Optional[str] = None

        # Step 1: Inspect the VLAN interface entry directly.
        try:
            iface_root = self.config_show(api_key, f"{base}/network/interface/vlan/entry[@name='{vlan_if}']")
        except RuntimeError as exc:
            iface_root = None
            if self.logger:
                self.logger.debug(
                    f"SVI lookup failed for '{vlan_if}': {exc}",
                    extra={"grouping": "layer2-discovery"},
                )

        if iface_root is not None:
            members = _extract_members(iface_root)
            vlan_name = iface_root.findtext(".//result/vlan") or vlan_if
            if members:
                self._vlan_member_cache[cache_key] = members
                return members

        candidates = [vlan_if]
        norm = vlan_if.replace("vlan.", "").replace("vlan-", "")
        if norm and norm != vlan_if:
            candidates.extend([norm, f"vlan.{norm}", f"vlan-{norm}"])

        xpath_templates = [
            "{base}/network/vlan/entry[vlan-interface='{candidate}']/interface",
            "{base}/network/vlan/entry[virtual-interface='{candidate}']/interface",
            "{base}/network/vlan/entry[@name='{candidate}']/interface",
        ]

        last_exc: Optional[Exception] = None
        for candidate in candidates:
            for template in xpath_templates:
                xpath = template.format(base=base, candidate=candidate)
                try:
                    vlan_root = self.config_show(api_key, xpath)
                except RuntimeError as exc:
                    last_exc = exc
                    continue
                members = _extract_members(vlan_root)
                if members:
                    self._vlan_member_cache[cache_key] = members
                    return members

        if vlan_name:
            for candidate in {vlan_name, f"vlan.{vlan_name}", f"vlan-{vlan_name}"}:
                try:
                    vlan_root = self.config_show(
                        api_key,
                        f"{base}/network/vlan/entry[@name='{candidate}']/interface",
                    )
                except RuntimeError as exc:
                    last_exc = exc
                    continue
                members = _extract_members(vlan_root)
                if members:
                    self._vlan_member_cache[cache_key] = members
                    return members

            # virtual-interface attribute on VLAN object (PAN-OS 10+).
            if not members:
                for candidate in {vlan_name, f"vlan.{vlan_name}", f"vlan-{vlan_name}"}:
                    try:
                        vlan_root = self.config_show(
                            api_key,
                            f"{base}/network/vlan/entry[@name='{candidate}'][virtual-interface='{vlan_if}']/interface",
                        )
                    except RuntimeError as exc:
                        last_exc = exc
                        continue
                    members = _extract_members(vlan_root)
                    if members:
                        self._vlan_member_cache[cache_key] = members
                        return members

        if self.logger and last_exc:
            self.logger.debug(
                f"VLAN member lookup failed for '{vlan_if}': {last_exc}",
                extra={"grouping": "layer2-discovery"},
            )

        self._vlan_member_cache[cache_key] = []
        return []

    def fib_lookup(self, api_key: str, vr: str, ip: str) -> Dict[str, Optional[str]]:
        """Perform a FIB lookup for the given IP."""
        cmd = f"<test><routing><fib-lookup><virtual-router>{vr}</virtual-router><ip>{ip}</ip></fib-lookup></routing></test>"
        root = self.op(api_key, cmd)
        return _extract_next_hop_bundle(root)

    def route_lookup(self, api_key: str, vr: str, ip: str) -> Dict[str, Optional[str]]:
        """Perform a route lookup for the given IP."""
        cmd = f"<test><routing><route-lookup><virtual-router>{vr}</virtual-router><ip>{ip}</ip></route-lookup></routing></test>"
        root = self.op(api_key, cmd)
        return _extract_next_hop_bundle(root)

    def get_lldp_neighbors(
        self,
        api_key: str,
        interface: Optional[str] = None,
    ) -> Dict[str, List[Dict[str, Optional[str]]]]:
        """Return LLDP neighbors, optionally filtered by interface."""

        if interface:
            safe_iface = interface.replace('"', "")
            cmd = f'<show><lldp><neighbors>"{safe_iface}"</neighbors></lldp></show>'
        else:
            cmd = "<show><lldp><neighbors>all</neighbors></lldp></show>"
        root = self.op(api_key, cmd)
        neighbors = _parse_lldp_neighbors(root)
        if self.logger:
            flattened: List[Dict[str, Optional[str]]] = []
            for entries in neighbors.values():
                flattened.extend(entries or [])
            preview = flattened[:3]
            self.logger.debug(
                "Retrieved LLDP neighbors for Palo Alto device",
                extra={
                    "grouping": "next-hop-discovery",
                    "neighbor_count": sum(len(v) for v in neighbors.values()),
                    "neighbor_preview": preview,
                },
            )
        return neighbors

    def get_arp_table(self, api_key: str) -> List[Dict[str, Optional[str]]]:
        """Return ARP table entries."""

        commands = [
            "<show><arp><entry name=\"all\"/></arp></show>",
            "<show><arp>all</arp></show>",
            "<show><arp><all/></arp></show>",
        ]
        last_exc: Optional[Exception] = None
        root: Optional[ET.Element] = None
        for cmd in commands:
            try:
                root = self.op(api_key, cmd)
                break
            except RuntimeError as exc:
                last_exc = exc
                if self.logger:
                    self.logger.debug(
                        f"ARP command '{cmd}' failed: {exc}",
                        extra={"grouping": "next-hop-discovery"},
                    )
        if root is None:
            if last_exc:
                raise last_exc
            return []
        entries = _parse_arp_entries(root)
        if self.logger:
            self.logger.debug(
                "Retrieved ARP table for Palo Alto device",
                extra={
                    "grouping": "next-hop-discovery",
                    "entry_count": len(entries),
                    "entry_preview": entries[:5],
                },
            )
        return entries

    def get_mac_table(self, api_key: str) -> List[Dict[str, Optional[str]]]:
        """Return MAC address table entries."""

        commands = [
            "<show><mac>all</mac></show>",
            "<show><mac><entry name=\"all\"/></mac></show>",
            "<show><mac><all/></mac></show>",
        ]
        last_exc: Optional[Exception] = None
        root: Optional[ET.Element] = None
        for cmd in commands:
            try:
                root = self.op(api_key, cmd)
                break
            except RuntimeError as exc:
                last_exc = exc
                if self.logger:
                    self.logger.debug(
                        f"MAC command '{cmd}' failed: {exc}",
                        extra={"grouping": "layer2-discovery"},
                    )
        if root is None:
            if last_exc:
                raise last_exc
            return []
        entries = _parse_mac_entries(root)
        if self.logger:
            self.logger.debug(
                "Retrieved MAC table for Palo Alto device",
                extra={
                    "grouping": "layer2-discovery",
                    "entry_count": len(entries),
                    "entry_preview": entries[:5],
                },
            )
        return entries
