"""Palo Alto API client for next-hop lookups."""

from __future__ import annotations

import ipaddress
import logging
import re
import time
import urllib.parse
import urllib3
import requests
import xml.etree.ElementTree as ET
from typing import List, Optional, Dict, Iterable, Any

from ..exceptions import FirewallLogCheckError


def _parse_pan_xml(text: str) -> ET.Element:
    """Parse XML response from Palo Alto API."""
    root = ET.fromstring(text)
    status = root.get("status")
    if status == "error":
        msg_candidates = (
            root.findtext(".//line"),
            root.findtext(".//message"),
            root.findtext(".//msg"),
        )
        msg = next((candidate.strip() for candidate in msg_candidates if candidate and candidate.strip()), "Unknown error")
        raise RuntimeError(f"Palo Alto API error: {msg}")
    return root


_PAN_API_KEY_QUERY_RE = re.compile(r"(\bkey=)[^&\s]+")


def _redact_pan_api_key(text: str, api_key: Optional[str] = None) -> str:
    """Redact API key material from arbitrary strings (URLs, exception messages)."""

    redacted = _PAN_API_KEY_QUERY_RE.sub(r"\1***redacted***", text)
    if api_key:
        redacted = redacted.replace(api_key, "***redacted***")
    return redacted


def _sanitize_pan_api_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """Return a shallow copy of params with secrets redacted."""

    sanitized: Dict[str, Any] = dict(params)
    if "key" in sanitized:
        sanitized["key"] = "***redacted***"
    return sanitized


def _safe_port(value: Any) -> int:
    """Return a validated destination port integer in [0, 65535]."""

    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise FirewallLogCheckError(f"Invalid destination port '{value}' (expected integer 0-65535).") from exc
    if port < 0 or port > 65535:
        raise FirewallLogCheckError(f"Invalid destination port '{port}' (expected integer 0-65535).")
    return port


def _safe_ip_literal(value: Any, *, field: str) -> str:
    """Return a validated IPv4/IPv6 literal string."""

    if value is None:
        raise FirewallLogCheckError(f"Invalid {field} IP: value is required.")
    raw = str(value).strip()
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError as exc:
        raise FirewallLogCheckError(f"Invalid {field} IP '{raw}'.") from exc


def _safe_positive_int(value: Any, *, field: str) -> int:
    """Return a validated positive integer (>=1)."""

    try:
        integer_value = int(value)
    except (TypeError, ValueError) as exc:
        raise FirewallLogCheckError(f"Invalid {field} '{value}' (expected integer).") from exc
    if integer_value < 1:
        raise FirewallLogCheckError(f"Invalid {field} '{integer_value}' (expected >= 1).")
    return integer_value


_PROTO_MAP = {
    "6": "tcp",
    "17": "udp",
    "1": "icmp",
}


def _normalize_proto(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    candidate = value.strip().lower()
    if not candidate:
        return None
    if candidate.isdigit():
        return _PROTO_MAP.get(candidate, candidate)
    return candidate


def _safe_int_or_none(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    try:
        return int(candidate)
    except ValueError:
        return None


def _find_traffic_logs_node(root: ET.Element) -> Optional[ET.Element]:
    """Locate the <logs> node in a log query response."""

    for xp in (
        ".//result/log/logs",
        ".//result//log//logs",
        ".//log/logs",
    ):
        node = root.find(xp)
        if node is not None:
            return node
    return None


def _parse_traffic_log_entries(root: ET.Element) -> List[Dict[str, Any]]:
    """Parse traffic log <entry> elements into normalized dicts."""

    logs_node = _find_traffic_logs_node(root)
    if logs_node is None:
        return []

    entries: List[Dict[str, Any]] = []
    for entry in logs_node.findall("./entry"):
        timestamp = _find_first_text(entry, "./receive_time", ".//receive_time", "./time_generated", ".//time_generated")
        action = _find_first_text(entry, "./action", ".//action")
        source_ip = _find_first_text(entry, "./src", ".//src")
        destination_ip = _find_first_text(entry, "./dst", ".//dst")
        protocol = _normalize_proto(_find_first_text(entry, "./proto", ".//proto", "./protocol", ".//protocol"))
        destination_port = _safe_int_or_none(_find_first_text(entry, "./dport", ".//dport", "./dstport", ".//dstport"))
        rule = _find_first_text(entry, "./rule", ".//rule")
        app = _find_first_text(entry, "./app", ".//app")
        device_serial = _find_first_text(entry, "./serial", ".//serial")
        device_name = _find_first_text(entry, "./device_name", ".//device_name")
        session_end_reason = _find_first_text(entry, "./session_end_reason", ".//session_end_reason")

        entries.append(
            {
                "timestamp": timestamp,
                "action": action,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "protocol": protocol,
                "destination_port": destination_port,
                "rule": rule,
                "app": app,
                "device_serial": device_serial,
                "device_name": device_name,
                "session_end_reason": session_end_reason,
            }
        )
    return entries


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

    def traffic_logs_query(
        self,
        api_key: str,
        *,
        query: str,
        nlogs: int = 10,
        max_wait_seconds: int = 30,
    ) -> List[Dict[str, Any]]:
        """Query Panorama traffic logs via the XML API (type=log&log-type=traffic).

        Handles both synchronous responses and async job-id polling.
        """

        if not isinstance(query, str) or not query.strip():
            raise FirewallLogCheckError("Traffic log query must be a non-empty string.")

        nlogs_int = _safe_positive_int(nlogs, field="nlogs")
        max_wait_int = _safe_positive_int(max_wait_seconds, field="max_wait_seconds")

        submit_params: Dict[str, Any] = {
            "type": "log",
            "log-type": "traffic",
            "query": query,
            "nlogs": str(nlogs_int),
            "skip": "0",
            "dir": "backward",
            "key": api_key,
        }

        url = f"https://{self.host}/api/"
        if self.logger:
            self.logger.debug(
                "Panorama traffic log query submit params=%s",
                _sanitize_pan_api_params(submit_params),
                extra={"grouping": "firewall-log-check"},
            )

        try:
            response = self.session.get(url, params=submit_params, timeout=self.timeout)
        except requests.RequestException as exc:
            raise FirewallLogCheckError(
                f"Panorama traffic log query failed: {_redact_pan_api_key(str(exc), api_key=api_key)}"
            ) from exc

        if response.status_code >= 400:
            raise FirewallLogCheckError(f"Panorama traffic log query failed: HTTP {response.status_code}.")

        try:
            root = _parse_pan_xml(response.text)
        except ET.ParseError as exc:
            raise FirewallLogCheckError(f"Panorama traffic log query failed: malformed XML ({exc}).") from exc
        except RuntimeError as exc:
            raise FirewallLogCheckError(_redact_pan_api_key(str(exc), api_key=api_key)) from exc

        job_id = _find_first_text(root, ".//result/job", ".//job")
        if job_id:
            return self._poll_traffic_log_job(api_key, job_id, max_wait_seconds=max_wait_int)

        logs_node = _find_traffic_logs_node(root)
        if logs_node is None:
            if self.logger:
                self.logger.debug(
                    "Unexpected Panorama log query response (no job id, no logs node).",
                    extra={"grouping": "firewall-log-check"},
                )
            raise FirewallLogCheckError("Panorama traffic log query returned an unexpected response.")

        entries = _parse_traffic_log_entries(root)
        if self.logger:
            self.logger.debug(
                "Panorama traffic log query completed count=%s entries=%s",
                logs_node.get("count"),
                len(entries),
                extra={"grouping": "firewall-log-check"},
            )
        return entries

    def traffic_logs_deny_for_flow(
        self,
        api_key: str,
        *,
        src_ip: str,
        dst_ip: str,
        dst_port: Any,
        since_hours: int = 24,
        max_results: int = 10,
        max_wait_seconds: int = 30,
        fetch_limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Query last-N-hours DENY traffic logs for an exact src/dst/dport flow."""

        safe_src = _safe_ip_literal(src_ip, field="source")
        safe_dst = _safe_ip_literal(dst_ip, field="destination")
        safe_port = _safe_port(dst_port)
        safe_hours = _safe_positive_int(since_hours, field="since_hours")
        safe_max = _safe_positive_int(max_results, field="max_results")

        safe_fetch = safe_max
        if fetch_limit is not None:
            safe_fetch = _safe_positive_int(fetch_limit, field="fetch_limit")

        query = (
            f"(receive_time in last-{safe_hours}-hrs) "
            f"and (addr.src in {safe_src}) "
            f"and (addr.dst in {safe_dst}) "
            f"and (dport eq {safe_port})"
        )
        entries = self.traffic_logs_query(
            api_key,
            query=query,
            nlogs=safe_fetch,
            max_wait_seconds=max_wait_seconds,
        )
        deny_entries = [
            entry
            for entry in entries
            if (entry.get("action") or "").strip().lower() == "deny"
        ]
        return deny_entries[:safe_max]

    def _poll_traffic_log_job(
        self,
        api_key: str,
        job_id: str,
        *,
        max_wait_seconds: int = 30,
    ) -> List[Dict[str, Any]]:
        """Poll a Panorama log query job until complete or timeout."""

        started = time.monotonic()
        poll_interval = 1.0

        while True:
            root = self._get_traffic_log_job_results(api_key, job_id)
            logs_node = _find_traffic_logs_node(root)

            progress: Optional[int] = None
            if logs_node is not None:
                progress_text = (logs_node.get("progress") or "").strip()
                if progress_text.isdigit():
                    progress = int(progress_text)
                elif progress_text:
                    try:
                        progress = int(float(progress_text))
                    except ValueError:
                        progress = None

            if self.logger:
                self.logger.debug(
                    "Panorama traffic log query job poll job_id=%s progress=%s count=%s",
                    job_id,
                    progress_text if logs_node is not None else None,
                    logs_node.get("count") if logs_node is not None else None,
                    extra={"grouping": "firewall-log-check"},
                )

            if progress is None and logs_node is not None:
                progress = 100

            if progress is not None and progress >= 100:
                return _parse_traffic_log_entries(root)

            if (time.monotonic() - started) >= max_wait_seconds:
                entries = _parse_traffic_log_entries(root)
                if entries:
                    if self.logger:
                        self.logger.debug(
                            "Panorama traffic log query timed out but returned partial results job_id=%s progress=%s count=%s entries=%s",
                            job_id,
                            logs_node.get("progress") if logs_node is not None else None,
                            logs_node.get("count") if logs_node is not None else None,
                            len(entries),
                            extra={"grouping": "firewall-log-check"},
                        )
                    return entries

                raise FirewallLogCheckError(
                    f"Panorama traffic log query timed out after {max_wait_seconds} seconds (job {job_id})."
                )

            time.sleep(poll_interval)
            poll_interval = 2.0

    def _get_traffic_log_job_results(self, api_key: str, job_id: str) -> ET.Element:
        """Fetch log query results for a Panorama job-id (action=get)."""

        params: Dict[str, Any] = {
            "type": "log",
            "action": "get",
            "job-id": job_id,
            "key": api_key,
        }
        url = f"https://{self.host}/api/"
        if self.logger:
            self.logger.debug(
                "Panorama traffic log query get params=%s",
                _sanitize_pan_api_params(params),
                extra={"grouping": "firewall-log-check"},
            )

        try:
            response = self.session.get(url, params=params, timeout=self.timeout)
        except requests.RequestException as exc:
            raise FirewallLogCheckError(
                f"Panorama traffic log query failed: {_redact_pan_api_key(str(exc), api_key=api_key)}"
            ) from exc

        if response.status_code >= 400:
            raise FirewallLogCheckError(f"Panorama traffic log query failed: HTTP {response.status_code}.")

        try:
            return _parse_pan_xml(response.text)
        except ET.ParseError as exc:
            raise FirewallLogCheckError(f"Panorama traffic log query failed: malformed XML ({exc}).") from exc
        except RuntimeError as exc:
            raise FirewallLogCheckError(_redact_pan_api_key(str(exc), api_key=api_key)) from exc
