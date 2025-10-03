"""Palo Alto API client for next-hop lookups."""

from __future__ import annotations

import urllib.parse
import urllib3
import requests
import xml.etree.ElementTree as ET
from typing import Optional, Dict, Iterable


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

    def _get(self, url: str) -> requests.Response:
        """Perform an HTTP GET request."""
        return self.session.get(url, timeout=self.timeout)

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

    def get_virtual_router_for_interface(self, api_key: str, interface: str) -> str:
        """Get the virtual router for a given interface, defaulting to 'default'."""
        xpath = "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router"
        safe_chars = "/:[]@=.-'"
        quoted_xpath = urllib.parse.quote(xpath, safe=safe_chars)
        url = (
            f"https://{self.host}/api/?type=config&action=show"
            f"&xpath={quoted_xpath}"
            f"&key={api_key}"
        )
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
        url = f"https://{self.host}/api/?type=op&cmd={urllib.parse.quote(cmd_xml)}&key={api_key}"
        return _parse_pan_xml(self._get(url).text)

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
