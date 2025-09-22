"""Palo Alto API client for next-hop lookups."""

from __future__ import annotations

import urllib.parse
import urllib3
import requests
import xml.etree.ElementTree as ET
from typing import Optional, Dict


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


def _find_first_text(root: ET.Element, *xpaths: str) -> Optional[str]:
    """Find the first non-empty text in the given xpaths."""
    for xp in xpaths:
        el = root.find(xp)
        if el is not None and el.text and el.text.strip():
            return el.text.strip()
    return None


def _extract_next_hop_bundle(root: ET.Element) -> Dict[str, Optional[str]]:
    """Extract next-hop and egress interface from XML."""
    nh = _find_first_text(
        root, ".//nexthop", ".//nexthop-ip", ".//ip-next-hop", ".//via", ".//gw"
    )
    egress = _find_first_text(
        root, ".//egress-interface", ".//egress-if", ".//interface", ".//egress", ".//oif"
    )
    return {"next_hop": nh, "egress_interface": egress}


class PaloAltoClient:
    """Client for interacting with Palo Alto devices via API."""
    def __init__(self, host: str, verify_ssl: bool, timeout: int = 10):
        self.host = host
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.timeout = timeout
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

    def get_virtual_router_for_interface(self, api_key: str, interface: str) -> Optional[str]:
        """Get the virtual router for a given interface."""
        xpath = "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router"
        url = f"https://{self.host}/api/?type=config&action=get&xpath={urllib.parse.quote(xpath)}&key={api_key}"
        r = self._get(url)
        root = _parse_pan_xml(r.text)
        for vr in root.findall(".//virtual-router/entry"):
            vr_name = vr.get("name")
            members = [m.text.strip() for m in vr.findall(".//interface/member") if m.text]
            if interface in members:
                return vr_name
        return None

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