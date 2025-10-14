"""Palo Alto API client for next-hop lookups."""

from __future__ import annotations

import re
import urllib.parse
import urllib3
import requests
import xml.etree.ElementTree as ET
from collections import defaultdict
from typing import Optional, Dict, Iterable, Sequence, List


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


def _extract_result_text(root: ET.Element) -> str:
    result_node = root.find(".//result")
    if result_node is None:
        return ""
    text = ET.tostring(result_node, encoding="unicode", method="text")
    return text or ""


def _parse_interface_cli_output(text: str) -> Dict[str, Dict[str, object]]:
    stats: Dict[str, Dict[str, object]] = {}
    current: Optional[str] = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("-"):
            continue

        header = re.match(r"^(?:Name|Interface)\s*:?\s*([^,]+)", line, re.IGNORECASE)
        if header:
            name = header.group(1).strip()
            current = name.lower()
            stats.setdefault(current, {"name": name})
            continue

        if current is None:
            continue

        runtime = re.match(
            r"^Runtime link speed/duplex/state:\s*(\d+)(?:/[^/]*)?/(up|down)",
            line,
            re.IGNORECASE,
        )
        if runtime:
            _assign_stat(stats[current], "speed_mbps", _safe_int(runtime.group(1)))
            _assign_bool(stats[current], "oper_up", runtime.group(2).lower() == "up")
            continue

        mtu_match = re.match(r"^Interface MTU\s+(\d+)", line, re.IGNORECASE)
        if mtu_match:
            _assign_stat(stats[current], "mtu", _safe_int(mtu_match.group(1)))
            continue

        mac_match = re.match(r"^(?:Port )?MAC(?:\s+address)?\s+([0-9a-f:\.-]{12,})", line, re.IGNORECASE)
        if mac_match:
            _assign_text(stats[current], "mac", mac_match.group(1))
            continue

        for pattern, key in _COUNTER_PATTERNS:
            match = pattern.match(line)
            if match:
                _assign_stat(stats[current], key, _safe_int(match.group(1)))
                break

    return stats


def _merge_parsed_stats(dest: Dict[str, Dict[str, object]], source: Dict[str, Dict[str, object]]) -> None:
    for name_lower, data in source.items():
        target = dest.setdefault(name_lower, {})
        if "name" in data:
            target.setdefault("name", data["name"])
        for key, value in data.items():
            if key == "name" or value is None:
                continue
            if isinstance(value, bool):
                if key not in target or target[key] is None:
                    target[key] = value
                elif value:
                    target[key] = True
                continue
            if isinstance(value, int):
                existing = target.get(key)
                if existing is None or not isinstance(existing, int) or value > existing:
                    target[key] = value
                continue
            target.setdefault(key, value)


COUNTER_PATTERNS = [
    (re.compile(r"^rx\s+bytes\s+(\d+)$", re.IGNORECASE), "rx_bytes"),
    (re.compile(r"^tx\s+bytes\s+(\d+)$", re.IGNORECASE), "tx_bytes"),
    (re.compile(r"^rx\s+unicast\s+packets\s+(\d+)$", re.IGNORECASE), "rx_unicast"),
    (re.compile(r"^tx\s+unicast\s+packets\s+(\d+)$", re.IGNORECASE), "tx_unicast"),
    (re.compile(r"^rx\s+errors\s+(\d+)$", re.IGNORECASE), "rx_errors"),
    (re.compile(r"^tx\s+errors\s+(\d+)$", re.IGNORECASE), "tx_errors"),
    (re.compile(r"^rx\s+drops\s+(\d+)$", re.IGNORECASE), "rx_discards"),
    (re.compile(r"^tx\s+drops\s+(\d+)$", re.IGNORECASE), "tx_discards"),
    (re.compile(r"^rx-bytes\s+(\d+)$", re.IGNORECASE), "rx_bytes"),
    (re.compile(r"^tx-bytes\s+(\d+)$", re.IGNORECASE), "tx_bytes"),
    (re.compile(r"^bytes\s+received\s+(\d+)$", re.IGNORECASE), "rx_bytes"),
    (re.compile(r"^bytes\s+transmitted\s+(\d+)$", re.IGNORECASE), "tx_bytes"),
    (re.compile(r"^packets\s+received\s+(\d+)$", re.IGNORECASE), "rx_unicast"),
    (re.compile(r"^packets\s+transmitted\s+(\d+)$", re.IGNORECASE), "tx_unicast"),
    (re.compile(r"^receive\s+incoming\s+errors\s+(\d+)$", re.IGNORECASE), "rx_errors"),
    (re.compile(r"^receive\s+errors\s+(\d+)$", re.IGNORECASE), "rx_errors"),
    (re.compile(r"^transmit\s+errors\s+(\d+)$", re.IGNORECASE), "tx_errors"),
    (re.compile(r"^receive\s+discarded\s+(\d+)$", re.IGNORECASE), "rx_discards"),
    (re.compile(r"^packets\s+dropped\s+(\d+)$", re.IGNORECASE), "rx_discards"),
    (re.compile(r"^drops-in\s+(\d+)$", re.IGNORECASE), "rx_discards"),
    (re.compile(r"^drops-out\s+(\d+)$", re.IGNORECASE), "tx_discards"),
]


def _assign_stat(bucket: Dict[str, object], key: str, value: Optional[int]) -> None:
    if value is None:
        return
    existing = bucket.get(key)
    if existing is None or not isinstance(existing, int) or value > existing:
        bucket[key] = value


def _assign_bool(bucket: Dict[str, object], key: str, value: Optional[bool]) -> None:
    if value is None:
        return
    existing = bucket.get(key)
    if existing is None:
        bucket[key] = value
    elif value:
        bucket[key] = True


def _assign_text(bucket: Dict[str, object], key: str, value: str) -> None:
    if value:
        bucket.setdefault(key, value)


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

    def get_interface_statistics(self, api_key: str, interfaces: Sequence[str]) -> Dict[str, Dict[str, object]]:
        """Return interface statistics for the requested logical interfaces."""
        if not interfaces:
            return {}

        normalized: Dict[str, Dict[str, object]] = defaultdict(dict)
        errors: Dict[str, List[str]] = defaultdict(list)

        def _run_and_merge(cmd: str, *, record_error: Optional[str] = None) -> None:
            try:
                root = self.op(api_key, cmd)
            except RuntimeError as exc:
                if record_error:
                    message = str(exc)
                    if message not in errors[record_error]:
                        errors[record_error].append(message)
                return

            xml_stats = _parse_interface_xml(root)
            if xml_stats:
                _merge_parsed_stats(normalized, xml_stats)
                return

            text = _extract_result_text(root)
            if text:
                cli_stats = _parse_interface_cli_output(text)
                if cli_stats:
                    _merge_parsed_stats(normalized, cli_stats)

        # Bulk overview (equivalent to 'show interface all')
        _run_and_merge("<show><interface>all</interface></show>")
        # Hardware overview can include additional counters
        _run_and_merge("<show><interface><hardware>all</hardware></interface></show>")

        commands = (
            "<show><interface>{}</interface></show>",
            "<show><interface>all</interface></show>",
        )

        for interface in interfaces:
            iface_lower = interface.lower()
            for template in commands:
                if normalized.get(iface_lower):
                    break
                cmd = template.format(interface)
                _run_and_merge(cmd, record_error=None if normalized.get(iface_lower) else interface)
                if normalized.get(iface_lower):
                    errors.pop(interface, None)
                    break
            if not normalized.get(iface_lower):
                # Try the hardware overview once more to ensure stats exist
                _run_and_merge("<show><interface><hardware>all</hardware></interface></show>")
                if normalized.get(iface_lower):
                    errors.pop(interface, None)

        result: Dict[str, Dict[str, object]] = {}
        for interface in interfaces:
            iface_lower = interface.lower()
            data = dict(normalized.get(iface_lower, {}))
            if data:
                data["name"] = interface
                result[interface] = data
            elif errors.get(interface):
                result[interface] = {
                    "error": "; ".join(errors[interface]),
                    "error_type": "RuntimeError",
                }
            else:
                result[interface] = {}

        return result


def _coerce_int(text: Optional[str]) -> Optional[int]:
    if text is None:
        return None
    try:
        return int(text.replace(",", "").strip())
    except (ValueError, AttributeError):
        return None


def _coerce_bool(text: Optional[str]) -> Optional[bool]:
    if text is None:
        return None
    value = text.strip().lower()
    if value in {"up", "true", "enabled", "yes", "on"}:
        return True
    if value in {"down", "false", "disabled", "no", "off"}:
        return False
    return None


def _parse_interface_xml(root: ET.Element) -> Dict[str, Dict[str, object]]:
    stats: Dict[str, Dict[str, object]] = {}
    for entry in root.findall(".//ifnet/entry"):
        name = (entry.get("name") or entry.findtext("name") or "").strip()
        if not name:
            continue
        key = name.lower()
        bucket = stats.setdefault(key, {"name": name})

        _assign_bool(bucket, "oper_up", _coerce_bool(entry.findtext("state")))
        _assign_stat(bucket, "speed_mbps", _coerce_int(entry.findtext("speed")))
        mac_val = (entry.findtext("mac") or entry.findtext("hwaddr") or "").strip()
        if mac_val:
            _assign_text(bucket, "mac", mac_val)
            _assign_text(bucket, "mac_address", mac_val)
        _assign_stat(bucket, "mtu", _coerce_int(entry.findtext("mtu")))

        counters = entry.find("counters")
        if counters is not None:
            def counter(*tags: str) -> Optional[int]:
                for tag in tags:
                    value = counters.findtext(tag)
                    if value is not None:
                        parsed = _coerce_int(value)
                        if parsed is not None:
                            return parsed
                return None

            _assign_stat(bucket, "rx_bytes", counter("byte-in", "bytes-in", "rx-bytes"))
            _assign_stat(bucket, "tx_bytes", counter("byte-out", "bytes-out", "tx-bytes"))
            _assign_stat(bucket, "rx_unicast", counter("pkt-in-unicast", "packets-in-unicast", "rx-unicast", "packets-in"))
            _assign_stat(bucket, "tx_unicast", counter("pkt-out-unicast", "packets-out-unicast", "tx-unicast", "packets-out"))
            _assign_stat(bucket, "rx_errors", counter("err-in", "errors-in", "rx-errors"))
            _assign_stat(bucket, "tx_errors", counter("err-out", "errors-out", "tx-errors"))
            _assign_stat(bucket, "rx_discards", counter("drop-in", "drops-in", "rx-drops", "discard-in"))
            _assign_stat(bucket, "tx_discards", counter("drop-out", "drops-out", "tx-drops", "discard-out"))

    return stats


def _extract_result_text(root: ET.Element) -> str:
    result_node = root.find(".//result")
    if result_node is None:
        return ""
    text = ET.tostring(result_node, encoding="unicode", method="text")
    return text or ""


def _parse_interface_cli_output(text: str) -> Dict[str, Dict[str, object]]:
    stats: Dict[str, Dict[str, object]] = {}
    current: Optional[str] = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("-"):
            continue

        header = re.match(r"^(?:Name|Interface)\s*:?\s*([^,]+)", line, re.IGNORECASE)
        if header:
            name = header.group(1).strip()
            current = name.lower()
            stats.setdefault(current, {"name": name})
            continue

        if current is None:
            continue

        runtime = re.match(
            r"^Runtime link speed/duplex/state:\s*(\d+)(?:/[^/]*)?/(up|down)",
            line,
            re.IGNORECASE,
        )
        if runtime:
            _assign_stat(stats[current], "speed_mbps", _coerce_int(runtime.group(1)))
            _assign_bool(stats[current], "oper_up", runtime.group(2).lower() == "up")
            continue

        mtu_match = re.match(r"^Interface MTU\s+(\d+)", line, re.IGNORECASE)
        if mtu_match:
            _assign_stat(stats[current], "mtu", _coerce_int(mtu_match.group(1)))
            continue

        mac_match = re.match(r"^(?:Port\s+)?MAC(?:\s+address)?\s+([0-9A-Fa-f:\.-]{12,})", line, re.IGNORECASE)
        if mac_match:
            _assign_text(stats[current], "mac", mac_match.group(1))
            _assign_text(stats[current], "mac_address", mac_match.group(1))
            continue

        for pattern, key in COUNTER_PATTERNS:
            match = pattern.match(line)
            if match:
                _assign_stat(stats[current], key, _coerce_int(match.group(1)))
                break

    return stats


def _merge_parsed_stats(dest: Dict[str, Dict[str, object]], source: Dict[str, Dict[str, object]]) -> None:
    for name_lower, data in source.items():
        target = dest.setdefault(name_lower, {})
        if "name" in data:
            target.setdefault("name", data["name"])
        for key, value in data.items():
            if key == "name" or value is None:
                continue
            if isinstance(value, bool):
                if key not in target or target[key] is None:
                    target[key] = value
                elif value:
                    target[key] = True
                continue
            if isinstance(value, int):
                existing = target.get(key)
                if existing is None or not isinstance(existing, int) or value > existing:
                    target[key] = value
                continue
            target.setdefault(key, value)


COUNTER_PATTERNS = [
    (re.compile(r"^RX\s+Bytes\s+(\d+)$", re.IGNORECASE), "rx_bytes"),
    (re.compile(r"^TX\s+Bytes\s+(\d+)$", re.IGNORECASE), "tx_bytes"),
    (re.compile(r"^RX\s+Unicast\s+Packets\s+(\d+)$", re.IGNORECASE), "rx_unicast"),
    (re.compile(r"^TX\s+Unicast\s+Packets\s+(\d+)$", re.IGNORECASE), "tx_unicast"),
    (re.compile(r"^RX\s+Errors\s+(\d+)$", re.IGNORECASE), "rx_errors"),
    (re.compile(r"^TX\s+Errors\s+(\d+)$", re.IGNORECASE), "tx_errors"),
    (re.compile(r"^RX\s+(?:Drops|Discard(?:ed)?)\s+(\d+)$", re.IGNORECASE), "rx_discards"),
    (re.compile(r"^TX\s+(?:Drops|Discard(?:ed)?)\s+(\d+)$", re.IGNORECASE), "tx_discards"),
    (re.compile(r"^rx-bytes\s+(\d+)$", re.IGNORECASE), "rx_bytes"),
    (re.compile(r"^tx-bytes\s+(\d+)$", re.IGNORECASE), "tx_bytes"),
    (re.compile(r"^rx-unicast\s+(\d+)$", re.IGNORECASE), "rx_unicast"),
    (re.compile(r"^tx-unicast\s+(\d+)$", re.IGNORECASE), "tx_unicast"),
    (re.compile(r"^bytes\s+received\s+(\d+)$", re.IGNORECASE), "rx_bytes"),
    (re.compile(r"^bytes\s+transmitted\s+(\d+)$", re.IGNORECASE), "tx_bytes"),
    (re.compile(r"^packets\s+received\s+(\d+)$", re.IGNORECASE), "rx_unicast"),
    (re.compile(r"^packets\s+transmitted\s+(\d+)$", re.IGNORECASE), "tx_unicast"),
    (re.compile(r"^receive\s+incoming\s+errors\s+(\d+)$", re.IGNORECASE), "rx_errors"),
    (re.compile(r"^receive\s+errors\s+(\d+)$", re.IGNORECASE), "rx_errors"),
    (re.compile(r"^transmit\s+errors\s+(\d+)$", re.IGNORECASE), "tx_errors"),
    (re.compile(r"^receive\s+discarded\s+(\d+)$", re.IGNORECASE), "rx_discards"),
    (re.compile(r"^packets\s+dropped\s+(\d+)$", re.IGNORECASE), "rx_discards"),
    (re.compile(r"^drops-in\s+(\d+)$", re.IGNORECASE), "rx_discards"),
    (re.compile(r"^drops-out\s+(\d+)$", re.IGNORECASE), "tx_discards"),
]


def _assign_stat(bucket: Dict[str, object], key: str, value: Optional[int]) -> None:
    if value is None:
        return
    existing = bucket.get(key)
    if existing is None or not isinstance(existing, int) or value > existing:
        bucket[key] = value


def _assign_bool(bucket: Dict[str, object], key: str, value: bool) -> None:
    existing = bucket.get(key)
    if existing is None:
        bucket[key] = value
    elif value:
        bucket[key] = True


def _assign_text(bucket: Dict[str, object], key: str, value: str) -> None:
    if value:
        bucket.setdefault(key, value)
