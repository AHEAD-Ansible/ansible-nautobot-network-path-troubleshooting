#!/usr/bin/env python3
"""
PAN-OS interface stats smoke test (single interface) — v7

- Auth: keygen
- Base stats: "show interface all" + "show interface <iface>" (XML-only)
- Advanced/PHY: "show system state filter-pretty sys.sX.pY.stats" (fallback to detail)
- FIX: robust parser for brace-wrapped single-line pretty output
- Prefers hardware counters over XML (bytes/packets)
- Exposes rx/tx broadcast & multicast, rx_missed_errors
- Keeps full hardware dict under 'hw_raw'
- Optional heuristic to set oper_up=True if XML lacks a link flag but counters tick
"""

import json
import re
import sys
import textwrap
import xml.etree.ElementTree as ET
from typing import Optional, Dict

import requests
from urllib3.exceptions import InsecureRequestWarning

# =================== EDIT THESE ===================
FW_HOST    = "192.168.100.76"
USERNAME   = "admin-ro"
PASSWORD   = "Labl@b!234"
INTERFACE  = "ethernet1/7"      # e.g., ethernet1/7
VERIFY_SSL = False              # True if you have proper CA
TIMEOUT_S  = 10
TARGET     = None               # Panorama device serial, e.g. "007123004567"
INCLUDE_HW = True               # pull sys.sX.pY stats
HEURISTIC_OPER_UP = True        # set oper_up=True if XML lacks link flag but counters > 0
DEBUG      = True               # print short debug snippets
# ==================================================

def _to_int(v: Optional[str]) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(str(v).replace(",", "").strip())
    except Exception:
        return None

def _short(label: str, text: str):
    if not DEBUG:
        return
    s = textwrap.shorten(" ".join(text.split()), width=420, placeholder=" …")
    print(f"[debug] {label}: {s}")

def get_key(host: str, user: str, password: str) -> str:
    r = requests.get(
        f"https://{host}/api/",
        params={"type": "keygen", "user": user, "password": password},
        verify=VERIFY_SSL, timeout=TIMEOUT_S,
    )
    r.raise_for_status()
    root = ET.fromstring(r.text)
    key = root.findtext(".//key")
    if not key:
        raise RuntimeError(f"keygen failed: {r.text}")
    return key

def op(host: str, key: str, cmd_xml: str) -> ET.Element:
    params = {"type": "op", "cmd": cmd_xml, "key": key}
    if TARGET:
        params["target"] = TARGET
    r = requests.get(
        f"https://{host}/api/",
        params=params,
        verify=VERIFY_SSL, timeout=TIMEOUT_S,
    )
    r.raise_for_status()
    root = ET.fromstring(r.text)
    if root.get("status") != "success":
        raise RuntimeError(f"op error: {r.text}")
    return root

# ------------------------- XML mining -------------------------
def _tag(el: ET.Element) -> str:
    return el.tag.split("}", 1)[-1].lower()

def _collect_values(el: ET.Element) -> Dict[str, str]:
    vals: Dict[str, str] = {}
    for node in el.iter():
        k = _tag(node)
        if not k or k in {"response", "result"}:
            continue
        t = (node.text or "").strip()
        if t and k not in vals:
            vals[k] = t
    return vals

def _pick(vals: Dict[str, str], *keys: str) -> Optional[str]:
    for k in keys:
        if k in vals and vals[k]:
            return vals[k]
    return None

def parse_any_interface_xml(root: ET.Element, iface: str) -> Dict[str, object]:
    result = root.find(".//result")
    if result is None:
        return {}

    # Scoped subtree for our interface
    candidates = result.findall(f".//*[@name='{iface}']")
    if not candidates:
        for n in result.findall(".//*"):
            if (n.findtext("name") or "").strip().lower() == iface.lower():
                candidates.append(n)
    if not candidates:
        candidates = [result]

    candidates.sort(key=lambda e: sum(1 for _ in e.iter()), reverse=True)
    best = candidates[0]

    vals = _collect_values(best)
    _short("xml_vals", json.dumps(vals)[:800])

    out: Dict[str, object] = {"name": iface}

    # State (if present)
    state = _pick(vals, "state", "link", "status", "oper-state", "runtime-state")
    if state:
        out["state"] = state
        out["oper_up"] = state.strip().lower() == "up"

    # Admin/config state if present
    cfg_state = _pick(vals, "configured-state", "admin-state", "admin")
    if cfg_state:
        out["admin_up"] = cfg_state.strip().lower() != "down"

    # Duplex/speed/MTU/MAC variants
    duplex = _pick(vals, "duplex")
    if duplex:
        out["duplex"] = duplex

    out["speed_mbps"] = _to_int(_pick(vals, "speed", "link-speed", "speed-mbps"))
    out["mtu"]        = _to_int(_pick(vals, "mtu", "adjust-mtu"))

    mac = _pick(vals, "mac", "macaddr", "hwaddr", "mac-address")
    if mac:
        out["mac"] = mac
        out["mac_address"] = mac

    # Generic counters (ibytes/obytes/ipackets/opackets/etc.)
    def c(*names): return _to_int(_pick(vals, *names))

    out["rx_bytes"]   = c("ibytes", "byte-in", "bytes-in", "rx-bytes", "rx_bytes", "bytes-received")
    out["tx_bytes"]   = c("obytes", "byte-out", "bytes-out", "tx-bytes", "tx_bytes", "bytes-transmitted")

    out["rx_unicast"] = c("ipackets", "pkt-in-unicast", "packets-in-unicast", "rx-unicast", "packets-received")
    out["tx_unicast"] = c("opackets", "pkt-out-unicast","packets-out-unicast","tx-unicast","packets-transmitted")

    out["rx_errors"]  = c("ierrors", "err-in", "errors-in", "rx-errors")
    out["tx_errors"]  = c("oerrors", "err-out","errors-out","tx-errors")

    out["rx_discards"] = c("ifwderrors", "drop-in","drops-in","rx-drops","rx-discards")
    out["tx_discards"] = c("ofwderrors", "drop-out","drops-out","tx-drops","tx-discards")

    return {k: v for k, v in out.items() if v is not None}

# ------------------ Advanced hardware counters ------------------
def _iface_to_slot_port(iface: str):
    # "ethernet1/7" -> ("s1", "p7") for fixed-chassis
    m = re.match(r"^ethernet(\d+)\/(\d+)$", iface, re.IGNORECASE)
    if not m:
        return None
    return f"s{int(m.group(1))}", f"p{int(m.group(2))}"

def _result_text(root: ET.Element) -> str:
    node = root.find(".//result")
    if node is None:
        return ""
    return ET.tostring(node, encoding="unicode", method="text") or ""

def _kv_text_to_ints(txt: str) -> dict:
    """
    Robust key:value extractor for both single-line brace-wrapped and multi-line forms.
    Examples handled:
      "{ rx-bytes: 123, tx-bytes: 456, }"
      "rx-bytes: 123"
      "rx_bytes=123"
    """
    out = {}
    for key, raw in re.findall(r"([A-Za-z0-9_.\-]+)\s*[:=]\s*(0x[0-9A-Fa-f]+|\d+)", txt):
        val = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
        out[key] = val
    return out

def get_hw_counters(host: str, key: str, iface: str) -> dict:
    sp = _iface_to_slot_port(iface)
    if not sp:
        return {}
    s, p = sp

    # Pretty, decimal form (preferred)
    try:
        root = op(host, key, f"<show><system><state><filter-pretty>sys.{s}.{p}.stats</filter-pretty></state></system></show>")
        txt = _result_text(root)
        _short("hw_pretty", txt[:420])
        out = _kv_text_to_ints(txt)
        if out:
            return out
    except Exception as e:
        _short("hw_pretty_err", str(e))

    # Fallback: deeper detail (often hex)
    try:
        root = op(host, key, f"<show><system><state><filter>sys.{s}.{p}.detail</filter></state></system></show>")
        txt = _result_text(root)
        _short("hw_detail", txt[:420])
        return _kv_text_to_ints(txt)
    except Exception as e:
        _short("hw_detail_err", str(e))
        return {}

def map_hw_to_fields(hw: dict) -> Dict[str, int]:
    """
    Map the pretty stats you have into canonical fields.
    """
    m = {}
    if not hw:
        return m

    # Prefer hardware bytes/packets
    if "rx-bytes" in hw:     m["rx_bytes"] = hw["rx-bytes"]
    if "tx-bytes" in hw:     m["tx_bytes"] = hw["tx-bytes"]
    if "rx-unicast" in hw:   m["rx_unicast"] = hw["rx-unicast"]
    if "tx-unicast" in hw:   m["tx_unicast"] = hw["tx-unicast"]

    # Advanced fields
    if "rx-broadcast" in hw: m["rx_broadcast"] = hw["rx-broadcast"]
    if "tx-broadcast" in hw: m["tx_broadcast"] = hw["tx-broadcast"]
    if "rx-multicast" in hw: m["rx_multicast"] = hw["rx-multicast"]
    if "tx-multicast" in hw: m["tx_multicast"] = hw["tx-multicast"]

    # Errors
    if "rx-error" in hw:         m["rx_errors"] = hw["rx-error"]
    if "tx-error" in hw:         m["tx_errors"] = hw["tx-error"]
    if "rx-missed-error" in hw:  m["rx_missed_errors"] = hw["rx-missed-error"]

    return m

def infer_oper_from_counters(stats: Dict[str, object], hw: dict) -> None:
    """
    If XML didn't expose link state, optionally infer 'oper_up' from counters.
    """
    if ("oper_up" not in stats or stats["oper_up"] is None) and HEURISTIC_OPER_UP:
        for k in ("rx-unicast", "tx-unicast", "rx-bytes", "tx-bytes",
                  "rx-broadcast", "tx-broadcast", "rx-multicast", "tx-multicast"):
            if k in hw and isinstance(hw[k], int) and hw[k] > 0:
                stats["oper_up"] = True
                break

# ------------------------------ main ------------------------------
def main():
    if not VERIFY_SSL:
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    # Key
    try:
        key = get_key(FW_HOST, USERNAME, PASSWORD)
    except Exception as e:
        print(json.dumps({"ok": False, "error": f"keygen failed: {e}"}))
        sys.exit(2)

    # XML (all) then (single) → merge (base)
    stats = {}
    try:
        root_all = op(FW_HOST, key, "<show><interface>all</interface></show>")
        stats = parse_any_interface_xml(root_all, INTERFACE)
    except Exception as e:
        _short("xml_all_err", str(e))

    try:
        root_one = op(FW_HOST, key, f"<show><interface>{INTERFACE}</interface></show>")
        single = parse_any_interface_xml(root_one, INTERFACE)
        for k, v in single.items():
            stats[k] = v
    except Exception as e:
        _short("xml_one_err", str(e))

    # Advanced hardware counters (override XML for bytes/packets; add advanced fields)
    hw = {}
    if INCLUDE_HW:
        hw = get_hw_counters(FW_HOST, key, INTERFACE)
        if hw:
            mapped = map_hw_to_fields(hw)
            # hardware should WIN over XML for overlapped keys:
            for k, v in mapped.items():
                stats[k] = v
            stats["hw_raw"] = hw
            infer_oper_from_counters(stats, hw)

    meaningful = any(
        k in stats for k in ("oper_up", "admin_up", "speed_mbps", "mtu",
                             "mac_address", "rx_bytes", "tx_bytes", "rx_unicast", "tx_unicast")
    )

    print(json.dumps({
        "host": FW_HOST,
        "interface": INTERFACE,
        "ok": bool(meaningful),
        "stats": stats if stats else {"name": INTERFACE}
    }, indent=2))

    sys.exit(0 if meaningful else 1)

if __name__ == "__main__":
    main()
