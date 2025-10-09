#!/usr/bin/env python3
"""
BIG-IP "next-hop discovery" helper
- Finds pools containing a given backend IP
- Finds virtual servers directly referencing those pools (defaultPool)
- Determines egress VLAN/interface and best self IP for SNAT Automap
Requires: requests
"""

import ipaddress
import json
import re
import sys
from typing import Dict, List, Optional, Tuple

import requests
import urllib3

# ----------------------------
# ==== EDIT THESE VALUES =====
# ----------------------------
F5_HOST = "192.168.100.87"          # BIG-IP mgmt IP / hostname
F5_USERNAME = "admin-ro"               # statically set for now
F5_PASSWORD = "Labl@b!234"            # statically set for now
VERIFY_SSL = False                  # labs often use self-signed certs
DEST_IP = "10.251.0.205"            # backend/server IP you want to trace
TIMEOUT = 10                        # seconds for HTTP calls
PARTITIONS = None                   # None = all partitions; or ["Common", "App1"]
# ----------------------------

if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def split_ip_rd(addr: str) -> Tuple[str, Optional[int]]:
    """
    Split an F5 address like '10.1.2.3%2' or '10.1.2.3' into (ip, route_domain)
    """
    if "%" in addr:
        ip_part, rd_part = addr.split("%", 1)
        try:
            return ip_part, int(rd_part)
        except ValueError:
            return ip_part, None
    return addr, None


def strip_rd_from_vs_destination(dest: str) -> Tuple[str, Optional[int], Optional[int]]:
    """
    VS destination examples:
      '/Common/10.249.0.100%2:443'  or  '/Common/10.249.0.100:80'
    Returns: (ip, route_domain, port)
    """
    # remove partition prefix if present
    d = dest.split("/")[-1]
    if ":" in d:
        ip_port = d
    else:
        return d, None, None
    ip_rd, port_str = ip_port.rsplit(":", 1)
    ip_str, rd = split_ip_rd(ip_rd)
    try:
        port = int(port_str)
    except ValueError:
        port = None
    return ip_str, rd, port


def net_contains_ip(cidr: str, ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False


class F5Client:
    def __init__(self, host: str, username: str, password: str, verify_ssl: bool = True, timeout: int = 10):
        self.base = f"https://{host}/mgmt"
        self.s = requests.Session()
        self.s.verify = verify_ssl
        self.s.timeout = timeout
        self._login(username, password)

    def _login(self, username: str, password: str):
        # Acquire token (preferred over basic)
        url = f"{self.base}/shared/authn/login"
        payload = {
            "username": username,
            "password": password,
            "loginProviderName": "tmos"
        }
        r = self.s.post(url, json=payload)
        r.raise_for_status()
        token = r.json()["token"]["token"]
        self.s.headers.update({"X-F5-Auth-Token": token})

    def _get(self, path: str, params: Dict = None):
        url = f"{self.base}{path}"
        r = self.s.get(url, params=params)
        r.raise_for_status()
        return r.json()

    # ---- Data collectors ----

    def get_pools_with_members(self):
        # expandSubcollections=true to include pool 'members' inline
        return self._get("/tm/ltm/pool", params={"expandSubcollections": "true"})

    def get_virtuals(self):
        # Select a few key fields to reduce payload
        return self._get("/tm/ltm/virtual")

    def get_virtual_addresses(self):
        return self._get("/tm/ltm/virtual-address")

    def get_self_ips(self):
        return self._get("/tm/net/self")

    def get_vlans(self):
        # Include subcollection 'interfaces' to derive physical ports
        return self._get("/tm/net/vlan", params={"expandSubcollections": "true"})

    def get_static_routes(self):
        return self._get("/tm/net/route")


def find_pools_for_ip(pools_doc: Dict, dest_ip: str, partitions: Optional[List[str]] = None) -> List[Dict]:
    matches = []
    for p in pools_doc.get("items", []):
        if partitions and p.get("partition") not in partitions:
            continue
        # members may be missing if no members or not expanded
        for m in p.get("membersReference", {}).get("items", []) or p.get("members", []) or []:
            # Prefer explicit address field; fallback to parsing member 'name'
            addr = m.get("address")
            if not addr:
                # names look like "10.251.0.205%0:80" or "/Common/node:port"
                name = m.get("name", "")
                m_ip = name.split("%")[0].split(":")[0].split("/")[-1]
                addr = m_ip
            member_ip, _ = split_ip_rd(addr)
            if member_ip == dest_ip:
                matches.append({
                    "pool_name": p.get("fullPath") or p.get("name"),
                    "pool_partition": p.get("partition"),
                    "member": m
                })
                break
    return matches


def find_virtuals_for_pools(virtuals_doc: Dict, pool_fullpaths: List[str]) -> List[Dict]:
    hits = []
    pool_set = set(pool_fullpaths)
    for vs in virtuals_doc.get("items", []):
        pool_ref = vs.get("pool")
        if pool_ref and pool_ref in pool_set:
            hits.append(vs)
    return hits


def index_virtual_addresses(va_doc: Dict) -> Dict[Tuple[str, Optional[int]], Dict]:
    """
    Build dict keyed by (ip, route_domain) -> VA object
    """
    idx = {}
    for va in va_doc.get("items", []):
        ip, rd = split_ip_rd(va.get("address", ""))
        if ip:
            idx[(ip, rd)] = va
    return idx


def index_self_ips(self_doc: Dict) -> List[Dict]:
    """
    Return a list of dicts with parsed helpers:
    - network (IPv4Network)
    - ip (str), rd (int|None)
    - vlan (fullPath)
    - floating (bool)
    """
    out = []
    for s in self_doc.get("items", []):
        addr = s.get("address")  # e.g. "10.251.0.1/24"
        if not addr or ":" in addr:
            continue  # skip IPv6 in first version
        cidr = addr
        ip_str = cidr.split("/")[0]
        ip_base, rd = split_ip_rd(ip_str)
        try:
            net = ipaddress.ip_network(cidr.replace("%{}".format(rd) if rd is not None else "", ""), strict=False)
        except Exception:
            continue
        floating = s.get("floating", False)
        # sometimes 'floating' can be "enabled"/"disabled"
        if isinstance(floating, str):
            floating = floating.lower() in ("true", "enabled", "yes")
        out.append({
            "raw": s,
            "network": net,
            "ip": ip_base,
            "rd": rd,
            "vlan": s.get("vlan"),
            "floating": floating,
            "fullPath": s.get("fullPath") or s.get("name")
        })
    return out


def index_vlans_with_ports(vlan_doc: Dict) -> Dict[str, Dict]:
    """
    Map VLAN fullPath -> { 'name':..., 'interfaces': ['1.1','1.2(tagged)'] }
    """
    idx = {}
    for v in vlan_doc.get("items", []):
        iface_list = []
        for it in v.get("interfacesReference", {}).get("items", []) or v.get("interfaces", []) or []:
            name = it.get("name")
            tagged = it.get("tagged")  # true/false or "enabled"/"disabled"
            if isinstance(tagged, str):
                tagged = tagged.lower() in ("true", "enabled", "yes")
            suffix = "(tagged)" if tagged else "(untagged)"
            iface_list.append(f"{name}{'' if name is None else ''} {suffix}".strip())
        idx[v.get("fullPath") or v.get("name")] = {
            "raw": v,
            "interfaces": [i.split()[0] for i in iface_list],  # clean "1.1"
            "labelled": iface_list
        }
    return idx


def longest_match_route(routes_doc: Dict, dest_ip: str, rd: Optional[int]) -> Optional[Dict]:
    """
    Choose the static route with the longest prefix that matches dest_ip, honoring route-domain if encoded in 'network'
    e.g., route["network"] may be "10.0.0.0%2/8" or "0.0.0.0/0"
    """
    target = ipaddress.ip_address(dest_ip)
    best = None
    best_prefix = -1
    for r in routes_doc.get("items", []):
        network = r.get("network")
        if not network or ":" in network:
            continue
        # Split potential %rd
        net_ip_mask = network
        ip_part = net_ip_mask.split("%")[0]
        mask_part = net_ip_mask.split("/")[-1]
        try:
            net = ipaddress.ip_network(f"{ip_part}/{mask_part}", strict=False)
        except Exception:
            continue
        # Route-domain check (ignore if either side has no RD)
        route_rd = None
        if "%" in net_ip_mask:
            try:
                route_rd = int(net_ip_mask.split("%")[1].split("/")[0])
            except Exception:
                route_rd = None
        if rd is not None and route_rd is not None and rd != route_rd:
            continue
        if target in net and net.prefixlen > best_prefix:
            best = r
            best_prefix = net.prefixlen
    return best


def choose_egress_vlan_and_self(self_list: List[Dict], gw_ip: str, rd: Optional[int]) -> Tuple[Optional[str], Optional[Dict]]:
    """
    Find the VLAN and best self IP used to reach 'gw_ip':
    - Find the self IP whose network contains 'gw_ip' and (if rd given) same RD
    - Prefer floating on that VLAN; else any self-IP on that VLAN
    """
    vlan = None
    candidates = []
    for s in self_list:
        if rd is not None and s["rd"] is not None and rd != s["rd"]:
            continue
        if net_contains_ip(s["raw"]["address"], gw_ip):
            vlan = s["vlan"]
            candidates.append(s)
    if not vlan:
        return None, None
    # prefer floating
    floaters = [s for s in candidates if s["floating"]]
    best = floaters[0] if floaters else candidates[0]
    return vlan, best


def main():
    client = F5Client(F5_HOST, F5_USERNAME, F5_PASSWORD, verify_ssl=VERIFY_SSL, timeout=TIMEOUT)

    pools_doc = client.get_pools_with_members()
    vips_doc = client.get_virtuals()
    va_doc = client.get_virtual_addresses()
    self_doc = client.get_self_ips()
    vlan_doc = client.get_vlans()
    routes_doc = client.get_static_routes()

    # 1) Pools containing the backend IP
    pool_hits = find_pools_for_ip(pools_doc, DEST_IP, PARTITIONS)
    pool_names = [h["pool_name"] for h in pool_hits]

    # 2) VS that reference those pools (defaultPool)
    vs_hits = find_virtuals_for_pools(vips_doc, pool_names)

    # 3) Map VS -> Virtual Address (if present)
    va_index = index_virtual_addresses(va_doc)
    vs_summaries = []
    rd_from_member = None
    for hit in pool_hits:
        # try to infer RD from member address if it had one
        member_addr = hit["member"].get("address") or hit["member"].get("name", "")
        _, rd_from_member = split_ip_rd(member_addr or DEST_IP)

    for vs in vs_hits:
        ip, rd, port = strip_rd_from_vs_destination(vs.get("destination", ""))
        va = va_index.get((ip, rd)) or va_index.get((ip, None))
        vs_summaries.append({
            "name": vs.get("fullPath") or vs.get("name"),
            "destination": vs.get("destination"),
            "virtual_address": va.get("fullPath") if va else None
        })

    # 4) Compute egress (VLAN/interface + best self IP) for reaching the backend IP
    self_list = index_self_ips(self_doc)
    vlan_index = index_vlans_with_ports(vlan_doc)

    # If destination is on a directly-connected self-IP network, that's the egress
    directly_connected = next((s for s in self_list if net_contains_ip(s["raw"]["address"], DEST_IP)), None)

    egress_vlan = None
    egress_self = None
    next_hop = None

    if directly_connected:
        egress_vlan = directly_connected["vlan"]
        egress_self = directly_connected
        next_hop = DEST_IP  # ARP direct
    else:
        # Longest-match static route
        route = longest_match_route(routes_doc, DEST_IP, rd_from_member)
        if route:
            next_hop = route.get("gw")  # may be None for directly-connected route with explicit interface
            # If route has an explicit interface (rare on BIG-IP), honor it; otherwise find VLAN via gateway containment
            if next_hop:
                egress_vlan, egress_self = choose_egress_vlan_and_self(self_list, next_hop, rd_from_member)
            else:
                # direct route: infer VLAN by matching the route's 'network' to a self-IP's network
                net = route.get("network")
                for s in self_list:
                    if net_contains_ip(net, s["ip"]):
                        egress_vlan = s["vlan"]
                        egress_self = s
                        break

    vlan_label = None
    vlan_ports = []
    if egress_vlan:
        vlan_label = egress_vlan
        v = vlan_index.get(egress_vlan)
        if v:
            vlan_ports = v["interfaces"]

    result = {
        "destination_ip": DEST_IP,
        "pools_containing_member": pool_names,
        "virtual_servers": vs_summaries,
        "next_hop": next_hop,
        "egress_vlan": vlan_label,
        "egress_interfaces": vlan_ports,
        "egress_self_ip": egress_self["fullPath"] if egress_self else None,
        "egress_self_ip_address": egress_self["raw"]["address"] if egress_self else None,
    }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as e:
        sys.stderr.write(f"HTTP error: {e}\nBody: {getattr(e.response, 'text', '')[:1000]}\n")
        sys.exit(2)
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)
