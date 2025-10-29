import os
import urllib.parse
import requests
import xml.etree.ElementTree as ET
import urllib3

def _parse_pan_xml(text: str) -> ET.Element:
    try:
        return ET.fromstring(text)
    except ET.ParseError as e:
        raise RuntimeError(f"Malformed XML from device: {e}\n{text[:4000]}")

def _first(root: ET.Element, xpath: str):
    el = root.find(xpath)
    return el.text.strip() if el is not None and el.text else None

class PaloAltoClient:
    def __init__(self, host: str, verify_ssl: bool = False, timeout: int = 10):
        self.host = host
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.timeout = timeout
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _get(self, url: str) -> requests.Response:
        print(f"[HTTP GET] {url}")
        r = self.session.get(url, timeout=self.timeout)
        print(f"[HTTP STATUS] {r.status_code}")
        return r

    def keygen(self, username: str, password: str) -> str:
        url = (
            f"https://{self.host}/api/?type=keygen"
            f"&user={urllib.parse.quote(username, safe='')}"
            f"&password={urllib.parse.quote(password, safe='')}"
        )
        r = self._get(url)
        root = _parse_pan_xml(r.text)
        key = _first(root, ".//key")
        if not key:
            raise RuntimeError("API key not found in response.")
        return key

    def show_route_raw(self, api_key: str, vr: str, destination: str = None) -> str:
        """
        Use the supported 'show routing route' op command, optionally filtered by destination + VR.
        CLI equivalent: show routing route destination <ip/netmask> virtual-router <vr>
        Docs show available params: destination, interface, nexthop, type, virtual-router, count, ecmp, afi, safi. 
        """
        # Build XML body
        parts = ["<show><routing><route>"]
        if destination:
            parts.append(f"<destination>{destination}</destination>")
        if vr:
            parts.append(f"<virtual-router>{vr}</virtual-router>")
        parts.append("</route></routing></show>")
        cmd_xml = "".join(parts)

        url = f"https://{self.host}/api/?type=op&cmd={urllib.parse.quote(cmd_xml)}&key={api_key}"
        r = self._get(url)
        print("[OP RAW XML]")
        print(r.text)
        return r.text

    def fib_lookup_raw(self, api_key: str, vr: str, ip: str) -> str:
        cmd_xml = (
            "<test><routing><fib-lookup>"
            f"<ip>{ip}</ip><virtual-router>{vr}</virtual-router>"
            "</fib-lookup></routing></test>"
        )
        url = f"https://{self.host}/api/?type=op&cmd={urllib.parse.quote(cmd_xml)}&key={api_key}"
        r = self._get(url)
        print("[OP RAW XML]")
        print(r.text)
        return r.text
    
        # ---- NEW: generic config reader (type=config&action=show) ----
    def config_show(self, api_key: str, xpath: str) -> ET.Element:
        """GET active config subtree at xpath; raises on API errors."""
        url = (
            f"https://{self.host}/api/?type=config&action=show"
            f"&xpath={urllib.parse.quote(xpath, safe='')}&key={api_key}"
        )
        r = self._get(url)
        root = _parse_pan_xml(r.text)
        status = root.attrib.get("status")
        if status != "success":
            # pull a helpful message if present
            msg = _first(root, ".//msg") or _first(root, ".//line") or "unknown error"
            raise RuntimeError(f"Config show failed: {msg}")
        return root

    # ---- NEW: members for a single VLAN interface (e.g., 'vlan.200') ----
    def vlan_members_for_interface(self, api_key: str, vlan_if: str) -> list[str]:
        """
        Return list of physical L2 member interfaces for the VLAN object bound to vlan_if.
        Strategy:
          - Try one-call: /network/vlan/entry[vlan-interface='<vlan_if>']/interface
          - Fallback two-step:
              1) /network/interface/vlan/entry[@name='<vlan_if>']/vlan  -> VLAN object name
              2) /network/vlan/entry[@name='<vlan_name>']/interface     -> members
        """
        root_base = "/config/devices/entry[@name='localhost.localdomain']"

        # 1) One-call (fast path)
        try:
            xp = f"{root_base}/network/vlan/entry[vlan-interface='{vlan_if}']/interface"
            root = self.config_show(api_key, xp)
            members = [m.text.strip() for m in root.findall(".//member") if m is not None and m.text]
            if members:
                return members
        except Exception as e:
            print(f"[DEBUG] one-call VLAN member lookup skipped/fallback: {e}")

        # 2) Two-step
        xp_vlan_name = f"{root_base}/network/interface/vlan/entry[@name='{vlan_if}']/vlan"
        root1 = self.config_show(api_key, xp_vlan_name)
        vlan_name = _first(root1, ".//vlan")
        if not vlan_name:
            return []

        xp_members = f"{root_base}/network/vlan/entry[@name='{vlan_name}']/interface"
        root2 = self.config_show(api_key, xp_members)
        members = [m.text.strip() for m in root2.findall(".//member") if m is not None and m.text]
        return members

    # ---- NEW: full mapping of ALL SVIs -> member ports ----
    def vlan_members_map(self, api_key: str) -> dict[str, list[str]]:
        """
        Read all VLAN objects and build { 'vlan.X': ['ethernet1/3', ...], ... }.
        Only entries that have both a vlan-interface and at least one member are returned.
        """
        root_base = "/config/devices/entry[@name='localhost.localdomain']"
        xp = f"{root_base}/network/vlan/entry"
        root = self.config_show(api_key, xp)

        mapping: dict[str, list[str]] = {}
        for entry in root.findall(".//result//entry"):
            svi = _first(entry, "./vlan-interface")
            members = [
                m.text.strip() for m in entry.findall(".//interface/member")
                if m is not None and m.text and m.text.strip()
            ]
            if svi and members:
                mapping[svi] = members
        return mapping
    
    def config_show(self, api_key: str, xpath: str) -> ET.Element:
        url = (
            f"https://{self.host}/api/?type=config&action=show"
            f"&xpath={urllib.parse.quote(xpath, safe='')}&key={api_key}"
        )
        r = self._get(url)
        root = _parse_pan_xml(r.text)
        if root.attrib.get("status") != "success":
            msg = _first(root, ".//msg") or _first(root, ".//line") or "unknown error"
            raise RuntimeError(f"Config show failed: {msg}")
        return root

    def list_vlan_interfaces(self, api_key: str) -> list[str]:
        """Return ['vlan.10', 'vlan.200', ...] if any SVI exists."""
        base = "/config/devices/entry[@name='localhost.localdomain']"
        try:
            root = self.config_show(api_key, f"{base}/network/interface/vlan")
        except RuntimeError as e:
            if "No such node" in str(e):
                return []
            raise
        names = []
        for e in root.findall(".//result//entry"):
            name = e.attrib.get("name")
            if name:
                names.append(name)
        return sorted(names)

    def list_vlan_objects(self, api_key: str) -> list[dict]:
        """
        Return [{'name': 'VLAN200', 'vlan_interface': 'vlan.200' or None,
                 'members': ['ethernet1/3','ethernet1/4']}...]
        """
        base = "/config/devices/entry[@name='localhost.localdomain']"
        try:
            root = self.config_show(api_key, f"{base}/network/vlan/entry")
        except RuntimeError as e:
            if "No such node" in str(e):
                return []
            raise
        out = []
        for e in root.findall(".//result//entry"):
            name = e.attrib.get("name")
            svi = _first(e, "./vlan-interface")
            members = [m.text.strip() for m in e.findall(".//interface/member") if m.text and m.text.strip()]
            out.append({"name": name, "vlan_interface": svi, "members": members})
        return out

    def vlan_members_for_interface(self, api_key: str, vlan_if: str) -> list[str]:
        """
        Try one-call; if missing, try two-step (SVI -> VLAN object -> members).
        """
        base = "/config/devices/entry[@name='localhost.localdomain']"

        # One-call: VLAN object filtered by vlan-interface
        try:
            root = self.config_show(api_key, f"{base}/network/vlan/entry[virtual-interface='vlan.200']")
            members = [m.text.strip() for m in root.findall(".//member") if m.text]
            if members:
                return members
        except RuntimeError as e:
            if "No such node" not in str(e):
                raise

        # Two-step: find VLAN object name from the SVI, then read its members
        root1 = self.config_show(api_key, f"{base}/network/interface/vlan/entry[@name='{vlan_if}']/vlan")
        vlan_name = _first(root1, ".//vlan")
        if not vlan_name:
            return []
        root2 = self.config_show(api_key, f"{base}/network/vlan/entry[@name='{vlan_name}']/interface")
        return [m.text.strip() for m in root2.findall(".//member") if m.text]
    
    def vlan_members_for_vlan_object(self, api_key: str, vlan_name: str) -> list[str]:
        """
        Return list of member interfaces for a VLAN object (e.g. 'Servers').
        """
        base = "/config/devices/entry[@name='localhost.localdomain']"
        root = self.config_show(api_key, f"{base}/network/vlan/entry[@name='{vlan_name}']/interface")
        return [m.text.strip() for m in root.findall(".//member") if m is not None and m.text and m.text.strip()]

    def _index_vlan_members(self, api_key: str) -> dict[str, str]:
        """
        Build reverse index: member_if -> vlan_object_name
        Example: {'ethernet1/2': 'Servers', 'ethernet1/2.200': 'Servers'}
        """
        base = "/config/devices/entry[@name='localhost.localdomain']"
        idx: dict[str, str] = {}
        try:
            root = self.config_show(api_key, f"{base}/network/vlan/entry")
        except RuntimeError as e:
            if "No such node" in str(e):
                return idx
            raise
        for e in root.findall(".//result//entry"):
            vlan_name = e.attrib.get("name")
            for m in e.findall(".//interface/member"):
                if m is not None and m.text and m.text.strip():
                    idx[m.text.strip()] = vlan_name
        return idx

    def _iter_phys_if_entries(self, api_key: str) -> list[ET.Element]:
        """
        Return all ethernet and aggregate-ethernet <entry> nodes.
        """
        base = "/config/devices/entry[@name='localhost.localdomain']/network/interface"
        entries: list[ET.Element] = []
        for kind in ("ethernet", "aggregate-ethernet"):
            try:
                root = self.config_show(api_key, f"{base}/{kind}/entry")
            except RuntimeError as e:
                if "No such node" in str(e):
                    continue
                raise
            entries.extend(root.findall(".//result//entry"))
        return entries

    def find_vlan_tag_locations(self, api_key: str, vlan_tag: int) -> dict:
        """
        Find everywhere VLAN <vlan_tag> appears:
          - SVIs (vlan.X) with <tag>vlan_tag</tag>
          - Layer2 subinterfaces with that tag
          - Layer3 subinterfaces with that tag
        Returns a dict with lists of dicts describing each hit.
        """
        base = "/config/devices/entry[@name='localhost.localdomain']"
        vlan_tag_str = str(vlan_tag)
        results = {"svis": [], "l2_subifs": [], "l3_subifs": []}

        # SVIs (if any)
        try:
            svi_root = self.config_show(api_key, f"{base}/network/interface/vlan/entry")
            for e in svi_root.findall(".//result//entry"):
                name = e.attrib.get("name")
                tag = e.findtext("./tag")
                if name and tag == vlan_tag_str:
                    results["svis"].append({"name": name})
        except RuntimeError as e:
            if "No such node" not in str(e):
                raise  # otherwise, no SVI tree — fine

        # Reverse index of VLAN object membership -> which VLAN object
        member_to_vlan = self._index_vlan_members(api_key)

        # Scan physical ifs for subinterfaces in layer2/layer3 with matching <tag>
        for phys in self._iter_phys_if_entries(api_key):
            parent = phys.attrib.get("name", "?")

            # L2 subifs
            for unit in phys.findall(".//layer2/units/entry"):
                unit_name = unit.attrib.get("name")
                tag_el = unit.find("./tag")
                if unit_name and tag_el is not None and tag_el.text == vlan_tag_str:
                    results["l2_subifs"].append({
                        "name": unit_name,
                        "parent": parent,
                        "vlan_object": member_to_vlan.get(unit_name) or member_to_vlan.get(parent),
                    })

            # L3 subifs
            for unit in phys.findall(".//layer3/units/entry"):
                unit_name = unit.attrib.get("name")
                tag_el = unit.find("./tag")
                if unit_name and tag_el is not None and tag_el.text == vlan_tag_str:
                    results["l3_subifs"].append({
                        "name": unit_name,
                        "parent": parent,
                        # L3 subifs won't be members of a VLAN object; include None
                        "vlan_object": member_to_vlan.get(unit_name),
                    })

        return results




if __name__ == "__main__":
    # --------- EDIT THESE OR PASS VIA ENV/CLI ----------
    HOST = os.getenv("PA_HOST", "192.168.100.86")
    USERNAME = os.getenv("PA_USERNAME", "admin-ro")
    PASSWORD = os.getenv("PA_PASSWORD", "Labl@b!234")
    VERIFY_SSL = False
    VR = os.getenv("PA_VR", "Internal")
    TEST_IP = os.getenv("PA_TEST_IP", "10.200.200.200")      # for fib-lookup
    ROUTE_DEST = os.getenv("PA_ROUTE_DEST", TEST_IP)         # you can set "10.200.200.200/32" explicitly
    # ---------------------------------------------------

    c = PaloAltoClient(HOST, VERIFY_SSL)

    print("\n=== STEP 1: KEYGEN ===\n")
    key = c.keygen(USERNAME, PASSWORD)
    print(f"[API KEY] {key[:4]}...{key[-4:]}")

    # print("\n=== STEP 2: FIB LOOKUP (RAW XML) ===\n")
    # c.fib_lookup_raw(key, VR, TEST_IP)

    # print("\n=== STEP 3: ROUTING TABLE QUERY (RAW XML) ===\n")
    # # Try /32 for a precise RIB match; PAN-OS accepts 'destination <ip/netmask>'
    # dest = ROUTE_DEST if "/" in ROUTE_DEST else f"{ROUTE_DEST}/32"
    # c.show_route_raw(key, VR, dest)

    print("\n=== STEP 4: VLAN DISCOVERY ===\n")
    try:
        svi_list = c.list_vlan_interfaces(key)
        print(f"[SVIs] {svi_list if svi_list else '(none)'}")
    except Exception as e:
        print(f"[ERROR] listing VLAN interfaces: {e}")

    try:
        vlan_objs = c.list_vlan_objects(key)
        if not vlan_objs:
            print("[VLAN OBJECTS] (none)")
        else:
            print("[VLAN OBJECTS]")
            for v in vlan_objs:
                print(f"  {v['name']}: vlan_interface={v['vlan_interface']}, members={v['members']}")
    except Exception as e:
        print(f"[ERROR] listing VLAN objects: {e}")

    VLAN_IF = os.getenv("PA_VLAN_IF", "vlan.200")
    try:
        members = c.vlan_members_for_interface(key, VLAN_IF)
        print(f"[VLAN MEMBERS FOR {VLAN_IF}] {members if members else '(none or not linked)'}")
    except Exception as e:
        print(f"[ERROR] member lookup for {VLAN_IF}: {e}")


    # print("\n=== STEP 4: VLAN MEMBER DISCOVERY ===\n")
    # VLAN_IF = os.getenv("PA_VLAN_IF", "vlan.200")

    # # A) One SVI -> members
    # try:
    #     members = c.vlan_members_for_interface(key, VLAN_IF)
    #     print(f"[VLAN MEMBERS] {VLAN_IF} -> {members if members else '(none)'}")
    # except Exception as e:
    #     print(f"[ERROR] member lookup for {VLAN_IF} failed: {e}")

    # # B) Full map of all SVIs -> members
    # try:
    #     mapping = c.vlan_members_map(key)
    #     print("[VLAN MAP]")
    #     if not mapping:
    #         print("  (no VLANs with both vlan-interface and members found)")
    #     else:
    #         for svi, mems in mapping.items():
    #             print(f"  {svi}: {', '.join(mems)}")
    # except Exception as e:
    #     print(f"[ERROR] full VLAN map failed: {e}")

    # print("\n=== STEP 5: VLAN TAG DISCOVERY ===\n")
    # VLAN_TAG = int(os.getenv("PA_VLAN_TAG", "200"))

    # try:
    #     info = c.find_vlan_tag_locations(key, VLAN_TAG)
    #     print(f"[SVIs with tag {VLAN_TAG}] { [x['name'] for x in info['svis']] or '(none)' }")

    #     if info["l2_subifs"]:
    #         print(f"[L2 subinterfaces with tag {VLAN_TAG}]")
    #         for x in info["l2_subifs"]:
    #             print(f"  {x['name']} (parent {x['parent']})"
    #                   f"{' in VLAN '+x['vlan_object'] if x['vlan_object'] else ''}")
    #     else:
    #         print(f"[L2 subinterfaces with tag {VLAN_TAG}] (none)")

    #     if info["l3_subifs"]:
    #         print(f"[L3 subinterfaces with tag {VLAN_TAG}]")
    #         for x in info["l3_subifs"]:
    #             print(f"  {x['name']} (parent {x['parent']})")
    #     else:
    #         print(f"[L3 subinterfaces with tag {VLAN_TAG}] (none)")
    # except Exception as e:
    #     print(f"[ERROR] VLAN tag discovery failed: {e}")


