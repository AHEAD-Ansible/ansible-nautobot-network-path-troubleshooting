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

if __name__ == "__main__":
    # --------- EDIT THESE OR PASS VIA ENV/CLI ----------
    HOST = os.getenv("PA_HOST", "192.168.100.76")
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

    print("\n=== STEP 2: FIB LOOKUP (RAW XML) ===\n")
    c.fib_lookup_raw(key, VR, TEST_IP)

    print("\n=== STEP 3: ROUTING TABLE QUERY (RAW XML) ===\n")
    # Try /32 for a precise RIB match; PAN-OS accepts 'destination <ip/netmask>'
    dest = ROUTE_DEST if "/" in ROUTE_DEST else f"{ROUTE_DEST}/32"
    c.show_route_raw(key, VR, dest)
