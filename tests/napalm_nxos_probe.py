#!/usr/bin/env python3

"""
napalm_nxos_probe.py — quick connectivity & routing probe for NX-OS via NAPALM

Usage examples:
  # Basic SSH (recommended first test)
  python napalm_nxos_probe.py --host 10.0.0.10 -u admin --driver nxos_ssh --dest 1.1.1.1 --debug

  # NX-API (HTTPS) — if you have NX-API enabled on the device
  python napalm_nxos_probe.py --host 10.0.0.10 -u admin --driver nxos --port 443 --dest 1.1.1.1 --debug

  # Probe the SSH banner/ident before running NAPALM (helps diagnose "banner line contains invalid characters")
  python napalm_nxos_probe.py --host 10.0.0.10 --probe-banner

Notes:
- For SSH driver, this script can create a Netmiko session log if you pass --session-log /path/to/file.log
- For NX-API driver, ensure NX-API is enabled and reachable; adjust --port and --insecure if your setup uses HTTP/invalid certs.
"""
import argparse
import getpass
import json
import logging
import socket
import sys
import traceback
from typing import Optional

try:
    import napalm
except Exception as exc:
    print("ERROR: NAPALM is not installed in this environment.", file=sys.stderr)
    print("Try: pip install napalm netmiko paramiko", file=sys.stderr)
    raise

DEFAULT_TIMEOUT = 30


def configure_logging(debug: bool) -> None:
    """Configure console logging and crank up library loggers when --debug."""
    level = logging.DEBUG if debug else logging.INFO
    root = logging.getLogger()
    if not root.handlers:
        handler = logging.StreamHandler(sys.stdout)
        fmt = "%(asctime)s %(name)s %(levelname)s: %(message)s"
        handler.setFormatter(logging.Formatter(fmt))
        root.addHandler(handler)
    root.setLevel(level)

    # Library loggers — useful to see what's happening under the hood
    for name in ("napalm", "netmiko", "paramiko.transport"):
        lg = logging.getLogger(name)
        lg.setLevel(level)


def probe_banner(host: str, port: int, timeout: int = 5) -> Optional[str]:
    """Read the very first line from TCP 22 to verify a clean SSH identification string."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = b""
            # Read until first newline (or up to 255 bytes)
            while b"\n" not in data and len(data) < 255:
                chunk = s.recv(64)
                if not chunk:
                    break
                data += chunk
            line = data.splitlines()[0] if data else b""
            return line.decode("utf-8", errors="replace")
    except Exception as exc:
        return f"[probe error] {exc}"


def main():
    p = argparse.ArgumentParser(description="NAPALM NX-OS connectivity & route probe")
    p.add_argument("--host", required=True, help="Device management IP/DNS")
    p.add_argument("-u", "--user", required=True, help="Username")
    p.add_argument("--password", help="Password (prompted if omitted)")
    p.add_argument("--driver", choices=["nxos_ssh", "nxos"], default="nxos_ssh", help="NAPALM driver")
    p.add_argument("--port", type=int, help="TCP port (default: 22 for SSH, 443 for NX-API)")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"NAPALM overall timeout (default {DEFAULT_TIMEOUT}s)")
    p.add_argument("--dest", help="Destination IP/Prefix for get_route_to() (optional)")
    p.add_argument("--session-log", help="Netmiko session log path (SSH driver only)")
    p.add_argument("--ssh-config", help="Path to OpenSSH config to use (SSH driver only)")
    p.add_argument("--insecure", action="store_true", help="NX-API only: disable SSL verification / use http if needed")
    p.add_argument("--debug", action="store_true", help="Enable verbose library logging")
    p.add_argument("--probe-banner", action="store_true", help="Probe and print the SSH banner/ident first (port 22)")
    args = p.parse_args()

    configure_logging(args.debug)

    # if args.probe-banner:
    #     ident = probe_banner(args.host, 22)
    #     print(f"SSH banner probe (port 22): {ident}")

    password = args.password or getpass.getpass("Password: ")

    # Build optional args per driver
    optional_args = {}
    if args.driver == "nxos_ssh":
        # SSH/Netmiko path
        optional_args["port"] = args.port if args.port else 22
        if args.session_log:
            optional_args["session_log"] = args.session_log
        if args.ssh_config:
            optional_args["ssh_config_file"] = args.ssh_config
    else:
        # NX-API (HTTP/HTTPS)
        optional_args["port"] = args.port if args.port else 443
        if args.insecure:
            # Common patterns: disable SSL verify or fall back to HTTP depending on environment
            optional_args["verify"] = False  # disable TLS cert verification
            # optional_args["transport"] = "http"  # uncomment if your NX-API is plain HTTP

    print(f"Driver: {args.driver}  Host: {args.host}  Port: {optional_args.get('port')}  Timeout: {args.timeout}")
    if args.driver == "nxos_ssh" and args.session_log:
        print(f"Netmiko session log: {args.session_log}")

    try:
        driver_cls = napalm.get_network_driver(args.driver)
        with driver_cls(
            hostname=args.host,
            username=args.user,
            password=password,
            timeout=args.timeout,
            optional_args=optional_args,
        ) as dev:
            print("Connected. is_alive():", dev.is_alive())

            facts = dev.get_facts()
            print("\n=== get_facts() ===")
            print(json.dumps(facts, indent=2))

            # Try an easy read that works on most platforms
            try:
                interfaces = dev.get_interfaces()
                print("\n=== get_interfaces() (truncated to 10) ===")
                # Truncate output to keep it readable
                trimmed = dict(list(interfaces.items())[:10])
                print(json.dumps(trimmed, indent=2))
            except Exception as exc:
                print(f"[warn] get_interfaces() failed: {exc}")

            if args.dest:
                try:
                    rt = dev.get_route_to(destination=args.dest)
                    print(f"\n=== get_route_to(destination={args.dest!r}) ===")
                    print(json.dumps(rt, indent=2))
                except Exception as exc:
                    print(f"[warn] get_route_to({args.dest}) failed: {exc}")

    except Exception as exc:
        print("\n[ERROR] NAPALM failure:", exc)
        if args.debug:
            traceback.print_exc()
        sys.exit(2)


if __name__ == "__main__":
    main()
