#!/usr/bin/env python3
"""Manual smoke test: validate Panorama traffic logs for a known DENY flow.

This helper is intended for WP-007 (lab validation). It uses the same XML API
client implementation as the Nautobot Job/CLI (`jobs.network_path_tracing`),
but runs as a standalone script so you can validate Panorama logging without
requiring Nautobot path tracing prerequisites.

Credentials are read from environment variables (preferred) or prompted:
- `PA_USERNAME`
- `PA_PASSWORD`

Panorama host can be provided via `--panorama-host` or `PANORAMA_HOST`.

Examples:
  export PANORAMA_HOST=panorama.example.com
  export PA_USERNAME=panorama-ro
  export PA_PASSWORD='***'
  python tests/panorama_traffic_log_smoke.py --src-ip 10.0.0.10 --dst-ip 10.0.0.20 --dst-port 443

Exit codes:
  0 = query succeeded (logs may or may not be found unless --expect-found)
  1 = query failed (auth/network/API error)
  2 = query succeeded but no logs found and --expect-found was set
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from getpass import getpass
from pathlib import Path
from typing import Any, Dict, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

SITE_PACKAGES = (
    PROJECT_ROOT
    / "venv"
    / "lib"
    / f"python{sys.version_info.major}.{sys.version_info.minor}"
    / "site-packages"
)
if SITE_PACKAGES.exists() and str(SITE_PACKAGES) not in sys.path:
    sys.path.insert(0, str(SITE_PACKAGES))


from jobs.network_path_tracing.interfaces.palo_alto import PaloAltoClient  # noqa: E402


_QUERY_PARAM_SECRET_RE = re.compile(r"(\b(?:key|user|password)=)[^&\s]+", re.IGNORECASE)


def _env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_positive_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip()
    if not value:
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= 1 else default


def _safe_ip(value: str, *, label: str) -> str:
    raw = (value or "").strip()
    if not raw:
        raise ValueError(f"Missing {label} (expected IP literal).")
    return str(ipaddress.ip_address(raw))


def _safe_port(value: Any) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid destination port '{value}' (expected integer 0-65535).") from exc
    if port < 0 or port > 65535:
        raise ValueError(f"Invalid destination port '{port}' (expected integer 0-65535).")
    return port


def _redact_secret_query_params(text: str) -> str:
    return _QUERY_PARAM_SECRET_RE.sub(r"\1***redacted***", text)


def _redact_known_secrets(text: str, *, secrets: tuple[str, ...]) -> str:
    redacted = text
    for secret in secrets:
        if not secret:
            continue
        redacted = redacted.replace(secret, "***redacted***")
    return redacted


def _build_query(*, time_field: str, since_hours: int, src_ip: str, dst_ip: str, dst_port: int) -> str:
    return (
        f"({time_field} in last-{since_hours}-hrs) "
        f"and (addr.src in {src_ip}) "
        f"and (addr.dst in {dst_ip}) "
        f"and (dport eq {dst_port})"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panorama-host", help="Panorama hostname/IP (or set PANORAMA_HOST).")
    parser.add_argument("--src-ip", required=True, help="Source IP (pre/post-NAT as logged in Panorama).")
    parser.add_argument("--dst-ip", required=True, help="Destination IP (pre/post-NAT as logged in Panorama).")
    parser.add_argument("--dst-port", required=True, type=int, help="Destination port (0-65535).")
    parser.add_argument(
        "--since-hours",
        type=int,
        default=24,
        help="Time window size for the query (default: 24).",
    )
    parser.add_argument(
        "--time-field",
        choices=("receive_time", "time_generated"),
        default="receive_time",
        help="Timestamp field used for time filtering (default: receive_time).",
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=10,
        help="Maximum number of log entries to return (default: 10).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP timeout in seconds (default: 10).",
    )
    parser.add_argument(
        "--max-wait-seconds",
        type=int,
        help=(
            "Max seconds to wait for Panorama async log query job completion "
            "(default: PANORAMA_LOG_QUERY_MAX_WAIT_SECONDS or 30)."
        ),
    )
    verify_group = parser.add_mutually_exclusive_group()
    verify_group.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify Panorama SSL certificate (overrides PA_VERIFY_SSL).",
    )
    verify_group.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable Panorama SSL verification (overrides PA_VERIFY_SSL).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON only.",
    )
    parser.add_argument(
        "--expect-found",
        action="store_true",
        help="Exit 2 if the query succeeds but returns zero entries.",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    panorama_host = (args.panorama_host or os.getenv("PANORAMA_HOST", "")).strip()
    if not panorama_host:
        print("ERROR: Panorama host is required (use --panorama-host or set PANORAMA_HOST).", file=sys.stderr)
        return 1

    username = (os.getenv("PA_USERNAME", "")).strip()
    if not username:
        username = input("Panorama username (PA_USERNAME): ").strip()
    password = os.getenv("PA_PASSWORD")
    if not password:
        password = getpass("Panorama password (PA_PASSWORD): ")

    verify_ssl: bool
    if args.verify_ssl:
        verify_ssl = True
    elif args.no_verify_ssl:
        verify_ssl = False
    else:
        verify_ssl = _env_flag("PA_VERIFY_SSL", False)

    try:
        src_ip = _safe_ip(args.src_ip, label="--src-ip")
        dst_ip = _safe_ip(args.dst_ip, label="--dst-ip")
        dst_port = _safe_port(args.dst_port)
        since_hours = int(args.since_hours)
        if since_hours < 1:
            raise ValueError("--since-hours must be >= 1.")
        max_results = int(args.max_results)
        if max_results < 1:
            raise ValueError("--max-results must be >= 1.")
        max_wait_seconds = (
            int(args.max_wait_seconds)
            if args.max_wait_seconds is not None
            else _env_positive_int("PANORAMA_LOG_QUERY_MAX_WAIT_SECONDS", 30)
        )
        if max_wait_seconds < 1:
            raise ValueError("--max-wait-seconds must be >= 1.")
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    query = _build_query(
        time_field=args.time_field,
        since_hours=since_hours,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
    )

    client = PaloAltoClient(panorama_host, verify_ssl=verify_ssl, timeout=args.timeout)
    try:
        api_key = client.keygen(username, password)
        entries = client.traffic_logs_query(
            api_key,
            query=query,
            nlogs=max_results,
            max_wait_seconds=max_wait_seconds,
        )
    except Exception as exc:
        safe_error = _redact_secret_query_params(str(exc))
        safe_error = _redact_known_secrets(safe_error, secrets=(username, password))
        print(f"ERROR: {safe_error}", file=sys.stderr)
        return 1

    entries = [
        entry
        for entry in entries
        if (entry.get("action") or "").strip().lower() == "deny"
    ]

    payload: Dict[str, Any] = {
        "panorama": {"host": panorama_host, "verify_ssl": verify_ssl},
        "query": {
            "time_field": args.time_field,
            "since_hours": since_hours,
            "action": "deny",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "destination_port": dst_port,
            "max_results": max_results,
            "max_wait_seconds": max_wait_seconds,
            "filter": query,
        },
        "result": {
            "found": bool(entries),
            "count": len(entries),
            "entries": entries,
        },
    }

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Panorama host: {panorama_host} (verify_ssl={verify_ssl})")
        print(f"Query: {query}")
        print(f"Returned entries: {len(entries)}")
        for idx, entry in enumerate(entries, start=1):
            ts = entry.get("timestamp")
            action = entry.get("action")
            s_ip = entry.get("source_ip")
            d_ip = entry.get("destination_ip")
            d_port = entry.get("destination_port")
            rule = entry.get("rule")
            device = entry.get("device_name") or entry.get("device_serial")
            print(f"- {idx}: ts={ts} action={action} src={s_ip} dst={d_ip} dport={d_port} rule={rule} device={device}")

    if args.expect_found and not entries:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
