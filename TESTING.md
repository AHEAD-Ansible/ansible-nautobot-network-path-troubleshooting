# Testing the Network Path Tracing Toolkit

The repository ships two complementary testing layers:
- **Automated pytest suite** – Fast unit tests that validate the reusable modules without requiring Nautobot or device access.
- **Optional smoke / probe scripts** – Manually executed helpers for validating vendor APIs and lab connectivity.

Use the sections below to decide which tests fit your workflow.

---

## Automated Tests (pytest)

### Prerequisites

1. Create and activate an isolated environment (recommended):

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install dependencies (pytest, responses, napalm stubs, etc.):

   ```bash
   pip install -r requirements.txt
   ```

### Running the Suite

Run every test:

```bash
pytest
```

Useful flags:
- `pytest tests/test_steps.py -vv` – focus on a single module with verbose output.
- `pytest -s` – stream log messages (handy for debugging routing lookups).
- `pytest -k gateway` – run only tests whose names match the expression.

### Coverage by Test Module

| Test file | What it covers |
|-----------|----------------|
| `tests/test_steps.py` | End-to-end step workflow with a fake Nautobot data source. Includes success/edge cases for input validation, gateway fallback logic, next-hop data normalization, and BFS path tracing. |
| `tests/test_interfaces_api.py` | REST data source behavior via the `responses` library. Verifies query parameters sent to Nautobot, enrichment of assigned objects, and gateway lookup fallbacks. |
| `tests/test_utils.py` | `resolve_target_to_ipv4()` happy-path and error handling (IPv6 rejection, hostname resolution failures). |
| `tests/conftest.py` | Ensures the project root is importable so pytest can load the `jobs.network_path_tracing` modules without installation. |

All automated tests are offline—no Nautobot instance or device access is required.

---

## Manual Smoke / Probe Scripts

These helpers live under `tests/` but are intended to be run manually after editing the constants at the top of each file to match your lab.

| Script | Purpose |
|--------|---------|
| `tests/gateway_source_l2_smoke.py` | Exercises layer-2 discovery from the default gateway toward the source endpoint. Stubs out Django/NetworkX when unavailable and reuses the actual workflow steps so you can validate LLDP/ARP behavior in isolation. |
| `tests/f5_icontrol_api_smoke_test.py` | Queries BIG-IP iControl REST API to map a backend IP to pools, virtual servers, and SNAT decisions. Useful when tuning the `F5Client` logic. |
| `tests/palo_api_smoke.py` | Minimal Palo Alto XML API client that authenticates, runs route/FIB lookups, and dumps raw XML responses for troubleshooting. |
| `tests/napalm_nxos_probe.py` | Command-line probe for NX-OS devices via NAPALM (SSH or NX-API). Can capture SSH banners, open session logs, and fetch `get_route_to()` data without Nautobot. |

Each script can be executed directly with `python tests/<script>.py`. They honor the credentials or constants defined at the top of the file and provide detailed debug output to help replicate lab issues.

---

## When to Use Which Tests?

- **Developing or refactoring core logic** – Run `pytest` frequently to catch regressions in the deterministic unit tests.
- **Validating connectivity to lab gear or vendor APIs** – Use the smoke scripts to confirm credentials, API responses, or LLDP/ARP reachability before running the full Nautobot job.

Refer back to the README for job execution details and to `administrators.md` for deeper module-level documentation.
