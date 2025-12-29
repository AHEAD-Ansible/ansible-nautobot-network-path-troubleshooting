# Developer & Administrator Guide

This document is aimed at Nautobot operators and developers who maintain or extend the Network Path Tracer job. It explains how the repository is structured, how the execution flow works, and which modules own the major responsibilities.

---

## Repository Layout

```
jobs/
├── network_path_tracer_job.py      # Nautobot Job entry point
├── __init__.py
└── network_path_tracing/
    ├── __init__.py                 # Public exports
    ├── apps.py / __init__.py       # Plugin metadata
    ├── config.py                   # Environment + runtime settings
    ├── cli.py                      # Optional CLI wrapper
    ├── exceptions.py               # Domain-specific errors
    ├── graph/                      # NetworkX + PyVis helpers
    ├── interfaces/                 # Nautobot data sources + device clients
    ├── steps/                      # Validation, gateway, next-hop, path tracing
    └── utils.py                    # Shared helpers (hostname resolver)

tests/
├── test_steps.py                   # Step-level unit tests
├── test_utils.py                   # Utility tests
├── test_interfaces_api.py          # Nautobot API adapter tests
└── *_smoke.py / *_probe.py         # Optional integration / lab scripts
```

---

## Runtime Flow

1. **Registration** – `NetworkPathTracerJob` is registered via `@register_jobs`. Nautobot exposes the form variables defined at the top of the class (`source_ip`, `destination_ip`, `secrets_group`, etc.).

2. **Execution** – `NetworkPathTracerJob.run()` orchestrates the workflow:
   - Validates and normalizes user inputs via `_to_address_string()` and `resolve_target_to_ipv4()`.
   - Retrieves credentials from the selected `SecretsGroup` and builds `NetworkPathSettings` (using `dataclasses.replace()` to inject username/password everywhere).
   - Instantiates `NautobotORMDataSource`, `InputValidationStep`, `GatewayDiscoveryStep`, `NextHopDiscoveryStep`, and `PathTracingStep`.
   - Executes the steps sequentially, logging each phase with structured metadata (`grouping=` arguments on `self.logger`).
   - Calls `_store_path_result()` to persist the payload in the `network_path_trace_results` custom field if it exists, or logs the payload otherwise.
   - On any error, `_fail_job()` records the failure, sets the `JobResult` to `FAILED`, and returns a safe empty dict to Nautobot.

3. **Result Shape** – The job returns a dict with `source`, `gateway`, `paths[]`, `issues`, and optional `visualization`. This mirrors what the CLI emits for consistency.

---

## Key Modules, Classes, and Functions

### `jobs/network_path_tracer_job.py`
- `NetworkPathTracerJob` – Main Nautobot job.
  - `run()` – performs orchestration described above.
  - `_to_address_string()` – trims whitespace, strips CIDR suffixes, and lowercases hostnames for consistent logging.
  - `_log_hostname_resolution()` – logs when hostnames resolve to different IPv4 addresses.
  - `_store_path_result()` – writes the result dict into `JobResult.cf["network_path_trace_results"]` when the JSON custom field exists; falls back to `custom_field_data` or log output otherwise.
  - `_fail_job(reason)` – central failure handler that logs, updates the `JobResult`, and ensures Nautobot surfaces the error message.

### `jobs/network_path_tracing/config.py`
- `NetworkPathSettings` – Immutable dataclass that bundles the user input, custom-field name, optional Nautobot API settings, Palo Alto, NAPALM, and F5 credentials, plus feature toggles (`enable_layer2_discovery`, `layer2_max_depth`).
- Helper methods (`api_settings()`, `pa_settings()`, etc.) guard optional integrations by returning `None` when credentials are missing.

### `jobs/network_path_tracing/interfaces`
- `nautobot.py` – Defines the shared dataclasses (`IPAddressRecord`, `PrefixRecord`, `DeviceRecord`, `RedundancyMember`, etc.) and the `NautobotDataSource` protocol.
- `nautobot_orm.py` – Concrete data source for in-app execution:
  - `get_ip_address()` / `_build_ip_record()` – fetch IPs via ORM and enrich them with device/interface info.
  - `get_most_specific_prefix()` – uses `network__net_contains_or_equals` to grab the containing prefix.
  - `find_gateway_ip()` – fetches the IP tagged with the configured custom field.
  - `resolve_redundant_gateway()` – maps interface redundancy groups (HSRP/VRRP) to the preferred member.
- `nautobot_api.py` – REST API data source used by the CLI when `--data-source api` is selected.
- `palo_alto.py` / `f5_bigip.py` – Thin clients for vendor APIs. The `NextHopDiscoveryStep` determines when to construct these based on the device platform slug/name.

### `jobs/network_path_tracing/steps`
- `InputValidationStep.run()` – normalizes IPs, ensures a prefix exists, and returns `InputValidationResult`.
- `GatewayDiscoveryStep.run()` – attempts host mode (`/32`), the tagged gateway, then `_fallback_to_lowest_host()`. `GatewayDiscoveryResult` also carries redundancy membership details.
- `NextHopDiscoveryStep.run()` – fetches the gateway device, caches lookups per destination, and dispatches to:
  - `_run_palo_alto_lookup()` – calls `PaloAltoClient.keygen()`, `get_virtual_router_for_interface()`, and merges the XML FIB/route lookup outputs.
  - `_run_f5_lookup()` – queries F5 TMOS APIs to map pools and virtual servers to interfaces (via `F5Client`).
  - `_run_napalm_lookup()` – invokes `napalm.get_network_driver()`, runs `open()` with the supplied credentials, and normalizes `get_route_to()` output into lists of `{next_hop, outgoing_interface}` dicts.
  - On success returns `NextHopDiscoveryResult(found=True, next_hops=[...])`; raises `NextHopDiscoveryError` otherwise.
- `PathTracingStep.run()` – BFS-based loop that:
  - Builds a `NetworkPathGraph` to track nodes and edges.
  - Seeds the queue with the gateway, then repeatedly calls the next-hop step, branching when multiple next hops exist.
  - Uses helper methods like `_process_state()`, `_record_issue()`, `_finalize_path()`, `_node_id_for_device()`, `_collect_source_layer2_path()`, and `_integrate_redundant_gateways()` to manage traversal, dedupe loops, and embed layer-2 context if requested.
  - Returns `PathTracingResult(paths=[Path(...) ...], issues=[...], graph=NetworkPathGraph)`.

### `jobs/network_path_tracing/graph`
- `NetworkPathGraph` – Wrapper around `networkx.MultiDiGraph` with helpers for tagging start/destination nodes, merging attributes, and serializing nodes/edges to JSON.
- `build_pyvis_network(graph)` – Renders the graph via PyVis for interactive viewing. Honors layer-2 edges (dashed) and color-codes start/source/destination nodes.

### `jobs/network_path_tracing/utils.py`
- `resolve_target_to_ipv4(value, field_label)` – Accepts IPs or hostnames, enforces IPv4-only behavior, and raises `InputValidationError` on missing/invalid inputs.

### `jobs/network_path_tracing/cli.py`
- `build_parser()` – Command-line arguments for selecting data source, IPs, visualization output, and NAPALM credentials.
- `select_data_source()` – Returns either `NautobotORMDataSource` or `NautobotAPIDataSource`.
- `run_steps()` – Mirrors `NetworkPathTracerJob.run()` but prints progress to stdout and optionally writes a PyVis HTML file. Useful for reproducing issues outside Nautobot.
- `main()` – CLI entry point when executing the module directly.

---

## Extending the Workflow

- **Adding new device-specific logic** – Extend `NextHopDiscoveryStep` with additional platform detection (e.g., Juniper) and implement a helper similar to `_run_palo_alto_lookup()`. Keep the detection case-insensitive and rely on platform slug/name substrings.
- **Changing default behavior** – Update constants in `config.py` (`_DEFAULT_SOURCE_IP`, `_DEFAULT_GATEWAY_CUSTOM_FIELD`, etc.). Any new settings should use the `_env_flag()/ _env_int()` helpers for consistency.
- **Additional graph metadata** – `NetworkPathGraph.ensure_node()` and `add_edge()` accept arbitrary attributes; update `_process_state()` or `_add_source_node()` in `PathTracingStep` to annotate nodes for downstream visualization consumers.

---

## Operational Considerations

- Create the `network_path_trace_results` JSON custom field on `extras.JobResult` so `_store_path_result()` can persist structured data.
- Ensure platform slugs map cleanly to NAPALM drivers; `NextHopDiscoveryStep._is_palo_alto_device()` and `_NXOS_DRIVERS` are good references for how detection is implemented.
- When running outside Nautobot (CLI or smoke tests), use the provided stubs for Django and NetworkX if you don’t have a full Nautobot environment available—see `tests/gateway_source_l2_smoke.py` for an example.

### Junos/SRX Support

- Detection is centralized in `jobs/network_path_tracing/interfaces/juniper/is_junos_device()`: it prefers `DeviceRecord.napalm_driver == "junos"` (populated by Platform `network_driver_mappings["napalm"]`) and falls back to platform slug/name containing `juniper`, `junos`, or `srx`.
- NETCONF is used over SSH port `830` (via `napalm_optional_args()`); confirm the worker can reach the device on that port and that NETCONF is enabled. A quick check is `ssh -p 830 <user>@<primary_ip>` (expect a NETCONF hello) or `show system services netconf status` on-box.
- Credentials come from the selected SecretsGroup (Generic username/password) and are injected into `NetworkPathSettings.napalm`; CLI usage requires `NAPALM_USERNAME`/`NAPALM_PASSWORD` or equivalent flags.
- Layer-2 fallbacks live in `jobs/network_path_tracing/interfaces/juniper/`: when NAPALM getters raise `NotImplementedError`, `Layer2Discovery` tries `show arp ... | display json`, `show ethernet-switching table mac-address <mac> | display json` / `show bridge mac-table mac-address <mac> | display json`, and `show lldp neighbors detail | display json` via `cli()` to keep MAC/LLDP context populated.
- Troubleshooting surfaces in job logs (grouping `next-hop-discovery`) and CLI output as `NAPALM driver 'junos' failed for <device>: <error>` or `NAPALM lookup failed...`; timeouts typically mean port 830/NETCONF reachability, while auth errors point to SecretsGroup or CLI credentials.

For details on unit tests, smoke scripts, and how to run them, refer to `TESTING.md`.
