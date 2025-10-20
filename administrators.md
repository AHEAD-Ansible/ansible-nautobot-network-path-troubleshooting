# Administrators Guide

This document gives Nautobot administrators a high-level but actionable view of
the network path tracing job, the supporting modules, and how execution flows
between them. Use it to understand which component owns each responsibility
and where to look when troubleshooting or extending the workflow.

## Top-Level Layout

```
jobs/
├── __init__.py
├── network_path_tracer_job.py        # Nautobot Job entry point
└── network_path_tracing/             # Reusable toolkit consumed by the job
    ├── __init__.py                   # Public package exports
    ├── config.py                     # Runtime configuration helpers
    ├── cli.py                        # (Optional) CLI utilities
    ├── exceptions.py                 # Domain-specific exception classes
    ├── interfaces/                   # Data source abstractions
    │   ├── nautobot.py               # Protocol & simple dataclasses
    │   ├── nautobot_api.py           # REST API implementation
    │   ├── nautobot_orm.py           # Django ORM implementation used by the job
    │   └── palo_alto.py              # Palo Alto XML API helper
    └── steps/                        # Discrete workflow steps
        ├── input_validation.py
        ├── gateway_discovery.py
        ├── next_hop_discovery.py
        └── path_tracing.py

tests/
└── test_steps.py                     # Step-level unit tests
```

## Execution Flow

1. **Job registration** – `jobs/network_path_tracer_job.py` defines
   `NetworkPathTracerJob` and registers it with Nautobot via the
   `@register_jobs` decorator. The job exposes two Nautobot form variables:
   `source_ip` and `destination_ip`.

2. **Run invocation** – When Nautobot runs the job, `NetworkPathTracerJob.run()`
   orchestrates the entire workflow:
   - Normalizes the inputs (`_to_address_string()`), logs startup metadata and
     unexpected kwargs, and instantiates `NetworkPathSettings` from
     `config.py` (capturing the gateway custom field key, API credentials, etc.).
   - Creates the shared data source (`NautobotORMDataSource`) and the pipeline
     steps (`InputValidationStep`, `GatewayDiscoveryStep`,
     `NextHopDiscoveryStep`, `PathTracingStep`).
   - Runs each step in order, propagating the returned domain models
     (`InputValidationResult`, `GatewayDiscoveryResult`, `PathTracingResult`).
   - Builds the final payload, stores it on the `JobResult` (via
     `_store_path_result()`), and marks completion status.
   - Funnels error conditions through `_fail_job()` which logs with grouping
     metadata, sets job status to failure, and re-raises a `ValueError` so the
     exception is visible in Nautobot.

3. **Result storage** – `_store_path_result()` checks for a JSON custom field
   named `network_path_trace_results` on the `JobResult` model. If present, the
   code prefers `job_result.cf[...]` + `validated_save()` (Nautobot 2.x
   approach); otherwise it falls back to mutating `custom_field_data`. When the
   custom field is missing (or the lookup fails), the payload is written to the
   job log for later inspection.

## Component Responsibilities

### Configuration (`network_path_tracing/config.py`)
`NetworkPathSettings` locks together source/destination IPs, the custom field
key, and optional integrations (Nautobot API, Palo Alto, NAPALM). Each nested
settings dataclass exposes `is_configured()` so callers can gate optional
features.

### Interfaces (`network_path_tracing/interfaces/`)
- `nautobot.py` defines lightweight dataclasses (`IPAddressRecord`,
  `PrefixRecord`, `DeviceRecord`) plus a `NautobotDataSource` protocol used by
  the steps.
- `nautobot_orm.py` is the concrete implementation used by the job. It resolves
  IPs, prefixes, devices, and custom field tagged gateways directly via the
  Nautobot ORM. Key behaviour:
  - `get_ip_address()` fetches the IP and resolves attached interfaces or
    assigned objects to determine the device/interface names.
  - `get_most_specific_prefix()` and `find_gateway_ip()` rely on Nautobot 2.x
    fields (`network__net_contains_or_equals`, `_custom_field_data__…`).
  - `get_device()` extracts platform metadata defensively, working across
    various Nautobot platform schemas.
- `nautobot_api.py` provides an API-based data source (unused by the current
  job but kept for CLI tooling).
- `palo_alto.py` encapsulates the XML API calls used when the platform slug is
  `panos`.

### Workflow Steps (`network_path_tracing/steps/`)
Each step returns a dataclass capturing the outcome and is designed to be
independently testable.

- `input_validation.py` – Validates the source IP, finds the containing prefix,
  and records whether the IP matches the prefix (host vs. subnet). Raises
  `InputValidationError` on failure.
- `gateway_discovery.py` – Discovers the first hop for the path by checking for
  (a) host IPs, (b) a custom field flagged gateway, or (c) the lowest host in
  the prefix. Raises `GatewayDiscoveryError` if it cannot resolve a gateway.
- `next_hop_discovery.py` – Uses platform-specific logic:
  - Palo Alto: authenticates, determines the virtual router, and performs FIB
    or routing table lookups.
  - Other platforms: calls `napalm.get_network_driver()` and logs the chosen
    driver to the Nautobot job log (`grouping="next-hop-discovery"`). It
    normalizes the structure returned by `get_route_to()` so both list and dict
    formats are supported, returning a `NextHopDiscoveryResult` with any
    next-hop IP/interface pairs.
  - Raises `NextHopDiscoveryError` for missing devices, credentials, or lookup
    failures.
- `path_tracing.py` – Recursively traces the path toward the destination using
  repeated `NextHopDiscoveryStep` invocations. It keeps track of seen devices,
  hop count limits, and failure thresholds to avoid loops. The result consists
  of one or more `Path` objects with ordered `PathHop` entries and any
  cross-path issues.

### Exceptions (`network_path_tracing/exceptions.py`)
Simple RuntimeError subclasses (`InputValidationError`,
`GatewayDiscoveryError`, `NextHopDiscoveryError`, `PathTracingError`) used to
signal step-specific failures up the stack.

### Package Export (`network_path_tracing/__init__.py`)
Collects the most-used classes (settings, interfaces, steps, exceptions) so
they can be imported as `from network_path_tracing import …` by both the job
and the tests.

## Testing Strategy

- `tests/test_steps.py` isolates the workflow steps using lightweight fakes and
  monkeypatching. The suite covers input validation, gateway discovery, path
  tracing scenarios (success, blackhole, multi-hop), and NAPALM route parsing.
  The job itself is not executed under pytest, avoiding the need for a full
  Nautobot runtime.

## Operational Notes

- Ensure a JSON custom field named `network_path_trace_results` is assigned to
  `extras.JobResult`. Without it, the job will log results instead of persisting
  them.
- NAPALM credentials (`NAPALM_USERNAME`, `NAPALM_PASSWORD`) and platform slug
  values determine whether next-hop discovery can interrogate network devices.
- Optional integrations (REST API, Palo Alto) are toggled via environment
  variables consumed by `NetworkPathSettings`.

Administrators can now navigate the codebase confidently, understand where
each piece fits, and pinpoint the module responsible for any given behaviour.
