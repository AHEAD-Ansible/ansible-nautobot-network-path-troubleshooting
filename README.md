# Nautobot Network Path Tracing App

[![Python Version](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![Nautobot Version](https://img.shields.io/badge/nautobot-2.x-blueviolet.svg)](https://nautobot.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)

## Overview

The Nautobot Network Path Tracing App is a plugin for [Nautobot](https://nautobot.com/), an open-source network source of truth and network automation platform. This app enables tracing of network paths between source and destination IP addresses, leveraging Nautobot's IPAM and device data. It supports gateway discovery, next-hop lookups (including ECMP handling), and integrates with external tools like NAPALM and Palo Alto APIs for advanced routing queries.

Key use cases:
- Troubleshooting connectivity issues by visualizing Layer 3 paths.
- Validating routing configurations in multi-device environments.
- Automating path tracing as part of Nautobot Jobs.

The app is modular, with a workflow broken into discrete steps (input validation, gateway discovery, next-hop discovery, and path tracing). It can fetch data directly from Nautobot's ORM (for in-process execution) or via the REST API (for remote/CLI usage).

## Features

- **Path Tracing Workflow**: Traces full L3 paths from source IP to destination, handling ECMP (Equal-Cost Multi-Path) routes.
- **Gateway Discovery**: Locates default gateways using custom fields or fallback to the lowest usable IP in the prefix.
- **Next-Hop Discovery**: Supports NAPALM for device-specific route lookups (e.g., IOS, NX-OS) and Palo Alto API for firewalls.
- **Data Sources**: Nautobot ORM (efficient for Jobs) and REST API (flexible for CLI/remote access).
- **Error Handling**: Custom exceptions for validation, gateway, next-hop, and tracing failures.
- **CLI Tool**: Run individual steps (validation + gateway discovery) from the command line for testing/debugging.
- **Job Integration**: Nautobot Job to execute the full workflow, storing results in custom fields or logs.
- **Testing**: Unit tests for steps, interfaces, and CLI.

## Requirements

- **Nautobot**: Version 2.x (tested with 2.0+).
- **Python**: 3.12+.
- **Dependencies**:
  - NAPALM: For next-hop discovery on network devices (`pip install napalm`).
  - Requests: For API interactions.
  - Optional: Palo Alto PAN-OS SDK or similar for PA integration (not strictly required).
- **Nautobot Custom Field**: A boolean custom field (default: `network_gateway`) on IPAddress objects to tag gateways.
- **Environment Variables** (optional, for API/CLI mode):
  - `NAUTOBOT_API_URL`: Nautobot API base URL (e.g., `http://nautobot.local/`).
  - `NAUTOBOT_API_TOKEN`: API token for authentication.
  - `NAUTOBOT_API_VERIFY_SSL`: Set to `false` to disable SSL verification.
  - `NETWORK_PATH_SOURCE_IP` / `NETWORK_PATH_DESTINATION_IP`: Default IPs for CLI testing.
  - `NETWORK_PATH_GATEWAY_CF`: Custom field name for gateways (default: `network_gateway`).
  - Palo Alto: `PA_USERNAME`, `PA_PASSWORD`, `PA_VERIFY_SSL`.
  - NAPALM: `NAPALM_USERNAME`, `NAPALM_PASSWORD`.

## Installation

1. **Clone the Repository**:
   ```
   git clone https://github.com/your-org/nautobot-network-path-tracing.git
   cd nautobot-network-path-tracing
   ```

2. **Install as Nautobot App**:
   - Add to your Nautobot project's `nautobot_config.py`:
     ```python
     PLUGINS = ["network_path_tracing"]
     PLUGINS_CONFIG = {
         "network_path_tracing": {
             # Optional config here
         }
     }
     ```
   - Run migrations and collect static files:
     ```
     nautobot-server makemigrations network_path_tracing
     nautobot-server migrate
     nautobot-server collectstatic
     ```
   - Restart Nautobot services.

3. **Custom Field Setup**:
   - In Nautobot, create a boolean Custom Field on IPAddress objects named `network_gateway` (or your chosen name).
   - Tag gateway IPs in prefixes with this field set to True.

4. **Job Registration**:
   - The app registers a Job (`NetworkPathTracerJob`) automatically. Access it via Nautobot's Jobs UI.

## Configuration

- **App Settings**: Defined in `NetworkPathSettings` dataclass. Override via environment variables as needed.
- **NAPALM Integration**: Ensure devices in Nautobot have `napalm_driver` set on their Platform (e.g., `ios`, `nxos_ssh`).
- **Palo Alto Integration**: Configure credentials via env vars; the app detects PA devices by platform slug.
- **Custom Field for Results**: Optionally create a JSON Custom Field `network_path_trace_results` on JobResult to store outputs.

For full config options, see `network_path_tracing/config.py`.

## Usage

### In Nautobot (via Job)

1. Navigate to **Jobs** > **Network Path Tracer**.
2. Input source and destination IPs (e.g., `10.0.0.1/24` and `4.2.2.1/24`).
3. Run the Job.
4. View results in the Job log or custom field data (JSON payload with paths, hops, and issues).

Example Result Payload:
```json
{
  "status": "success",
  "source": {
    "address": "10.10.10.10",
    "prefix_length": 24,
    "prefix": "10.10.10.0/24",
    "device_name": "server-1",
    "interface_name": "eth0",
    "is_host_ip": false
  },
  "gateway": {
    "found": true,
    "method": "custom_field",
    "address": "10.10.10.1",
    "device_name": "gw-1",
    "interface_name": "Gig0/0",
    "details": "Gateway tagged via custom field 'network_gateway'."
  },
  "paths": [
    {
      "hops": [
        {
          "device_name": "gw-1",
          "interface_name": "Gig0/0",
          "next_hop_ip": "10.20.20.1",
          "egress_interface": "Gig0/1",
          "details": "NAPALM lookup"
        }
      ],
      "reached_destination": true,
      "issues": []
    }
  ],
  "issues": []
}
```

### CLI Mode

Run individual steps (validation + gateway discovery) for quick testing:
```
python -m network_path_tracing.cli --source-ip 10.10.10.10 --destination-ip 10.20.20.20 --data-source orm --debug
```

- `--data-source`: `orm` (default, requires Nautobot context) or `api` (remote via env vars).
- Output: JSON payload with source and gateway details.

For full CLI options: `python -m network_path_tracing.cli --help`.

## Development and Testing

- **Setup**: `pip install -r requirements.txt` (or use Poetry/Pipenv).
- **Tests**: Run `pytest` from the root directory.
- **Linting**: Use `black`, `flake8`, etc.
- **NAPALM Probe Script**: `tests/napalm_nxos_probe.py` for debugging NX-OS connections.

Contributions welcome! See `CONTRIBUTING.md` (if available) or open issues/PRs.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

- Built on Nautobot's extensible plugin architecture.
- Leverages NAPALM for cross-vendor device interactions.
- Inspired by network automation best practices for path tracing.