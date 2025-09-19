# NetPath Role

Runs reachability checks and traceroute path discovery from each traceroute
source host. The role makes use of lightweight custom modules to produce a
detailed hop-by-hop JSON structure that downstream roles can consume.

## Tasks Overview

1. `ping_check`: Validates reachability to the destination using single-probe
   pings in a loop, capturing success/RTT per attempt.
2. Ensures the `traceroute` package is present on the remote host.
3. `traceroute_path`: Executes an ECMP-aware traceroute and parses the Layer-3
   hop responses.
4. `hop_path_to_json`: Normalizes the hop list into JSON with hop indices and
   per-hop device lists.
5. Saves the structured JSON to `playbooks/artifacts/` on the controller.

## Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `netpath_destination` | required | Destination IP/hostname for ping/traceroute. |
| `ansible_host` | inventory | Override source IP/hostname if different from inventory name. |
| `hop_json` | derived | Registered output from `hop_path_to_json` (list of hops). |

## Custom Modules

- `ping_check.py`: Runs iterative pings with stop-on-success support and detailed
  metrics per attempt.
- `traceroute_path.py`: Parses traceroute output, preserving ECMP paths and
  unresolved hops.
- `hop_path_to_json.py`: Converts hop lists into JSON and returns both structured
  data and a prettified string.

## Artifacts

The role saves `SOURCE__to__DEST.json` locally (relative to the playbook
execution directory) for each host processed.
