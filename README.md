# ansible-nautobot-network-path-troubleshooting

Automation toolkit to trace network paths from one or more Linux sources and
enrich the hop-by-hop results with data from Nautobot. The repository bundles
custom Ansible modules for path discovery along with a Nautobot integration
role that turns raw traceroute output into context-aware JSON artifacts.

## Features

- Multi-attempt ICMP reachability test with detailed per-probe reporting.
- ECMP-aware traceroute parsing that retains every responding IP per hop.
- Hop JSON conversion and local artifact capture for offline review.
- Nautobot enrichment that augments each hop with device/interface metadata,
  plus endpoint context for both source and destination.

## Requirements

- Python 3.9+
- Ansible 2.14+ (tested with ansible-core packaged via `requirements.txt`)
- Access to a Nautobot instance with the Network to Code collection enabled.
- SSH reachability from the Ansible control node to each traceroute source.

Install Python dependencies into a virtual environment and pull the Nautobot
collection:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
ansible-galaxy collection install -r requirements.yml
```

## Inventory & Variables

Populate `hosts.ini` (or another inventory) with the traceroute source hosts.
Credentials and global settings live in `group_vars/all.yml`, including:

- `netpath_destination`: Destination IP/hostname for traceroute/ping.
- Nautobot connection parameters (`nautobot_url`, `nautobot_token`, etc.).
- `nautobot_enrich_include`: Toggles for which Nautobot fields to attach
  (device/interface names, IDs, platform, etc.).

Adjust any of these values or override them via `-e` on the command line.

## Running the Playbook

Execute the full workflow with:

```bash
ansible-playbook playbooks/trace.yml -i hosts.ini
```

The playbook executes two roles against each source host:

1. `netpath`: runs `ping_check`, ensures `traceroute`, captures hop structure.
2. `nautobot_enrich`: iterates the hop data and looks up matching Nautobot
   objects via the modular `nautobot_lookup` role.

## Artifacts

Both the raw hop JSON and the enriched output are stored locally under
`playbooks/artifacts/` with a filename of the form:

- `SOURCE__to__DEST.json` (raw hop data)
- `SOURCE__to__DEST__enriched.json` (Nautobot-enriched data)

Enriched payloads follow the structure:

```json
{
  "source": {"ip": "...", "device_name": "...", "platform": "..."},
  "destination": {"ip": "...", "device_name": "...", "platform": "..."},
  "hops": [ ... ]
}
```

These artifacts can be committed for audit purposes or consumed by downstream
systems.

## Repository Layout

- `roles/netpath/` – Custom modules (`ping_check`, `traceroute_path`,
  `hop_path_to_json`) and tasks for discovery.
- `roles/nautobot_enrich/` – Processes hop data, builds enriched artifacts.
- `roles/nautobot_lookup/` – Reusable Nautobot lookup helpers by object type.
- `playbooks/trace.yml` – Entry point playbook orchestrating the workflow.

See the role-specific documentation in each role directory for variable
reference and task flow diagrams.
