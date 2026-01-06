## Network Path Tracer for Nautobot

This repository ships a Nautobot Job that network operators can run on-demand to trace the live forwarding path between two IP endpoints. The job reads Nautobot IPAM data, logs into the first-hop gateway, and walks hop-by-hop (including ECMP branches) using NAPALM and vendor-specific APIs for Palo Alto firewalls and F5 BIG-IP devices. Results are captured in the Nautobot JobResult record and optionally rendered as an interactive PyVis diagram.

### Why run this job?
- Validate routing from a server to a remote service without logging into the server itself.
- Confirm which devices/interfaces forward a flow and spot missing routing or data inconsistencies.
- Capture multi-path (ECMP) information and redundancy groups (HSRP/VRRP) in a single report.
- Provide repeatable troubleshooting steps that rely on Nautobot as the source of truth.

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| Nautobot version | 2.4.x (job tested with Nautobot 2.4.14) |
| Custom Fields | `network_gateway` (Boolean on `ipam.IPAddress`) marks the default gateway within each prefix. Optional but recommended: `network_path_trace_results` (JSON on `extras.JobResult`) for storing job payloads. |
| Secrets | A `SecretsGroup` with Generic/username and Generic/password entries. The same credentials are reused for Palo Alto, NAPALM targets, and F5 unless overridden through environment variables. |
| Device data | Source/destination IPs modeled in IPAM, associated devices/interfaces, and accurate device primary IPs + platform slugs (NAPALM drivers). |
| Optional env vars | `PA_USERNAME`, `PA_PASSWORD`, `F5_USERNAME`, `F5_PASSWORD`, `NAPALM_USERNAME`, `NAPALM_PASSWORD`, etc. See `jobs/network_path_tracing/config.py` for the full list. |

> **Tip:** Even if the source IP is missing from Nautobot, the job can still trace using its containing prefix, but gateway detection relies heavily on the `network_gateway` custom field for accuracy.

---

## Installing the Job

1. **Deploy the app**  
   - Copy this repository into your Nautobot deployment (plugin directory or mounted volume).  
   - Add `my_app.apps.NetworkPathTracingConfig` to `PLUGINS` in `nautobot_config.py`.  
   - Restart Nautobot services so the app and job are registered.

2. **Expose the Job**  
   - Navigate to *Jobs › Available Jobs* in Nautobot and confirm **Network Path Tracer** appears under the plugin’s namespace.  
   - Assign the job to an appropriate Job Queue if you use worker queues.

3. **Create the `network_path_trace_results` custom field (optional but recommended)**  
   - Type: JSON  
   - Object type: `extras.JobResult`  
   - Purpose: allows the job to store its structured payload in the JobResult after execution.

4. **Ensure the `network_gateway` custom field exists on `ipam.IPAddress`**  
   - Boolean field used to tag default gateways.  
   - Apply it to IPs that represent the default gateway for a given prefix.

---

## Preparing Nautobot Data

1. **Tag default gateways** – For each prefix that could be selected as a source subnet, mark the IP object that represents its default gateway with `network_gateway = True`.
2. **Populate redundancy data** – If you model interface redundancy groups (HSRP/VRRP), ensure IPs are associated correctly; the job will resolve preferred members.
3. **Verify device primary IPs and platform slugs** – Next-hop discovery connects via the device’s primary IP using the driver implied by the platform slug (e.g., `cisco_ios`, `nxos`, `panos`, `bigip`).  
4. **Maintain secrets** – The selected `SecretsGroup` **must** provide Generic/username and Generic/password. These credentials are injected into the NAPALM, Palo Alto, and F5 clients automatically.

### Junos/SRX setup

- **Platform mapping** – Ensure the Nautobot Platform for Juniper devices maps `network_driver_mappings["napalm"]` to `junos` (or set `napalm_driver="junos"` on the device). The tracer detects Junos via this mapping first, then by platform slug/name containing `juniper`/`junos`/`srx`.
- **NETCONF reachability** – NAPALM sessions use NETCONF over SSH on port `830` (`jobs/network_path_tracing/interfaces/juniper/napalm_optional_args`). Enable NETCONF on the SRX and allow the Nautobot worker to reach port 830. Quick checks: `ssh -p 830 <user>@<device_primary_ip>` should return the NETCONF hello; `show system services netconf status` should list SSH.
- **Credentials** – The Job uses the SecretsGroup Generic username/password for Junos connections. The CLI expects `NAPALM_USERNAME`/`NAPALM_PASSWORD` (or the equivalent flags). These credentials are reused for layer-2 enrichment when enabled.
- **Layer 2 enrichment** – When layer-2 discovery is on, Junos devices use LLDP/ARP/MAC via NAPALM first and fall back to read-only `show ... | display json` commands when getters are missing.

---

## Running the Job in Nautobot

1. Open **Jobs › Network Path Tracer**.
2. Provide the required fields:
   - **Source IP or FQDN** – Can be `10.0.0.10`, `server01.example.com`, or CIDR notation (`10.0.0.10/24`). Hostnames are resolved to IPv4.
   - **Destination IP or FQDN** – Same behavior as the source input.
   - **Secrets Group** – Supplies the read-only credentials for device access.
3. Optional toggles:
   - **Enable layer 2 discovery** – Tries to build an L2 chain (LLDP/ARP) between the gateway interface and the source endpoint.
   - **Ping endpoints** – Pings source and destination first to refresh ARP/ND caches before pulling routing data.
   - **Check Firewall Logs in Path (Panorama)** – Queries Panorama traffic logs for **DENY** entries matching `source_ip`, `destination_ip`, and a user-provided **destination port** (last 24h, max 10 results). Requires **Destination Port for Firewall Log Check** and **Panorama Device** when enabled.
4. Submit the job. Nautobot queues the execution; monitor the Job log for status updates.

During execution the job will:
1. Resolve hostnames to IPv4 and normalize the inputs.
2. Validate that the source lives in a modeled prefix, even if the IP record itself is missing.
3. Locate the default gateway using the tagged `network_gateway` IP (with fallback to the lowest usable host).
4. Log into the gateway, run route lookups toward the destination, and repeat for each discovered next hop until the destination is reached or limits are hit.
5. Capture every hop, error, and note in the JobResult payload and logs.

---

## Interpreting Results

- **Job Data payload** – Stored in the optional custom field or printed in the log. Includes sections for `source`, `gateway`, `paths[]`, and any global `issues`.
- **Firewall logs (`firewall_logs`)** – Always present for parity with the CLI. When enabled, `status` is `success` (queried successfully, even if `found=false`) or `error` (best-effort failure with safe messages in `errors[]`).
- **Paths list** – Each element shows sequential hops with ingress interface, egress interface, next-hop IP, and descriptive text. Paths that reach the destination are marked with `reached_destination = true`.
- **Issues** – Aggregated warnings such as “Device not found in Nautobot,” “Max hops exceeded,” or “Route lookup returned no next hop.”
- **PyVis visualization** – The Nautobot Job attaches `network_path_trace.html` when graph rendering succeeds; the CLI writes the same HTML via `--visualize-html`. Firewall nodes with matching **DENY** logs render red and include a concise “Firewall Logs (DENY)” hover summary; all tooltips are plain text (no visible `<br>` artifacts).

---

## Optional CLI Workflow

For lab testing or ad-hoc troubleshooting, you can run the exact same steps outside Nautobot:

```bash
python jobs/network_path_tracing/cli.py \
  --data-source orm \
  --source-ip 10.100.100.100 \
  --destination-ip 10.200.200.200 \
  --napalm-username <username> \
  --napalm-prompt-password \
  --visualize-html output/path.html
```

- Use `--data-source api` to run against a remote Nautobot instance (requires `NAUTOBOT_API_URL`/`NAUTOBOT_API_TOKEN`).  
- `--debug` prints the normalized records and serialized graph.  
- The CLI respects the same environment variables defined in `config.py`.

### Optional: Panorama DENY log check (CLI)

The CLI log check uses `PA_USERNAME`/`PA_PASSWORD` (values not shown) and requires `--panorama-host` (or `PANORAMA_HOST`) plus `--log-port`:

```bash
python jobs/network_path_tracing/cli.py \
  --data-source orm \
  --source-ip 10.100.100.100 \
  --destination-ip 10.200.200.200 \
  --check-panorama-logs \
  --panorama-host panorama.example.com \
  --log-port 443
```

---

## Troubleshooting Tips

- **“No default gateway found”** – Ensure the prefix contains an IP tagged with `network_gateway`. For small subnets (/31, /32) the fallback logic may not work.
- **“Device not found in Nautobot”** – Confirm the IP or interface is associated with a Device record and that the device has a primary IP set.
- **NAPALM authentication errors** – Verify the SecretsGroup credentials and that the target device allows SSH/HTTPS login for read-only commands.
- **Palo Alto or F5 lookups failing** – Check that the device platform slug (or name) includes `palo`, `panos`, `f5`, or `bigip` so the job selects the appropriate client, and that the corresponding environment variables are populated.
- **Result payload missing** – Create the `network_path_trace_results` JSON custom field on JobResult; otherwise the job logs the payload and continues.
- **Junos NETCONF failures** – Look for `NAPALM driver 'junos' failed for <device>...` or `NAPALM credentials not configured` in the Job log/CLI output. Confirm the device Platform maps to the `junos` driver, NETCONF is enabled on port 830, and the SecretsGroup/CLI credentials are valid.

For additional implementation details (modules, developer notes, and tests) see `administrators.md` and `TESTING.md`.
