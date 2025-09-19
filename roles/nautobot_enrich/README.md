# Nautobot Enrich Role

Consumes the hop list produced by the `netpath` role and enriches each hop with
metadata fetched from Nautobot. The role writes a second JSON artifact that
includes the original hop data plus optional device/interface identifiers.

## Prerequisites

- `netpath_hops`: Structured hop data from `hop_path_to_json`, typically passed
  via `set_fact` or role-to-role variable sharing.
- Nautobot connection settings (`nautobot_url`, `nautobot_token`, etc.) defined
  in inventory/group vars.
- The `networktocode.nautobot` collection installed locally.

## Workflow

1. Validates the hop input structure and ensures the local artifacts directory
   exists.
2. Iterates each hop through `process_hop.yml`, which:
   - Resets a per-hop device accumulator.
   - Invokes `process_device.yml` for every IP in the hop.
   - Appends the enriched hop data to `enriched_hops`.
3. Enriches the source and destination endpoints using the same lookup logic.
4. Renders the final enriched JSON (with `source`, `destination`, and `hops`)
   and saves it as `SOURCE__to__DEST__enriched.json` on the controller.

## Key Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `nautobot_enrich_artifacts_dir` | `./artifacts` | Local path to store enriched JSON outputs. |
| `nautobot_enrich_include` | see defaults | Toggles fields added to each device (`device_name`, `interface_name`, `platform`, IDs, etc.) for hops and endpoints alike. |
| `nautobot_depth` | `2` | Depth parameter passed to Nautobot lookup for related objects. |

## Related Roles

Relies on the `nautobot_lookup` role to perform reusable Nautobot API lookups by
object type. The shared `_enrich_ip.yml` helper invokes the IP lookup (and, when
needed, the device and platform lookups) for hop devices as well as source and
destination endpoints. The resulting data is incorporated into the enriched
artifact so downstream consumers can easily trace both path hops and endpoints.

When a platform value is unavailable for a resolved device, the enriched
structure still includes `"platform": ""` so downstream consumers can rely on
the key's presence.
