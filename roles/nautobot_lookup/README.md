# Nautobot Lookup Role

Utility role that centralises Nautobot API lookups for different object types.
It provides small task files (`ip_address.yml`, `device.yml`, `interface.yml`)
that perform consistent filtering, retries, and response normalization.

## Usage

Include the role from another play or role task using:

```yaml
- name: Lookup IP
  ansible.builtin.include_role:
    name: nautobot_lookup
    tasks_from: ip_address
  vars:
    nautobot_lookup_ip: 192.0.2.10
```

Each task file exposes a focused set of variables (see tables below). All tasks
return:

- `nautobot_lookup_raw`: Raw object/content returned by the collection lookup.
- `nautobot_lookup_list`: Normalized list of results (empty if no match).
- `nautobot_lookup_object`: First object from the list, or `{}` if none.
- `nautobot_lookup_found`: Boolean flag indicating whether any match was found.

## Shared Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `nautobot_url` | required | Nautobot base URL (e.g. `http://nautobot/api`). |
| `nautobot_token` | required | API token for authentication. |
| `nautobot_lookup_num_retries` | `3` | Retry attempts for transient failures. |
| `nautobot_lookup_validate_certs` | inherits | TLS validation flag, defaults to `nautobot_validate_certs`. |
| `nautobot_lookup_default_depth` | inherits | Depth value applied when none is provided per lookup. |

## Task Parameters

### `ip_address.yml`

| Variable | Description |
|----------|-------------|
| `nautobot_lookup_ip` | IP address to search (required). |
| `nautobot_lookup_namespace` | Optional namespace filter (defaults to `nautobot_namespace` when available). |
| `nautobot_lookup_depth` | Overrides depth for this lookup. |
| `nautobot_lookup_extra_filters` | Additional filter strings appended to the query. |

### `device.yml`

| Variable | Description |
|----------|-------------|
| `nautobot_lookup_device_name` | Device name (helper filter). |
| `nautobot_lookup_device_filters` | Explicit filter list (e.g. `['id=...']`). |
| `nautobot_lookup_extra_filters` | Additional filters appended to the query. |
| `nautobot_lookup_depth` | Optional depth override. |
| `nautobot_lookup_device_resource` | Override resource path (defaults to `devices`). |

### `interface.yml`

| Variable | Description |
|----------|-------------|
| `nautobot_lookup_interface_device` | Device name helper filter. |
| `nautobot_lookup_interface_name` | Interface name helper filter. |
| `nautobot_lookup_interface_filters` | Explicit filter fragments. |
| `nautobot_lookup_interface_resource` | Override resource path (defaults to `interfaces`). |
| `nautobot_lookup_depth` | Optional depth override. |

### `platform.yml`

| Variable | Description |
|----------|-------------|
| `nautobot_lookup_platform_id` | Platform UUID to fetch. |
| `nautobot_lookup_platform_filters` | Explicit filter list (e.g. `['slug=ios-xe']`). |
| `nautobot_lookup_platform_resource` | Override resource path (defaults to `platforms`). |
| `nautobot_lookup_depth` | Optional depth override. |

## Notes

- All tasks run locally (`delegate_to: localhost`) when invoked within blocks in
  the parent role, keeping API calls off the remote traceroute source host.
- Extend the role by adding more task files for other Nautobot object types
  following the `_run_lookup.yml` helper pattern.
