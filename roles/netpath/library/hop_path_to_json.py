#!/usr/bin/python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r'''
---
module: hop_path_to_json
short_description: Convert a hop list (ECMP-aware) into the requested JSON structure
version_added: "1.0.0"
description:
  - Accepts either:
    - hop_ips_by_hop: list of hops; each hop is a list of IPs (ECMP). Unresolved hops are empty lists.
    - path: back-compat single IP per hop.
  - Produces {"hops": [{"hop": n, "devices": [{"ip": "..."}]}]}.
options:
  hop_ips_by_hop:
    type: list
    elements: list
    required: false
  path:
    type: list
    elements: str
    required: false
  pretty:
    type: bool
    default: True
author:
  - AHEAD Networking
'''

RETURN = r'''
hops:
  description: Structured list of hop dictionaries.
  returned: always
  type: list
json:
  description: Prettified JSON string of the structure (useful for debug output).
  returned: when pretty is True
  type: str
'''

def run_module():
    module_args = dict(
        hop_ips_by_hop=dict(type='list', elements='list', required=False),
        path=dict(type='list', elements='str', required=False),
        pretty=dict(type='bool', default=True),
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    multi = module.params.get('hop_ips_by_hop')
    if multi is not None:
        structure = {
            "hops": [
                {"hop": idx, "devices": [{"ip": ip} for ip in hop]}
                for idx, hop in enumerate(multi, start=1)
            ]
        }
    else:
        path_ips = module.params.get('path') or []
        structure = {
            "hops": [
                {"hop": idx, "devices": ([{"ip": ip}] if ip else [])}
                for idx, ip in enumerate(path_ips, start=1)
            ]
        }

    result = {
        'changed': False,
        'hops': structure['hops'],
    }

    if module.params['pretty']:
        result['json'] = json.dumps(structure, indent=2)

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
