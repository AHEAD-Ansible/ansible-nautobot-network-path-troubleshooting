#!/usr/bin/python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: traceroute_path
short_description: Run traceroute on a Linux source host and parse L3 hop IPs (ECMP-aware)
version_added: "1.0.0"
description:
  - Runs traceroute (or tracepath as a fallback) on the remote source host to a destination.
  - Parses Layer-3 hop IPv4 addresses and returns:
    - hop_ips_by_hop: list of hops; each hop is a list of IPs (ECMP). Unresolved hops are empty lists.
    - path: single-IP-per-hop view (first IP of each hop, unresolved hops omitted).
    - presentable_path: text path (ECMP as {ip1 | ip2}, unresolved hops as *).
options:
  source:
    type: str
    required: True
  destination:
    type: str
    required: True
  max_hops:
    type: int
    default: 30
  timeout:
    type: int
    default: 1
  probes:
    type: int
    default: 3
author:
  - AHEAD Networking
'''

EXAMPLES = r'''
- name: Run traceroute from this host to 8.8.8.8
  traceroute_path:
    source: "{{ inventory_hostname }}"
    destination: 8.8.8.8
    probes: 3   # recommended for ECMP discovery
'''

RETURN = r'''
hop_ips_by_hop:
  description: List of hops; each hop is a list of IPv4 addresses (ECMP). Unresolved hops are empty lists.
  returned: always
  type: list
  elements: list
path:
  description: One-IP-per-hop view (first IP in each hop); unresolved hops omitted.
  returned: always
  type: list
  elements: str
presentable_path:
  description: Human-readable: {ip1 | ip2} for ECMP, '*' for unresolved hops.
  returned: always
  type: str
raw_output:
  description: Raw stdout from traceroute/tracepath.
  returned: success
  type: str
used_tool:
  description: Which tool was used (traceroute or tracepath).
  returned: always
  type: str
rc:
  description: Return code from the command.
  returned: always
  type: int
source:
  returned: always
  type: str
destination:
  returned: always
  type: str
'''

import re
from ansible.module_utils.basic import AnsibleModule

IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

def parse_hops_multi(output: str):
    """
    Return a list of hops where each hop is a list of unique IPv4 addresses
    found on that hop (handles ECMP). Unresolved hops are included as empty
    lists to preserve hop numbering.

    Handles typical traceroute formats like:
      "6  1.2.3.4 (1.2.3.4)  5.2 ms  2.3.4.5 (2.3.4.5)  4.1 ms ..."
    """
    hop_line_re = re.compile(r'^\s*(\d+)[\s?:]+(.*)$')
    hops_multi = []

    for line in output.splitlines():
        s = line.strip()
        if not s:
            continue
        m = hop_line_re.match(s)
        if not m:
            continue
        rest = m.group(2)

        # Collect all IPv4s on this hop line.
        ips = IPV4_RE.findall(rest)

        # Deduplicate within the hop while preserving order
        dedup, seen = [], set()
        for ip in ips:
            try:
                if any(int(o) > 255 for o in ip.split('.')):
                    continue
            except ValueError:
                continue
            if ip not in seen:
                seen.add(ip)
                dedup.append(ip)

        # Even if empty (e.g., "* * *"), append to preserve hop index
        hops_multi.append(dedup)
    return hops_multi

def run_module():
    module_args = dict(
        source=dict(type='str', required=True),
        destination=dict(type='str', required=True),
        max_hops=dict(type='int', default=30),
        timeout=dict(type='int', default=1),
        probes=dict(type='int', default=3),  # 3 probes typical; helps reveal ECMP
    )

    result = {
        'changed': False,
        'path': [],
        'presentable_path': '',
        'raw_output': '',
        'used_tool': '',
        'rc': 0,
    }

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=False)

    dest = module.params['destination']
    max_hops = module.params['max_hops']
    timeout = module.params['timeout']
    probes = module.params['probes']

    traceroute_bin = module.get_bin_path('traceroute', required=False)
    tracepath_bin = module.get_bin_path('tracepath', required=False)

    cmd = None
    used_tool = None
    if traceroute_bin:
        # -n: no DNS, -q: probes per hop, -w: timeout, -m: max hops
        cmd = [traceroute_bin, '-n', '-q', str(probes), '-w', str(timeout), '-m', str(max_hops), dest]
        used_tool = 'traceroute'
    elif tracepath_bin:
        cmd = [tracepath_bin, '-n', dest]
        used_tool = 'tracepath'
    else:
        module.fail_json(msg='Neither traceroute nor tracepath is available on the remote host; install traceroute package.', **result)

    rc, out, err = module.run_command(cmd)

    result.update({
        'rc': rc,
        'raw_output': out or err or '',
        'used_tool': used_tool,
        'source': module.params['source'],
        'destination': dest,
    })

    if rc != 0 and not out:
        module.fail_json(msg='Traceroute command failed', **result)

    hops_multi = parse_hops_multi(out or err or '')
    # Simple one-IP-per-hop view (omit unresolved)
    path = [hop[0] for hop in hops_multi if hop]

    # Presentable: ECMP as {ip1 | ip2}, unresolved as '*'
    tokens = []
    for hop in hops_multi:
        if not hop:
            tokens.append('*')
        elif len(hop) == 1:
            tokens.append(hop[0])
        else:
            tokens.append('{' + ' | '.join(hop) + '}')
    presentable = ' \u2192 '.join(tokens) if tokens else ''

    result['hop_ips_by_hop'] = hops_multi
    result['path'] = path
    result['presentable_path'] = presentable

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
