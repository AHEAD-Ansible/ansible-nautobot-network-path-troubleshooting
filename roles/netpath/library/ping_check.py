#!/usr/bin/python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re
import time
from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r'''
---
module: ping_check
short_description: Per-probe ping from the remote source host with detailed results
version_added: "1.1.0"
description:
  - Runs single-probe ping attempts (-c 1) in a loop on the remote source host.
  - Records each attempt's status (success/fail), RTT in ms (if present), and stdout.
  - Succeeds if at least one attempt succeeds; otherwise fails (stops the play when any_errors_fatal: true).
options:
  source:
    description: Source address/hostname (echo only; module runs on the connected host).
    type: str
    required: True
  destination:
    description: Destination IP or hostname to ping.
    type: str
    required: True
  count:
    description: Total number of attempts.
    type: int
    default: 10
  timeout:
    description: Per-probe timeout in seconds (maps to ping -W).
    type: int
    default: 1
  interval:
    description: Sleep seconds between attempts.
    type: float
    default: 0.2
  stop_on_first_success:
    description: If true, stop the loop after the first successful reply.
    type: bool
    default: False
author:
  - AHEAD Networking
'''

RETURN = r'''
attempts:
  description: Per-probe results.
  returned: always
  type: list
  elements: dict
  sample:
    - seq: 1
      success: true
      rc: 0
      rtt_ms: 0.78
      stdout: "64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=0.78 ms"
transmitted:
  type: int
  returned: always
received:
  type: int
  returned: always
packet_loss:
  description: Calculated as (1 - received/transmitted) * 100.
  type: float
  returned: always
raw_output:
  description: Concatenated stdout/stderr of all attempts.
  type: str
  returned: always
used_tool:
  description: 'ping' or 'ping6'
  type: str
  returned: always
'''

# Typical iputils ping line: time=0.78 ms
RTT_RE = re.compile(r'time[=<]?\s*(?P<rtt>[0-9]+(?:\.[0-9]+)?)\s*ms', re.IGNORECASE)

def extract_rtt_ms(text):
    m = RTT_RE.search(text or '')
    return float(m.group('rtt')) if m else None

def run_module():
    module_args = dict(
        source=dict(type='str', required=True),
        destination=dict(type='str', required=True),
        count=dict(type='int', default=10),
        timeout=dict(type='int', default=1),
        interval=dict(type='float', default=0.2),
        stop_on_first_success=dict(type='bool', default=False),
    )

    result = {
        'changed': False,
        'attempts': [],
        'transmitted': 0,
        'received': 0,
        'packet_loss': 100.0,
        'raw_output': '',
        'used_tool': '',
    }

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=False)

    dest = module.params['destination']
    count = module.params['count']
    timeout = module.params['timeout']
    interval = module.params['interval']
    stop_on_first_success = module.params['stop_on_first_success']

    ping_bin = module.get_bin_path('ping', required=False)
    ping6_bin = module.get_bin_path('ping6', required=False)

    if ping_bin:
        base_cmd = [ping_bin, '-n', '-c', '1', '-W', str(timeout)]
        used = 'ping'
    elif ping6_bin:
        base_cmd = [ping6_bin, '-n', '-c', '1', '-W', str(timeout)]
        used = 'ping6'
    else:
        module.fail_json(msg='No ping binary found (ping/ping6). Install iputils-ping.', **result)

    result['used_tool'] = used

    concatenated = []
    successes = 0

    for i in range(1, count + 1):
        cmd = base_cmd + [dest]
        rc, out, err = module.run_command(cmd)
        text = (out or '') + (('\n' + err) if err else '')
        concatenated.append(text)

        rtt = extract_rtt_ms(out or err or '')
        success = (rc == 0)

        result['attempts'].append({
            'seq': i,
            'success': success,
            'rc': rc,
            'rtt_ms': rtt,
            'stdout': (out or err or '').strip(),
        })

        if success:
            successes += 1
            if stop_on_first_success:
                break

        if i < count:
            time.sleep(interval)

    result['transmitted'] = len(result['attempts'])
    result['received'] = successes
    if result['transmitted'] > 0:
        result['packet_loss'] = round((1.0 - (successes / float(result['transmitted']))) * 100.0, 2)
    result['raw_output'] = '\n'.join(s for s in concatenated if s)

    if successes >= 1:
        module.exit_json(**result)
    else:
        module.fail_json(msg=f'Ping failed: {successes}/{result["transmitted"]} replies received', **result)

def main():
    run_module()

if __name__ == '__main__':
    main()

