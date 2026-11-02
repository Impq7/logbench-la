"""Fixed offline TEN features. Only raw T/E/N are accepted; no oracle or task metadata."""
import collections
import math
import statistics

from session_storage import load_model_inputs

ROLES = ('assistant', 'tool_call', 'tool')
TOOLS = ('get_iban', 'send_money', 'schedule_transaction', 'update_scheduled_transaction', 'get_balance',
         'get_most_recent_transactions', 'get_scheduled_transactions', 'read_file', 'get_user_info', 'update_password', 'update_user_info')
EVENTS = ('sched_process_fork', 'sched_process_exec', 'sched_process_exit', 'openat', 'read', 'write', 'close',
          'unlink', 'unlinkat', 'socket', 'connect', 'accept', 'accept4', 'bind', 'listen')
FORBIDDEN = {'y_attempt', 'y_harm', 'planned_injection', 'applied_injection', 'exposed_injection',
             'exposure_time', 'first_harm_time', 'evaluation', 'oracle', 'reasoning_content'}


def compute(trajectory, endpoint, network, network_tools):
    if not trajectory:
        raise ValueError('Empty trajectory cannot be a normal sample')
    if any(FORBIDDEN.intersection(row) for row in trajectory):
        raise ValueError('Forbidden metadata in trajectory')
    first, last = trajectory[0]['timestamp'], trajectory[-1]['timestamp']
    values = {'T_duration_seconds': max(0, last - first)}
    roles = collections.Counter(row['role'] for row in trajectory)
    for role in ROLES:
        values['T_count_' + role] = roles[role]
    for role in ('assistant', 'tool'):
        sizes = [len((r.get('content') or '').encode()) for r in trajectory if r['role'] == role]
        values['T_bytes_' + role] = sum(sizes)
        values['T_max_bytes_' + role] = max(sizes, default=0)
    calls = collections.Counter(row['tool_name'] for row in trajectory if row['role'] == 'tool_call')
    for name in TOOLS:
        values['T_tool_' + name] = calls[name]
    values['T_tool_other'] = sum(v for k, v in calls.items() if k not in TOOLS)
    # Raw Tracee nanoseconds are converted explicitly; no host IDs or path strings become features.
    observed = [r for r in endpoint if first <= r['timestamp'] / 1e9 <= last
                and r.get('observation_role','task')=='task']
    if not observed:
        raise ValueError('No endpoint evidence inside visible task interval')
    events = collections.Counter(r['eventName'] for r in observed)
    for event in EVENTS:
        values['E_event_' + event] = events[event]
    values['E_other'] = sum(v for k, v in events.items() if k not in EVENTS)
    values['E_process_count'] = len({r.get('stable_process_id', r['processEntityId']) for r in observed})
    for name, packets in [('network', network), ('network_tools', network_tools)]:
        packets = [p for p in packets if first <= p['timestamp'] <= last]
        if not packets:
            raise ValueError('No packet evidence inside this networked task interval: ' + name)
        sizes = [p['length'] for p in packets]
        intervals = [max(0, b['timestamp'] - a['timestamp']) for a, b in zip(packets, packets[1:])]
        prefix = 'N_' + name + '_'
        values[prefix + 'packets'] = len(packets)
        values[prefix + 'bytes'] = sum(sizes)
        values[prefix + 'mean_length'] = statistics.mean(sizes)
        values[prefix + 'max_length'] = max(sizes)
        values[prefix + 'std_length'] = statistics.pstdev(sizes)
        values[prefix + 'mean_iat'] = statistics.mean(intervals) if intervals else 0
        values[prefix + 'max_iat'] = max(intervals, default=0)
        values[prefix + 'tcp_packets'] = sum(p.get('protocol') == 6 for p in packets)
        values[prefix + 'five_tuple_count'] = len({(p['src'], p['dst'], p['src_port'], p['dst_port'], p['protocol']) for p in packets if 'src_port' in p})
    return {k: math.log1p(v) for k, v in values.items()}


def extract(folder):
    streams=load_model_inputs(folder)
    packets=streams['N']
    if any('primary_N' in p for p in packets):
        return compute(streams['T'],streams['E'],
            [p for p in packets if p.get('primary_N') and p['capture']=='network_api'],
            [p for p in packets if p.get('primary_N') and p['capture']=='network_tools'])
    return compute(streams['T'],streams['E'],
        [p for p in packets if p['interface']=='eth0'],[p for p in packets if p['interface']=='lo'])
