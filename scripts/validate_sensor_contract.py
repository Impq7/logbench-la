"""Fail-closed validation of independently captured diagnostic E/N evidence."""
import argparse
import collections
import json
from pathlib import Path
import re
import struct
from packet_metadata import pcap_packets


def loss_values(text):
    values = {}
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        name, value = line.rsplit(None, 1)
        if 'lost' in name.lower() or 'drop' in name.lower():
            values[name] = float(value)
    return values


def validate(folder):
    errors = []
    detail = {'kind': 'sensor_contract_only', 'benchmark_quality_gate': 'not_evaluated'}
    try:
        report = json.loads((folder / 'report.json').read_text(encoding='utf-8'))
        target = report['target_container_id']
        if not report.get('tracee_ready'):
            errors.append('tracee_not_ready')
        rows = [json.loads(line) for line in (folder / 'endpoint.jsonl').read_text(encoding='utf-8').splitlines() if line]
        if not rows:
            errors.append('endpoint_empty')
        ids = {row.get('container', {}).get('id', row.get('containerId', '')) for row in rows}
        namespaces = {row.get('mountNamespace') for row in rows}
        namespace_verified = namespaces == {report.get('target_mount_namespace')} and None not in namespaces
        if ids != {target} and not (ids <= {'', target} and namespace_verified):
            errors.append('endpoint_container_attribution_mismatch')
        detail['attribution'] = 'container_id' if ids == {target} else 'docker_pid_mount_namespace'
        counts = collections.Counter(row.get('eventName') for row in rows)
        detail['endpoint_event_counts'] = dict(counts)
        for event in ['sched_process_exec', 'sched_process_exit', 'openat', 'read', 'write', 'connect']:
            if counts[event] == 0:
                errors.append('missing_endpoint_event:' + event)
        if not (counts['unlink'] or counts['unlinkat']):
            errors.append('missing_endpoint_delete')
        if not any('/tmp/logbench-sensor-contract.txt' in json.dumps(row) for row in rows):
            errors.append('probe_file_not_observed')
        # Unknown loss counters never mean zero. Check both snapshots and sensor errors.
        before = loss_values((folder / 'tracee_metrics_before.txt').read_text())
        after = loss_values((folder / 'tracee_metrics_after.txt').read_text())
        detail['endpoint_loss_before'] = before
        detail['endpoint_loss_after'] = after
        if not before or before.keys() != after.keys() or any(v != 0 for v in after.values()):
            errors.append('endpoint_loss_unknown_or_nonzero')
        tcpdump = (folder / 'tcpdump.log').read_text()
        dropped = re.search(r'(\d+) packets dropped by kernel', tcpdump)
        captured = re.search(r'(\d+) packets captured', tcpdump)
        if not dropped or int(dropped.group(1)) != 0:
            errors.append('network_loss_unknown_or_nonzero')
        packets = pcap_packets(folder / 'network.pcap')
        detail['packet_count'] = len(packets)
        if not packets or not captured or int(captured.group(1)) != len(packets):
            errors.append('pcap_packet_count_mismatch_or_empty')
        actions = json.loads((folder / 'actions.json').read_text())
        receives = [a for a in actions if a['kind'] == 'service_received']
        responses = [a for a in actions if a['kind'] == 'http_result']
        if len(receives) != 1 or json.loads(receives[0]['body']) != {'sum': 42}:
            errors.append('independent_service_receipt_mismatch')
        if len(responses) != 1 or responses[0]['status'] != 200:
            errors.append('http_response_missing')
        else:
            port = responses[0]['port']
            if not any(p.get('dst_port') == port for p in packets) or not any(p.get('src_port') == port for p in packets):
                errors.append('http_connection_not_bidirectional_in_pcap')
            if not any(row.get('eventName') == 'connect' and str(port) in json.dumps(row) for row in rows):
                errors.append('http_socket_not_linked_to_endpoint')
        if not report['capture_ready_at'] <= report['task_started_at'] < report['task_ended_at'] <= report['capture_ended_at']:
            errors.append('capture_does_not_cover_task')
        detail['arrival_timestamps_available'] = False
        detail['limitations'] = ['No LLM trajectory in this diagnostic', 'No online arrival timestamps',
                                 'No attack or oracle validation', 'No concurrent session isolation test']
    except Exception as exc:
        errors.append(type(exc).__name__ + ': ' + str(exc))
    return dict(detail, passed=not errors, errors=errors)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    result = validate(args.directory)
    (args.directory / 'validation.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['passed'] else 1)
