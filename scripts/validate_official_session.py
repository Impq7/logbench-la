"""Small fail-closed gate for one official task and its independent sensors."""
import json
from pathlib import Path
import re

from agentdojo_to_atif import convert
from packet_metadata import pcap_packets

REVISION = 'official-single-task-r2'


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def rows(path):
    return [json.loads(line) for line in Path(path).read_text(encoding='utf-8').splitlines() if line.strip()]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def trajectory_for_plan(run_dir, plan):
    files = list(Path(run_dir).glob('openai-compatible/**/*.json'))
    require(len(files) == 1, 'Expected exactly one official trajectory, including no preflight trajectories')
    trajectory = read(files[0])
    expected_attack = plan['attack'] if plan['attack'] not in ('none', None, '') else None
    expected_injection = plan['injection_tasks'][0] if expected_attack else None
    for field, expected in {'suite_name':plan['suite'], 'benchmark_version':plan['benchmark_version'],
        'user_task_id':plan['user_tasks'][0], 'attack_type':expected_attack,
        'injection_task_id':expected_injection}.items():
        actual = trajectory.get(field)
        if field in ('attack_type','injection_task_id') and actual == 'none':
            actual = None
        require(actual == expected, 'Trajectory/plan mismatch: ' + field)
    return files[0], trajectory


def validate_run(run_dir, allow_diagnostic=False):
    root = Path(run_dir)
    report, plan = read(root/'report.json'), read(root/'00_plan.json')
    diagnostic = report.get('diagnostic') is True
    require(not diagnostic or allow_diagnostic, 'Diagnostics cannot enter the dataset')
    require(report.get('ready') is True, 'Coordinator not ready')
    require(plan.get('execution_scope') == 'single_official_task' and not plan.get('positive_control'), 'Mixed execution scope')
    require(report.get('cleanup_ok') is True and report.get('cleanup') and all(x['absent'] for x in report['cleanup']), 'Incomplete cleanup')
    require(report.get('business_network',{}).get('internal') is True, 'Business network not isolated')
    require(report.get('agent_exit_code') == 0 and report.get('sensors_drained') is True, 'Execution/sensor drain failed')
    start, end = report['task_started_monotonic'], report['task_ended_monotonic']
    require(start < end and report['capture_ready_at'] <= report['task_started_at'] <= report['task_ended_at'] <= report['capture_ended_at'], 'Invalid sensor/task interval')
    endpoint = report['endpoint']
    require(endpoint.get('live_matches_final') is True and endpoint.get('metrics_after_ok') is True, 'Endpoint drain/metrics incomplete')
    require(endpoint.get('loss_zero') is True and endpoint.get('loss_after') and all(v == 0 for v in endpoint['loss_after'].values()), 'Unknown/nonzero endpoint loss')
    raw_e = rows(root/'endpoint_agent.jsonl')
    require(any(e.get('eventName') != 'tracee_info' for e in raw_e), 'Empty endpoint capture')
    from clock_alignment import ClockAlignment, tracee_boot_time
    alignment = ClockAlignment(rows(root/'clock_sync.jsonl'))
    boot = tracee_boot_time(raw_e)
    require(any(start <= alignment.endpoint(e['timestamp'],boot) <= end for e in raw_e if e.get('eventName') != 'tracee_info'), 'No endpoint events in task interval')
    packets = pcap_packets(root/'capture/network.pcap')
    require(all(p.get('parse_status') == 'ok' for p in packets), 'Unparsed/truncated packets')
    log = (root/'tcpdump.log').read_text()
    def counter(label):
        found = re.findall(r'(\d+) packets? ' + label, log)
        require(len(found) == 1, 'Missing/ambiguous tcpdump counter: ' + label)
        return int(found[0])
    captured, received, dropped = counter('captured'), counter('received by filter'), counter('dropped by kernel')
    require('listening on' in log and dropped == 0 and captured == len(packets), 'PCAP readiness/count/loss mismatch')
    # Audit transport evidence is QA only. No joins or attribution are exported to N.
    sender, receiver = rows(root/'exfil_sender.jsonl'), rows(root/'exfil_receiver.jsonl')
    require(report.get('receiver_audit_saved') is True, 'Receiver log unavailable')
    require(all(r['send_completed'] and r['success'] for r in sender), 'Fixture transport failure (tool semantics preserved)')
    delivered = [r for r in receiver if r.get('event') == 'exfil_received' and r.get('complete') is True]
    require(len(delivered) == len(sender), 'Receiver/sender completeness mismatch')
    names = {name for p in packets for name in (p.get('dns_query') or [])}
    sni = {p.get('sni_host') for p in packets}
    for record in sender:
        require(record['target'] in names and record['target'] in sni, 'Missing independent DNS/TLS evidence')
    if sender:
        require(any(p.get('src_port') == 443 for p in packets) and any(p.get('dst_port') == 443 for p in packets), 'Missing bidirectional TLS packets')
    if not diagnostic:
        _, trajectory = trajectory_for_plan(root, plan)
        require(not trajectory.get('error') and type(trajectory.get('utility')) is bool and type(trajectory.get('security')) is bool, 'Incomplete official result; retain raw as unknown')
        convert(trajectory)
    return {'revision':REVISION,'passed':True,'coverage_T':'not_applicable' if diagnostic else 'OK',
            'coverage_E':'OK','coverage_N':'OK' if packets else 'valid_empty',
            'pcap_packets':len(packets),'pcap_received':received,'pcap_dropped':dropped,
            'fixture_sends':len(sender),'receiver_complete':len(delivered)}
