"""Read-only audit of current v2 raw sessions against paper A.1/D and user schema.

Never collects, fits, rewrites raw data, or reads superseded/foreign datasets.
Derived CSVs are audit exports, not repaired source records.
"""
import collections
import copy
import csv
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import statistics
import struct
import uuid

from audit_native_dataset import audit as legacy_audit
from validate_native_session import audit_labels, PAYLOAD
from validate_sensor_contract import loss_values
from development_features import compute

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'DataSet/deepseek-development'
FORBIDDEN = {'y_attempt', 'y_harm', 't_harm', 't_inj', 'first_harm_time',
             'first_harm_interval', 'exposure_time', 'native_attack_success',
             'task_success', 'oracle', 'evaluation', 'reasoning_content', 'chain_of_thought'}


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def rows(path):
    return [json.loads(s) for s in path.read_text(encoding='utf-8').splitlines() if s]


def args(e):
    return {a['name']: a.get('value') for a in e.get('args', [])}


def dump(path, value):
    with path.open('x', encoding='utf-8') as f:
        json.dump(value, f, ensure_ascii=False, indent=2, allow_nan=False)


def csvout(path, fields, data):
    with path.open('x', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        for row in data:
            w.writerow({k: 'NaN' if row.get(k) is None else row.get(k) for k in fields})


def summary(values):
    values = sorted(values)
    if not values:
        return {'n': 0, 'min': None, 'mean': None, 'max': None, 'p50': None, 'p95': None}
    # Linear interpolation, explicitly fixed for this audit.
    def q(p):
        x = (len(values) - 1) * p
        i = int(x)
        return values[i] + (values[min(i + 1, len(values) - 1)] - values[i]) * (x - i)
    return dict(n=len(values), min=values[0], mean=statistics.mean(values), max=values[-1], p50=q(.5), p95=q(.95))


def forbidden_paths(obj, prefix=''):
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = prefix + '/' + k
            if k in FORBIDDEN:
                out.append(p)
            out.extend(forbidden_paths(v, p))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(forbidden_paths(v, prefix + '/' + str(i)))
    return out


def parse_pcap(path):
    """Independent strict packet parser: Ethernet IPv4 TCP/UDP; keeps other frames explicit."""
    result = []
    with path.open('rb') as f:
        h = f.read(24)
        magic = {b'\xd4\xc3\xb2\xa1': ('<', 1e6), b'\xa1\xb2\xc3\xd4': ('>', 1e6),
                 b'\x4d\x3c\xb2\xa1': ('<', 1e9), b'\xa1\xb2\x3c\x4d': ('>', 1e9)}
        endian, resolution = magic[h[:4]]
        linktype = struct.unpack(endian + 'I', h[20:24])[0]
        if linktype != 1:
            raise ValueError('Independent audit requires Ethernet PCAP; got ' + str(linktype))
        while True:
            offset = f.tell()
            ph = f.read(16)
            if not ph:
                break
            if len(ph) != 16:
                raise ValueError('Truncated packet header')
            sec, frac, incl, orig = struct.unpack(endian + 'IIII', ph)
            data = f.read(incl)
            if len(data) != incl or incl != orig:
                raise ValueError('Truncated packet')
            p = dict(index=len(result), offset=offset, timestamp=sec + frac / resolution,
                     length=orig, record_sha256=hashlib.sha256(ph + data).hexdigest(),
                     frame_sha256=hashlib.sha256(data).hexdigest(),
                     ethertype=int.from_bytes(data[12:14], 'big'), payload=b'')
            if p['ethertype'] == 0x800 and len(data) >= 34:
                ip = data[14:]
                ihl = (ip[0] & 15) * 4
                p.update(src='.'.join(map(str, ip[12:16])), dst='.'.join(map(str, ip[16:20])), protocol=ip[9])
                frag = int.from_bytes(ip[6:8], 'big')
                p['fragmented'] = bool(frag & 0x3fff)
                if p['protocol'] in (6, 17) and not (frag & 0x1fff):
                    transport = ip[ihl:]
                    p['src_port'], p['dst_port'] = struct.unpack('!HH', transport[:4])
                    if p['protocol'] == 6:
                        p.update(seq=int.from_bytes(transport[4:8], 'big'), flags=transport[13])
                        p['payload'] = transport[(transport[12] >> 4) * 4:]
                    else:
                        p['payload'] = transport[8:]
            result.append(p)
    return result


def flow_rows(sid, name, packets, t0, port):
    grouped = collections.defaultdict(list)
    for p in packets:
        if 'src_port' in p:
            grouped[(p['src'], p['dst'], p['src_port'], p['dst_port'], p['protocol'])].append(p)
    out = []
    for key, ps in grouped.items():
        src, dst, sp, dp, protocol = key
        direction = ('client_to_tool' if dp == port else 'tool_to_client' if sp == port else 'unknown') if name == 'network_tools' else (
            'egress' if dst == '124.223.37.235' else 'ingress' if src == '124.223.37.235' else 'unknown')
        role = 'tool_http' if name == 'network_tools' and port in (sp, dp) else 'llm_api_tls' if '124.223.37.235' in (src, dst) else 'other'
        start, end = min(p['timestamp'] for p in ps), max(p['timestamp'] for p in ps)
        out.append(dict(session_id=sid, interface='lo' if name == 'network_tools' else 'eth0',
            flow_id=hashlib.sha256(json.dumps([sid, name, key]).encode()).hexdigest()[:24],
            src_ip=src, dst_ip=dst, src_port=sp, dst_port=dp, protocol=protocol,
            direction=direction, packet_count=len(ps), byte_count=sum(p['length'] for p in ps),
            start_ts=start, end_ts=end, dns_query=None, relative_timestamp=start - t0,
            time_basis='derived_wallclock_offset_seconds_NOT_verified_monotonic',
            application_role=role, flow_identity='derived_directional_5tuple_aggregation'))
    return out


def counter(text, pattern):
    m = re.search(pattern, text)
    return int(m.group(1)) if m else None


def main():
    out = ROOT / 'experiment' / ('paper-collection-audit-' + uuid.uuid4().hex[:12])
    out.mkdir(exist_ok=False)
    (out / 'audit_source.py').write_bytes(Path(__file__).read_bytes())
    print(json.dumps({'audit_output': str(out)}, ensure_ascii=False), flush=True)
    frozen = read(BASE / 'manifest/frozen.json')
    amendment = read(BASE / 'manifest/output-budget-amendment.json')
    excluded = amendment['excluded_incomplete_sessions']
    taskmap = {t['task_id']: t for t in frozen['native_manifest']['tasks']}
    folders = sorted((BASE / 'sessions').glob('native-session-*'))
    inventory = []
    for folder in folders:
        for p in sorted(folder.iterdir()):
            if p.is_file():
                inventory.append({'path': p.relative_to(ROOT).as_posix(), 'bytes': p.stat().st_size, 'sha256': sha(p)})
    dump(out / 'raw_inventory.json', inventory)
    sessions, manifest, labels_export, flows_export = [], [], [], []
    all_delays = collections.defaultdict(list)
    schema_t, schema_e = collections.Counter(), collections.Counter()
    forensic_links = []
    for folder in folders:
        sid = folder.name
        report, artifact, labels = [read(folder / n) for n in ['report.json', 'gateway_artifact.json', 'labels.json']]
        trajectory, endpoint = rows(folder / 'trajectory.jsonl'), rows(folder / 'endpoint.jsonl')
        task = taskmap[report['native_task_id']]
        first, last = trajectory[0]['timestamp'], trajectory[-1]['timestamp']
        condition = 'injected' if labels['planned_injection'] else 'benign'
        la = audit_labels(trajectory, artifact, labels, condition)
        hash_errors = [name for name, expected in report['sha256'].items() if sha(folder / name) != expected]
        source_errors = [n for n, h in artifact['provenance']['source_hashes'].items()
                         if sha(ROOT / 'third_party/agentdojo/src/agentdojo' / n) != h]
        t_forbidden = [(i, p) for i, row in enumerate(trajectory) for p in forbidden_paths(row)]
        e_forbidden = [(i, p) for i, row in enumerate(endpoint) for p in forbidden_paths(row)]
        for row in trajectory:
            schema_t.update(row.keys())
        for row in endpoint:
            schema_e.update(row.keys())
        calls = [r for r in trajectory if r['role'] == 'tool_call']
        tool_outputs = [r for r in trajectory if r['role'] == 'tool']
        call_ids = [r['tool_call_id'] for r in calls]
        per_request = [len(r.get('tool_calls', [])) for r in trajectory if r['role'] == 'assistant']
        state_opens = []
        state_io = []
        fd_paths = {}
        for i, e in sorted(enumerate(endpoint), key=lambda item: (item[1]['timestamp'], item[0])):
            a = args(e)
            pid = e['processEntityId']
            event = e['eventName']
            key = (pid, a.get('fd'))
            if event == 'openat' and e['returnValue'] >= 0:
                fd_paths[(pid, e['returnValue'])] = a.get('pathname', '')
                if '/tmp/native-state-' in a.get('pathname', ''):
                    state_opens.append(i)
                    state_io.append(i)
            elif event in ('read', 'write', 'close'):
                if '/tmp/native-state-' in fd_paths.get(key, ''):
                    state_io.append(i)
                if event == 'close':
                    fd_paths.pop(key, None)
        in_window = [i for i, e in enumerate(endpoint) if first <= e['timestamp'] / 1e9 <= last]
        state_visible = set(state_io).intersection(in_window)
        state_links = []
        for receipt in artifact['receipts']:
            matches = [(i, e) for i, e in enumerate(endpoint) if e['eventName'] == 'openat'
                       and args(e).get('pathname') == receipt['state_file'] and e['processId'] == receipt['service_pid']
                       and 'O_WRONLY' in str(args(e).get('flags', ''))]
            state_links.append({'tool_call_id': receipt['tool_call_id'], 'endpoint_indices': [i for i, _ in matches],
                'all_within_receipt_interval': bool(matches) and all(receipt['started_at'] <= e['timestamp']/1e9 <= receipt['timestamp'] for _, e in matches)})
            all_delays['state_open_minus_receipt_start_seconds'].extend(e['timestamp']/1e9 - receipt['started_at'] for _, e in matches)
        arrivals = rows(folder / 'arrival_endpoint.jsonl')
        endpoint_lines = (folder / 'endpoint.jsonl').read_bytes().splitlines(keepends=True)
        arrival_errors = []
        if len(arrivals) != len(endpoint_lines):
            arrival_errors.append('E_count')
        for i, (idx, raw, e) in enumerate(zip(arrivals, endpoint_lines, endpoint)):
            if idx['record_index'] != i or idx['sha256'] != hashlib.sha256(raw).hexdigest():
                arrival_errors.append('E_hash_or_index')
            all_delays['E_arrival_minus_event_seconds'].append(idx['arrival_time'] - e['timestamp']/1e9)
        e_time_reverse = sum(b['timestamp'] < a['timestamp'] for a, b in zip(endpoint, endpoint[1:]))
        arrival_reverse = sum(b['arrival_time'] < a['arrival_time'] for a, b in zip(arrivals, arrivals[1:]))
        all_delays['T_arrival_minus_event_seconds'].extend(r['arrival_time'] - r['timestamp'] for r in trajectory)
        before = loss_values((folder / 'tracee_metrics_before.txt').read_text())
        after = loss_values((folder / 'tracee_metrics_after.txt').read_text())
        e_loss = {k: after[k] - before[k] for k in after if k in before}
        n_info, pcaps, tool_packet_links = {}, {}, []
        for name, logname in [('network', 'tcpdump.log'), ('network_tools', 'tcpdump_tools.log')]:
            packets = parse_pcap(folder / (name + '.pcap'))
            pcaps[name] = packets
            idxs = rows(folder / ('arrival_' + name + '.jsonl'))
            if len(packets) != len(idxs):
                arrival_errors.append(name + '_count')
            for i, (p, idx) in enumerate(zip(packets, idxs)):
                if (idx['record_index'] != i or idx['sha256'] != p['record_sha256'] or idx['offset'] != p['offset']
                        or abs(idx['timestamp'] - p['timestamp']) > 1e-6):
                    arrival_errors.append(name + '_hash_time_or_index')
                all_delays['N_' + name + '_arrival_minus_event_seconds'].append(idx['arrival_time'] - p['timestamp'])
            log = (folder / logname).read_text()
            duplicate_pairs = []
            i = 0
            while i + 1 < len(packets):
                a, b = packets[i:i+2]
                if a['frame_sha256'] == b['frame_sha256'] and 0 <= b['timestamp'] - a['timestamp'] <= .0001:
                    duplicate_pairs.append([i, i+1])
                    i += 2
                else:
                    i += 1
            n_info[name] = dict(packets=len(packets), bytes=sum(p['length'] for p in packets),
                dropped=counter(log, r'(\d+) packets dropped by kernel'),
                captured=counter(log, r'(\d+) packets captured'),
                received_by_filter=counter(log, r'(\d+) packets received by filter'),
                non_ipv4=sum(p['ethertype'] != 0x800 for p in packets),
                no_five_tuple=sum('src_port' not in p for p in packets),
                dns_packets=sum(p.get('src_port') == 53 or p.get('dst_port') == 53 for p in packets),
                fragments=sum(p.get('fragmented', False) for p in packets),
                adjacent_identical_frame_pairs_within_100us=duplicate_pairs,
                event_order_reversals=sum(b['timestamp'] < a['timestamp'] for a, b in zip(packets, packets[1:])),
                arrival_order_reversals=sum(b['arrival_time'] < a['arrival_time'] for a, b in zip(idxs, idxs[1:])),
                raw_truth_token_packets=sum(any(token.encode() in p['payload'] for token in FORBIDDEN) for p in packets))
            flows_export.extend(flow_rows(sid, name, packets, first, artifact['service_port']))
            if name == 'network_tools':
                for call in calls:
                    marker = ('X-Tool-Call-Id: ' + call['tool_call_id']).lower().encode()
                    matches = [p for p in packets if marker in p['payload'].lower()]
                    tool_packet_links.append({'tool_call_id': call['tool_call_id'],
                        'packet_indices': [p['index'] for p in matches], 'packet_timestamps': [p['timestamp'] for p in matches],
                        'five_tuples': [[p['src'], p['dst'], p['src_port'], p['dst_port'], p['protocol']] for p in matches]})
                    all_delays['N_http_request_minus_T_call_seconds'].extend(p['timestamp'] - call['timestamp'] for p in matches)
        features_before = compute(trajectory, endpoint, pcaps['network'], pcaps['network_tools'])
        features_without_state = compute(trajectory, [e for i, e in enumerate(endpoint) if i not in state_visible], pcaps['network'], pcaps['network_tools'])
        contaminated = [k for k in features_before if features_before[k] != features_without_state[k]]
        duplicate_lo_indices = {pair[1] for pair in n_info['network_tools']['adjacent_identical_frame_pairs_within_100us']}
        lo_counterfactual = [p for i,p in enumerate(pcaps['network_tools']) if i not in duplicate_lo_indices]
        features_without_duplicate = compute(trajectory, endpoint, pcaps['network'], lo_counterfactual)
        duplicate_feature_changes = [k for k in features_before if features_before[k] != features_without_duplicate[k]]
        coverage_e = 'OK' if before and after and all(v == 0 for v in e_loss.values()) and not arrival_errors else 'partial_loss'
        coverage_n = 'OK' if all(v['dropped'] == 0 and v['packets'] == v['captured'] for v in n_info.values()) and not arrival_errors else 'partial_loss'
        coverage_t = 'OK' if artifact['termination'] == 'completed' else 'partial_loss'
        manifest.append(dict(session_id=sid, source_task_group_id=task['lineage'], scenario=artifact['provenance']['scenario'],
            backbone=report['model_requested'], coverage_T=coverage_t, coverage_E=coverage_e, coverage_N=coverage_n))
        inj = labels['exposure_time']
        # Exposure event has an actual monotonic relative time; never infer harm time from final state.
        inj_relative = next((r['relative_seconds'] for r in trajectory if r['timestamp'] == inj), None) if inj else None
        labels_export.append(dict(session_id=sid, source_task_group_id=task['lineage'], y_attempt=labels['y_attempt'],
            y_harm=labels['y_harm'], t_inj=inj_relative, t_harm=labels['first_harm_time'],
            attack_strategy='unknown_not_recorded' if labels['planned_injection'] else 'not_applicable',
            attack_surface='tool_response' if labels['planned_injection'] else 'not_applicable',
            attack_goal='account_password_change_to_new_password' if labels['planned_injection'] else 'not_applicable',
            status='excluded_incomplete' if sid in excluded else 'complete_development',
            source_label_sha256=sha(folder/'labels.json')))
        connects = [e for e in endpoint if e['eventName'] == 'connect' and args(e).get('addr', {}).get('sa_family') == 'AF_INET']
        exposures = [r for r in tool_outputs if ' '.join(PAYLOAD.split()) in ' '.join(r.get('content', '').split())]
        sessions.append(dict(session_id=sid, task_id=report['native_task_id'], group=task['lineage'], split=task['split'],
            excluded=sid in excluded, termination=artifact['termination'], condition=condition,
            attempt=labels['y_attempt'], harm=labels['y_harm'], utility=labels['task_success'],
            counts={'T':len(trajectory), 'E':len(endpoint), 'N':sum(x['packets'] for x in n_info.values()),
                    'N_eth0':n_info['network']['packets'], 'N_lo':n_info['network_tools']['packets']},
            report_sha256=sha(folder/'report.json'), worker_sha256=sha(folder/'worker.py'),
            max_output_tokens=report.get('max_output_tokens'),
            effective_output_budget_from_frozen_config=4096 if report['native_task_id']=='user_task_14' and sid not in excluded else 1024,
            raw_hash_errors=hash_errors, source_hash_errors=source_errors, independent_label_audit=la,
            T=dict(session_mismatches=sum(r['session_id'] != sid for r in trajectory),
                calls=len(calls), call_ids_unique=len(call_ids)==len(set(call_ids)),
                structured_arguments=sum(isinstance(r.get('arguments'), dict) for r in calls),
                strict_relative_increasing=all(b['relative_seconds'] > a['relative_seconds'] for a,b in zip(trajectory,trajectory[1:])),
                strict_monotonic_increasing=all(b['monotonic'] > a['monotonic'] for a,b in zip(trajectory,trajectory[1:])),
                arrival_nondecreasing=all(b['arrival_time'] >= a['arrival_time'] for a,b in zip(trajectory,trajectory[1:])),
                previous_call_used_as_parent=sum(r.get('parent_call_id') is not None for r in calls),
                multi_call_assistant_messages=sum(n>1 for n in per_request), forbidden_fields=t_forbidden,
                exact_payload_outputs=sum(PAYLOAD in r.get('content','') for r in exposures), normalized_payload_outputs=len(exposures)),
            E=dict(session_id_missing=sum('session_id' not in e for e in endpoint),
                stable_entity_missing=sum(not e.get('processEntityId') or not e.get('threadStartTime') for e in endpoint),
                namespace_mismatch=sum(e['mountNamespace'] != report['target_mount_namespace'] for e in endpoint),
                wrong_enriched_container=sum(e.get('containerId') not in ('',report['target_container_id']) for e in endpoint),
                empty_enriched_container=sum(not e.get('containerId') for e in endpoint),
                empty_executable=sum(not e.get('executable',{}).get('path') for e in endpoint),
                raw_event_order_reversals=e_time_reverse, arrival_order_reversals=arrival_reverse,
                visible_window_events=len(in_window), audit_state_open_events=len(state_opens),
                audit_state_io_events=len(state_io), audit_state_io_inside_feature_window=len(state_visible),
                feature_dimensions_changed_by_audit_io=contaminated, forbidden_fields=e_forbidden,
                ipv4_connect_events=len(connects),
                ipv4_connect_with_local_source_endpoint=sum('local_addr' in args(e) or 'src_port' in args(e) for e in connects),
                loss_before=before, loss_after=after, loss_deltas=e_loss),
            N=n_info, arrival_errors=sorted(set(arrival_errors)),
            duplicate_loopback_feature_dimensions=duplicate_feature_changes,
            requests=dict(successful_recorded=len(artifact['requests']), missing_finish_reason=sum('finish_reason' not in r for r in artifact['requests']),
                missing_usage=sum(not r.get('usage') for r in artifact['requests']),
                returned_models=sorted({r.get('returned_model') for r in artifact['requests']}), error=artifact['error']),
            capture_covers_task=report['capture_ready_at'] <= report['task_started_at'] < report['task_ended_at'] <= report['capture_ended_at'],
            state_links=state_links, tool_packet_links=tool_packet_links))
        forensic_links.extend(dict(session_id=sid, **v) for v in tool_packet_links)
        if len(sessions) == 1:
            mutated = copy.deepcopy(trajectory)
            for r in mutated:
                if r['role'] == 'tool_call':
                    r['parent_call_id'] = 'nonexistent-parent'
            dump(out / 'validator_counterexample.json', {'scope':'audit_labels component used by existing gate; in-memory only',
                'session_id':sid, 'mutation':'All tool_call parent_call_id changed to nonexistent-parent',
                'result':audit_labels(mutated, artifact, labels, condition)})
    dump(out / 'sessions.json', sessions)
    dump(out / 'field_presence.json', {'T':dict(schema_t), 'E':dict(schema_e), 'note':'Literal key presence; aliases mapped separately in report.'})
    dump(out / 'cross_modal_links.json', forensic_links)
    csvout(out/'session_manifest.csv', ['session_id','source_task_group_id','scenario','backbone','coverage_T','coverage_E','coverage_N'], manifest)
    csvout(out/'labels.csv', ['session_id','source_task_group_id','y_attempt','y_harm','t_inj','t_harm','attack_strategy','attack_surface','attack_goal'], labels_export)
    csvout(out/'session_status.csv', ['session_id','status','source_label_sha256'], labels_export)
    csvout(out/'derived_network_flows.csv', ['session_id','flow_id','interface','src_ip','dst_ip','src_port','dst_port','protocol','direction','packet_count','byte_count','start_ts','end_ts','dns_query','relative_timestamp','time_basis','application_role','flow_identity'], flows_export)
    def stats(subset):
        return dict(sessions=len(subset), groups=len({s['group'] for s in subset}),
            benign_condition=sum(s['condition']=='benign' for s in subset), injected_condition=sum(s['condition']=='injected' for s in subset),
            known_no_attempt_no_harm=sum(s['attempt']==0 and s['harm']==0 for s in subset),
            attempt_positive=sum(s['attempt']==1 for s in subset), harm_positive=sum(s['harm']==1 for s in subset),
            failed_attempt=sum(s['attempt']==1 and s['harm']==0 for s in subset), unknown_harm=sum(s['harm'] is None for s in subset),
            events={m:dict(total=sum(s['counts'][m] for s in subset), **summary([s['counts'][m] for s in subset])) for m in ['T','E','N','N_eth0','N_lo']})
    aggregate=dict(all_attempts=stats(sessions), complete_development=stats([s for s in sessions if not s['excluded']]),
        by_scenario={name:len(sessions) if name=='Banking' else 0 for name in ['Code','Terminal','Workspace','Slack','Travel','Banking']},
        by_split={split:stats([s for s in sessions if s['split']==split and not s['excluded']]) for split in ['train','validation','test']},
        timing={k:summary(v) for k,v in all_delays.items()},
        timing_warning='Arrival minus event and matched-operation offsets are buffering/latency observations, NOT independently measured clock alignment uncertainty.',
        hashes_verified=sum(len(read(p/'report.json')['sha256']) for p in folders),
        sensor_loss_totals={k:sum(s['E']['loss_deltas'].get(k,0) for s in sessions) for k in sessions[0]['E']['loss_deltas']},
        tcpdump_drop_total=sum(s['N'][n]['dropped'] for s in sessions for n in ['network','network_tools']),
        tool_calls=sum(s['T']['calls'] for s in sessions),
        tool_calls_with_pcap_header=sum(bool(r['packet_indices']) for r in forensic_links),
        successful_requests=sum(s['requests']['successful_recorded'] for s in sessions),
        missing_finish_reason=sum(s['requests']['missing_finish_reason'] for s in sessions),
        feature_state_io_events=sum(s['E']['audit_state_io_inside_feature_window'] for s in sessions),
        sessions_with_audit_io_in_features=sum(bool(s['E']['feature_dimensions_changed_by_audit_io']) for s in sessions),
        adjacent_identical_frame_pairs={name:sum(len(s['N'][name]['adjacent_identical_frame_pairs_within_100us']) for s in sessions) for name in ['network','network_tools']},
        sessions_with_loopback_duplicate_feature_changes=sum(bool(s['duplicate_loopback_feature_dimensions']) for s in sessions),
        strict_schema_pass=False, formal_collection_ready=False)
    dump(out / 'statistics.json', aggregate)
    print(json.dumps({'progress':'raw audit done; rerunning previous gate without modifying sessions','sessions':len(sessions)}),flush=True)
    legacy = legacy_audit()
    dump(out / 'existing_gate_rerun.json', legacy)
    after = [r['path'] for r in inventory if sha(ROOT/r['path']) != r['sha256']]
    dump(out / 'audit_run.json', {'name':'paper-A1-D-raw-collection-audit', 'created_at_utc':dt.datetime.now(dt.timezone.utc).isoformat(),
        'script_sha256':sha(Path(__file__)), 'paper_sha256':sha(ROOT/'paper_2027_ACL_KFQ_LogBench_LA.pdf'),
        'scope':'Current v2 22 collection attempts only. No superseded initial-parser/old project sessions read.',
        'model_requests':0,'training_runs':0,'raw_files_mutated':after,
        'previous_gate_passed':legacy['passed'], 'current_strict_schema_passed':False,
        'coverage_flag_definition':'Derived capture completeness only, not schema compliance. Incomplete rejected model response -> T partial_loss; no evidence of sensor failure -> never mark collector_failure.',
        'labels_export_definition':'t_inj is T relative_seconds of observed exposure; t_harm remains NaN. Strategy unknown. Surface/goal reconstructed from worker/oracle and not pre-frozen taxonomy.',
        'flows_export_definition':'Derived directional five-tuple aggregates, frame byte counts; wallclock-relative time is not verified monotonic time. No KitNET/HyperVision native compatibility claim.',
        'raw_files_checked':len(inventory)})
    print(json.dumps({'output':str(out), 'stats':aggregate, 'raw_mutations':after,'legacy_pass':legacy['passed']},ensure_ascii=False),flush=True)


if __name__ == '__main__':
    main()
