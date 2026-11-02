"""L3 observable-only projections, nine representations, and event windows."""
import collections
import json
import math
import numpy as np

from .artifacts import read, rows, save, save_rows, seal, verify
from scripts.session_storage import load_model_inputs

FORBIDDEN = {'y_attempt', 'y_harm', 't_harm', 'oracle', 'evaluation', 'reasoning_content',
             'planned_injection', 'applied_injection', 'exposed_injection', 'attack_id'}


def project_t(step):
    """Project one ATIF step into the flat T event stream.

    ``step`` is a single ATIF step object (``source`` / ``message`` / ``tool_calls``
    / ``observation``). One step may expand into several flat events:

    * a ``user`` step  -> one ``role='user'`` event;
    * an ``agent`` step -> one ``role='assistant'`` event, plus one ``role='tool_call'``
      event per ``tool_calls`` entry and one ``role='tool'`` event per
      ``observation.results`` entry (the tool return).

    There is no per-message timestamp in ATIF (the official OutputLogger records no
    arrival time), so ``time``/``arrival`` are the step's order index — a stable
    synthetic order used only for ordering and windows, never for cross-modality
    clock alignment (that happens on E/N's real clocks).
    """
    if FORBIDDEN.intersection(step):
        raise ValueError('Truth or hidden reasoning in observable T')
    order = step.get('step_id', 0)
    source = step.get('source')
    message = step.get('message') or ''
    events = []

    def event(role, tool, content, arguments):
        return {'time': order, 'arrival': order, 'role': role, 'tool': tool,
                'content': content, 'arguments': arguments}

    if source == 'user':
        events.append(event('user', None, message, {}))
    elif source == 'agent':
        events.append(event('assistant', None, message, {}))
        for call in step.get('tool_calls') or []:
            events.append(event('tool_call', call.get('function_name'),
                                '', call.get('arguments') or {}))
        for result in (step.get('observation') or {}).get('results') or []:
            events.append(event('tool', None, result.get('content') or '', {}))
    # Unknown sources are ignored (no fabricated role).
    return events


def project_t_behavior(row):
    """Project the pre-built payload-free Agent-behavior view of the T trajectory.

    The behavior view (``T.behavior.jsonl.gz``) already holds ``content_chars`` and
    argument shape descriptors instead of free text, so this projection is a
    pass-through guard: it forbids truth/hidden-reasoning keys and normalises the
    fields consumed by ``behavior_text_window``.
    """
    if FORBIDDEN.intersection(row):
        raise ValueError('Truth or hidden reasoning in observable T behavior view')
    return {'time': row['time'], 'arrival': row['arrival'],
        'role': row['role'], 'tool': row.get('tool'),
        'content_chars': row.get('content_chars', 0),
        'args': row.get('args') or {}, 'args_count': row.get('args_count', 0)}


def path_class(path):
    if not path:
        return 'unknown'
    if path.startswith(('/proc/', '/sys/', '/dev/')):
        return 'kernel_device'
    if path.startswith(('/usr/', '/lib/', '/etc/', '/opt/')):
        return 'system_runtime'
    if path.startswith(('/work/', '/tmp/')):
        return 'workspace_temporary'
    return 'other'


def project_e(row):
    executable = row.get('executable') or {}
    exe_path = executable.get('path', '') if isinstance(executable, dict) else ''
    process = row.get('processName') or ''
    name = row.get('eventName') or row.get('syscall') or ''
    direction = 'read' if name in ('read', 'recvfrom', 'recvmsg') else ('write' if name in ('write', 'sendto', 'sendmsg') else 'other')
    process_class = 'python_runtime' if 'python' in (exe_path + process) else ('container_runtime' if 'runc' in process else 'other')
    role = row.get('container_role') or 'unknown'
    sock = row.get('socket_five_tuple')
    # Preserve the target resource (remote endpoint of an fd->socket association) instead of a bare boolean.
    return {'time': row['relative_timestamp'], 'arrival': row['arrival_relative_timestamp'],
        'event': name, 'process': process, 'process_class': process_class, 'role': role,
        'direction': direction, 'path': row.get('file_path'), 'path_class': path_class(row.get('file_path')),
        'result': 'error' if (row.get('returnValue') or 0) < 0 else 'success',
        'sock_remote': [sock[2], sock[3], sock[4]] if sock else None,
        'sock_known': sock is not None}


def flow_direction(row, initiators=None):
    """Client->server vs server->client, derived from pure packet fields only.

    Never from the enrichment ``direction`` attribution column (which is agent-side
    provenance, not a network property).
    """
    flags = row.get('tcp_flags')
    if flags is not None:
        source = (row.get('src'),row.get('src_port'))
        target = (row.get('dst'),row.get('dst_port'))
        key = tuple(sorted((source,target), key=str))
        if flags & 0x02 and not flags & 0x10:
            if initiators is not None:
                initiators[key] = source
            return 'c2s'
        if initiators is not None and key in initiators:
            return 'c2s' if source == initiators[key] else 's2c'
        return 'unknown'
    dns = row.get('dns')
    if isinstance(dns, dict) and 'is_response' in dns:
        return 's2c' if dns['is_response'] else 'c2s'
    return 'unknown'


def project_n(row, initiators=None):
    """N projection: pure pcap-derivable traffic fields only.

    Input is the pure-PCAP parser output (standard traffic structure + raw epoch
    ``timestamp``). Direction is re-derived from packet fields via ``flow_direction``.
    No agent-attribution field exists in the input (the parser never emits one) and
    no destination IP is projected (shortcut avoidance); the time field is the raw
    pcap epoch timestamp — task-window alignment happens in ``materialize``.
    """
    return {'time': row['timestamp'], 'arrival': row['timestamp'],
        'protocol': row.get('network_protocol', 'unknown'),
        'ip_version': row.get('ip_version'), 'ethertype': row.get('ethertype'),
        'length': row['length'], 'payload_length': row.get('payload_length'),
        'src_port': row.get('src_port'), 'dst_port': row.get('dst_port'),
        'tcp_flags': row.get('tcp_flags'),
        'flow_direction': flow_direction(row, initiators),
        'dns_query': row.get('dns_query') or [],
        'dns_questions': len(row.get('dns_query') or []),
        'dns_is_response': (row.get('dns') or {}).get('is_response'),
        'sni_host': row.get('sni_host'), 'tls_handshake_type': row.get('tls_handshake_type')}


def materialize(out, samples, view='raw'):
    verify(out / '01_contract')
    stage = out / '03_represent'
    stage.mkdir()
    counts = []
    for sample in samples:
        source = out / sample['canonical']
        inputs = load_model_inputs(source, view=view)
        trace = inputs['T']
        if view == 'behavior':
            t_events = [project_t_behavior(r) for r in trace]
            first, last = trace[0]['time'], trace[-1]['time']
        else:
            # ATIF: one step may expand into several flat events, so flatten.
            t_events = [e for step in trace for e in project_t(step)]
        # E/N filtering windows come from timing.json's real task interval, never
        # from the ATIF T (which has no per-message clock). E's ``relative_timestamp``
        # is relative to ``clock_origin.timestamp``; N's ``timestamp`` is raw pcap
        # epoch — so each modality filters on its own domain below.
        timing = read(source/'timing.json')
        first_epoch = timing['task_started_at']
        last_epoch = timing['task_ended_at']
        if first_epoch is None or last_epoch is None:
            raise ValueError('Official-engine session missing task interval: ' + sample['session_id'])
        first_rel = timing['task_started_relative']
        last_rel = timing['task_ended_relative']
        initiators = {}
        streams = {'T': t_events,
            'E': [project_e(r) for r in inputs['E']
                  if r['observation_role'] == 'task'
                  and (first_rel is None or first_rel <= r['relative_timestamp'] <= last_rel)],
            'N': [project_n(r, initiators) for r in sorted(inputs['N'],key=lambda p:p['timestamp'])
                  if first_epoch <= r['timestamp'] <= last_epoch]}
        for modality, events in streams.items():
            events.sort(key=lambda r: r['arrival'])
            if not events:
                raise ValueError('Empty modality cannot be silently filled')
            save_rows(stage / sample['session_id'] / (modality + '.jsonl'), events)
        counts.append({'session_id': sample['session_id'], **{m: len(v) for m, v in streams.items()}})
    save(stage / 'counts.json', counts)
    save(stage / 'contract.json', {'input_fields': 'Explicit projections only; IDs and labels not supplied to feature functions',
        'ordering': 'Per-modality sensor arrival order; offline session prediction only',
        'T_view': view,
        'E': 'Exclude collector_io and outside_task, preserve real task syscalls',
        'N': 'Pure standard-PCAP parse fields (protocol/ports/flags/payload/DNS/TLS/epoch time); no agent attribution, no hashes; task-window alignment done in the fusion stage',
        'semantics': 'Path categories are schema-defined locations, not authorization decisions; N has packet-window summaries, not a native KitNET adapter',
        'T2': 'Fixed lexical character hashing; no pretrained semantic encoder',
        'T_behavior': 'Behavior view: role/tool/argument-shape/content-length only; no free text, no payload plaintext'})
    seal(stage)


def windows(events, size=64, stride=32):
    if not events:
        raise ValueError('Missing modality is unsupported')
    if size <= 0 or not 0 < stride <= size:
        raise ValueError('Invalid window settings')
    result = []
    for start in range(0, len(events), stride):
        result.append(events[start:start + size])
        if start + size >= len(events):
            break
    return result


def text_window(events, level):
    parts = []
    for event in events:
        part = '[ROLE=' + event['role'] + ']'
        if level >= 1:
            part += '[TOOL=' + str(event['tool']) + '][CHARS=' + str(len(event['content'])) + ']'
        if level >= 2:
            part += event['content'] + json.dumps(event['arguments'], sort_keys=True, ensure_ascii=False)
        parts.append(part)
    return '\n'.join(parts)


def behavior_text_window(events, level):
    """Behavior-view T windows: role/tool/argument shapes/content length, never free text."""
    parts = []
    for event in events:
        part = '[ROLE=' + event['role'] + ']'
        if level >= 1:
            part += '[TOOL=' + str(event['tool']) + '][CHARS=' + str(event['content_chars']) + ']'
        if level >= 2:
            if event['args']:
                part += '[ARGS=' + json.dumps(event['args'], sort_keys=True, ensure_ascii=False) + ']'
            part += '[ARGC=' + str(event['args_count']) + ']'
        parts.append(part)
    return '\n'.join(parts)


def e_text_window(events, level):
    """Tokenized E events aligned with T: keep event/process/direction/path and the fd->socket target resource."""
    parts = []
    for event in events:
        part = '[EVT=' + event['event'] + '][ROLE=' + event['role'] + ']'
        if level >= 1:
            part += '[PROC=' + event['process'] + '][DIR=' + event['direction'] + ']'
            if event['sock_remote']:
                rip, rport, proto = event['sock_remote']
                part += '[SOCK=' + str(rip) + ':' + str(rport) + '][PROTO=' + str(proto) + ']'
        if level >= 2:
            if event['path']:
                part += '[PATH=' + event['path'] + ']'
            if event['path_class']:
                part += '[PCLS=' + event['path_class'] + ']'
            part += '[RES=' + event['result'] + ']'
        parts.append(part)
    return '\n'.join(parts)


def count_window(events, modality, level):
    count = collections.Counter()
    count['event_count'] = len(events)
    for e in events:
        if modality == 'E':
            count['syscall=' + e['event']] += 1
            if level >= 1:
                count['process=' + e['process_role']] += 1
                count['direction=' + e['direction']] += 1
            if level >= 2:
                count['path=' + e['path_class']] += 1
                count['result=' + e['result']] += 1
                count['socket_known'] += e['socket_known']
        else:
            count['protocol=' + str(e['protocol'])] += 1
            count['flow_direction=' + e['flow_direction']] += 1
            if level >= 1:
                # Schema-defined bins are fixed before any collection/test inspection.
                count['length_bin=' + str(int(np.searchsorted([64, 256, 1024, 1500], e['length'])))] += 1
                count['bytes'] += e['length']
            if level >= 2:
                count['ip_version=' + str(e['ip_version'])] += 1
                count['ethertype=' + str(e.get('ethertype'))] += 1
                if e.get('src_port') is not None:
                    count['sport=' + str(e['src_port'])] += 1
                if e.get('dst_port') is not None:
                    count['dport=' + str(e['dst_port'])] += 1
                if e.get('tcp_flags') is not None:
                    count['tcp_flags=' + str(e['tcp_flags'])] += 1
                if e.get('payload_length') is not None:
                    count['payload_bytes'] += e['payload_length']
                count['dns_questions'] += e['dns_questions']
                if e.get('dns_is_response') is not None:
                    count['dns_response'] += 1 if e['dns_is_response'] else 0
                for q in e.get('dns_query') or []:
                    count['dns_query=' + str(q)] += 1
                count['tls_sni_present'] += 1 if e.get('sni_host') else 0
                if e.get('sni_host'):
                    count['tls_sni=' + e['sni_host']] += 1
    if modality == 'N' and level >= 1:
        times = sorted(e['time'] for e in events)
        gaps = np.diff(times)
        count['duration'] = times[-1] - times[0]
        for gap in gaps:
            count['iat_bin=' + str(int(np.searchsorted([.001, .01, .1, 1], gap)))] += 1
        if level >= 2:
            lengths = [e['length'] for e in events]
            count['length_mean'] = float(np.mean(lengths))
            count['length_std'] = float(np.std(lengths))
            count['iat_max'] = float(max(gaps, default=0))
    return {key: math.log1p(value) for key, value in count.items()}


def features(events, modality, level, config):
    chunks = windows(events, config['window_events'], config['window_stride'])
    if modality == 'T':
        if config.get('T_view') == 'behavior':
            return [behavior_text_window(w, level) for w in chunks]
        return [text_window(w, level) for w in chunks]
    if modality == 'E':
        return [e_text_window(w, level) for w in chunks]
    return [count_window(w, modality, level) for w in chunks]


def load_streams(out, samples):
    return {s['session_id']: {m: rows(out / '03_represent' / s['session_id'] / (m + '.jsonl')) for m in 'TEN'} for s in samples}
