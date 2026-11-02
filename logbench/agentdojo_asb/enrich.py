"""Enrich an AgentDojo official-engine T/E/N run into the dataset flat-session format.

The official benchmark engine (``agentdojo.scripts.benchmark``) emits:
  * T  — the ``OutputLogger`` JSON (messages + utility/security), and
  * E/N — the E/N sidecar (tracee endpoint events + network pcap + clock sync)
produced by ``scripts/agentdojo_official_ten_coordinator.py``.

This module reuses the KEEP primitives (``scripts.clock_alignment``,
``scripts.packet_metadata``, ``scripts.session_storage``) to enrich those raw
artefacts into the same four-directory session layout that the legacy
split-container collector produces, so ``load_model_inputs`` and
``rebuild_catalog`` accept it unchanged.

Honesty notes encoded into the data (never silently fabricated):
  * ``timestamp_basis`` — T per-message arrival time is NOT recorded by the
    official OutputLogger, so T timestamps are synthetic order-preserving values
    (``synthetic_order``); E/N are real clock-aligned (``tracee_boottime_mapped_to_monotonic``
    and ``pcap_epoch_mapped_to_monotonic`` respectively).
  * ``clock_extrapolated`` — N packets outside the measured clock bracket are
    aligned by nearest-sample extrapolation and flagged.
"""

import csv
import io
import json
import shutil
import sys
import uuid
import os
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from packet_metadata import pcap_packets  # noqa: E402
from clock_alignment import ClockAlignment  # noqa: E402
from session_storage import pack_official_session, rebuild_catalog, digest  # noqa: E402
from agentdojo_to_atif import convert as to_atif  # noqa: E402
from validate_official_session import validate_run, trajectory_for_plan


def _lines(path):
    return [json.loads(line) for line in Path(path).read_text(encoding='utf-8').splitlines() if line]


def _text(blocks):
    """Concatenate the text of OpenAI-style content blocks."""
    if isinstance(blocks, str):
        return blocks
    parts = []
    for block in blocks or []:
        if isinstance(block, str):
            parts.append(block)
        elif isinstance(block, dict) and block.get('type') == 'text':
            parts.append(block.get('content') or '')
    return ''.join(parts)


# ---------------------------------------------------------------------------
# T enrichment
# ---------------------------------------------------------------------------
def enrich_trajectory(tj, report, session_id):
    """Official ``OutputLogger`` messages -> ordered trajectory events.

    assistant messages with ``tool_calls`` expand into one assistant event plus
    one ``tool_call`` event per call, so the output satisfies the legacy
    ``check_trajectory`` parent/tool-result invariants.
    """
    messages = tj.get('messages', [])
    origin = report['clock_origin']
    start = report.get('task_started_at', origin['timestamp'])
    duration = float(tj.get('duration') or 0.0)
    # Expand so we know the total event count before assigning timestamps.
    expanded = []  # (role, payload)
    for msg in messages:
        role = msg.get('role')
        if role == 'assistant' and msg.get('tool_calls'):
            expanded.append(('assistant', msg))
            for call in msg['tool_calls']:
                expanded.append(('tool_call', call))
        else:
            expanded.append((role, msg))

    step = duration / len(expanded) if duration > 0 and len(expanded) > 1 else 0.0
    events = []
    event_index = {}
    for i, (role, payload) in enumerate(expanded):
        ts = start + i * step
        event_id = 'T-%05d' % i
        row = {
            'session_id': session_id,
            'event_id': event_id,
            'role': role,
            'content': None,
            'tool_name': None,
            'tool_arguments': None,
            'tool_return': None,
            'call_id': None,
            'parent_call_id': None,
            'parent_event_id': None,
            'tool_calls': None,
            'timestamp': ts,
            'monotonic': origin['monotonic'] + (ts - origin['timestamp']),
            'relative_timestamp': ts - origin['timestamp'],
            'relative_seconds': ts - origin['timestamp'],
            'arrival_timestamp': ts,
            'arrival_monotonic': origin['monotonic'] + (ts - origin['timestamp']),
            'arrival_time': ts,
            'timestamp_basis': 'synthetic_order',
        }
        if role == 'tool_call':
            row['call_id'] = payload.get('id')
            row['tool_name'] = payload.get('function')
            row['tool_arguments'] = payload.get('args')
            row['parent_event_id'] = event_index.get('assistant')
        elif role == 'tool':
            row['call_id'] = payload.get('tool_call_id')
            row['tool_return'] = _text(payload.get('content'))
        else:
            row['content'] = _text(payload.get('content'))
            if role == 'assistant' and payload.get('tool_calls'):
                row['tool_calls'] = payload['tool_calls']
                event_index['assistant'] = event_id
        events.append(row)
    return events


# ---------------------------------------------------------------------------
# E enrichment
# ---------------------------------------------------------------------------
def _event_args(event):
    return {a['name']: a.get('value') for a in event.get('args', [])}


def enrich_endpoint(run_dir, report, session_id):
    """Raw tracee endpoint events -> enriched E model-input events."""
    endpoint = _lines(run_dir / 'endpoint_agent.jsonl')
    arrivals = _lines(run_dir / 'arrival_endpoint_agent.jsonl')
    samples = _lines(run_dir / 'clock_sync.jsonl')
    alignment = ClockAlignment(samples)
    boot_ns = report['emodality']['boot_ns']
    origin = report['clock_origin']

    parents = {e['processEntityId']: e['parentEntityId'] for e in endpoint}

    def ancestry(pid):
        chain, seen = [], {pid}
        while pid in parents and parents[pid] and parents[pid] not in seen:
            pid = parents[pid]
            seen.add(pid)
            chain.append('%s:agent:%d' % (session_id, pid))
        return chain

    fd_objects = {}
    out = []
    for index, event in enumerate(endpoint):
        args = _event_args(event)
        pid = event['processEntityId']
        name = event['eventName']
        fd = args.get('fd', args.get('sockfd'))
        resource = fd_objects.get((pid, fd), {})
        path = args.get('pathname')
        if name == 'openat' and event['returnValue'] >= 0:
            resource = {'file_path': path, 'file_object_id': None}
            fd_objects[(pid, event['returnValue'])] = resource
        elif name == 'socket' and event['returnValue'] >= 0:
            fd_objects[(pid, event['returnValue'])] = {}
            resource = {}
        elif name == 'connect':
            address = args.get('addr') or {}
            remote = address.get('sin_addr', address.get('sin6_addr'))
            port = address.get('sin_port', address.get('sin6_port'))
            resource = {'socket_five_tuple': [None, None, remote, port, 'TCP'],
                        'connection_id': None}
        if name == 'close':
            fd_objects.pop((pid, fd), None)

        arrival = arrivals[index] if index < len(arrivals) else {}
        aligned = alignment.endpoint(event['timestamp'], boot_ns)
        within = report['task_started_monotonic'] <= aligned <= report['task_ended_monotonic']
        ts_epoch = origin['timestamp'] + aligned - origin['monotonic']
        resolved_path = resource.get('file_path') or path or ''
        collector = (name == 'tracee_info' or event.get('processName') in ('tcpdump','tracee')
            or resolved_path.startswith(('/runs/','/capture/'))
            or (event.get('processName','').startswith('python') and name == 'write' and fd in (1,2)))
        row = dict(event,
                   session_id=session_id,
                   container_role='agent',
                   raw_index=index,
                   stable_process_id='%s:agent:%d' % (session_id, pid),
                   process_ancestry=ancestry(pid),
                   ancestry_complete=False,
                   file_path=resource.get('file_path') or path,
                   file_object_id=resource.get('file_object_id'),
                   socket_five_tuple=resource.get('socket_five_tuple'),
                   connection_id=resource.get('connection_id'),
                   relative_timestamp=aligned - origin['monotonic'],
                   aligned_monotonic=aligned,
                   clock_uncertainty_seconds=alignment.boot_uncertainty,
                   arrival_timestamp=arrival.get('arrival_time'),
                   arrival_relative_timestamp=arrival.get('arrival_monotonic', origin['monotonic']) - origin['monotonic'],
                   observation_role='collector_io' if collector else ('task' if within else 'outside_task'),
                   remote_tool_action=False,
                   event_time_basis='tracee_boottime_mapped_to_monotonic')
        if row['observation_role'] == 'task':
            out.append(row)
    return out


# ---------------------------------------------------------------------------
# N parsing (pure PCAP -> standard traffic structure, no agent attribution)
# ---------------------------------------------------------------------------
def parse_network(run_dir):
    """Parse the capture pcap into standard traffic records.

    This is a thin wrapper over ``packet_metadata.pcap_packets``: input is the
    raw pcap file, output is the standard traffic structure (protocol, endpoints,
    ports, TCP flags, payload length, DNS/TLS metadata, and the raw pcap epoch
    ``timestamp``). It deliberately has NO agent concept — no session/container/
    application/tool attribution, no flow hashes, no clock alignment. Associating
    these packets with the agent/T/E modalities (time-window alignment, session
    attribution) is done later, in the fusion stage.
    """
    return pcap_packets(run_dir / 'capture' / 'network.pcap')


# ---------------------------------------------------------------------------
# Flat-session assembly + dataset packing
# ---------------------------------------------------------------------------
def _find_trajectory(run_dir, attack):
    """Locate the OutputLogger JSON for this run's attack.

    For an injected run (``attack`` != ``none``) we pick the attack's own
    trajectory and skip the ``none`` baseline. For a benign run (``attack`` ==
    ``none``) we pick the ``none`` baseline itself — there is no injected
    trajectory to skip.
    """
    plan = json.loads((run_dir/'00_plan.json').read_text(encoding='utf-8'))
    if plan['attack'] != attack:
        raise ValueError('Attack metadata/plan mismatch')
    return trajectory_for_plan(run_dir, plan)[0]


def _write_jsonl(path, records):
    with Path(path).open('w', encoding='utf-8') as stream:
        for row in records:
            stream.write(json.dumps(row, ensure_ascii=False, allow_nan=False) + '\n')


def _write_csv(path, fieldnames, row):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow({k: ('NaN' if row.get(k) is None else row[k]) for k in fieldnames})


def trajectory_labels(tj, meta, session_id):
    """Planned-attack labels, not exposure; errors invalidate harm evidence.

    AgentDojo can use security=True as an API-error placeholder. Only completed
    boolean utility/security results without an error support a harm label.
    The benign zero means no planned injection goal, not absence of all harms.
    """
    security, utility = tj.get('security'), tj.get('utility')
    attack_type = tj.get('attack_type') or meta.get('attack')
    is_benign = attack_type in (None, 'none')
    completed = not tj.get('error') and type(utility) is bool and type(security) is bool
    y_harm = (0 if is_benign else int(security)) if completed else None
    return {
        'session_id': session_id,
        'source_task_group_id': meta['lineage'],
        'user_task_id': tj.get('user_task_id'),
        'injection_task_id': None if is_benign else tj.get('injection_task_id'),
        'attack_type': 'none' if is_benign else attack_type,
        'y_attempt': 0 if is_benign else 1,
        'y_harm': y_harm,
        'first_harm_time': None,
        'task_success': utility,
        'exposed_injection': None,  # deliberately unverified in this revision
        'oracle_revision': 'agentdojo-official-planned-attempt-r2',
    }


def build_flat_session(run_dir, stage_dir, meta):
    """Assemble a flat session dir that ``pack_session`` can compact."""
    run_dir = Path(run_dir).resolve()
    stage_dir = Path(stage_dir).resolve()
    quality = validate_run(run_dir)
    stage_dir.mkdir(parents=True, exist_ok=False)

    report = json.loads((run_dir / 'report.json').read_text(encoding='utf-8')) if (run_dir / 'report.json').exists() else {}
    tj_path = _find_trajectory(run_dir, meta['attack'])
    tj = json.loads(tj_path.read_text(encoding='utf-8'))
    session_id = report.get('run_id') or ('official-' + digest(str(tj_path).encode())[:12])

    # Derived (enriched) model inputs.
    # T is stored as ATIF: one step object per JSONL line (source/message/tool_calls/
    # observation). Evaluation label fields (security/utility/attack_type/…) are
    # stripped by ``agentdojo_to_atif.convert`` so the trajectory is interaction-only.
    atif = to_atif(tj)
    (stage_dir/'trajectory.atif.json').write_text(json.dumps(atif,ensure_ascii=False),encoding='utf-8')
    _write_jsonl(stage_dir / 'trajectory.jsonl', atif['steps'])
    _write_jsonl(stage_dir / 'endpoint.events.jsonl', enrich_endpoint(run_dir, report, session_id))
    _write_jsonl(stage_dir / 'network.events.jsonl', [p for p in parse_network(run_dir)
        if report['task_started_at'] <= p['timestamp'] <= report['task_ended_at']])
    (stage_dir/'timing.json').write_text(json.dumps({
        'task_started_at':report['task_started_at'], 'task_ended_at':report['task_ended_at'],
        'task_started_relative':report['task_started_monotonic'] - report['clock_origin']['monotonic'],
        'task_ended_relative':report['task_ended_monotonic'] - report['clock_origin']['monotonic']}),encoding='utf-8')

    # Flat report.json (pack_official_session reads run_id / scenario / lineage / backbone).
    # Coordinator QA fields (tracee loss, pcap bytes, E span) are preserved here —
    # the training loader's QA gate depends on them to prove "N really captured the
    # exfiltration" and "tracee lost 0 events", and they must not be dropped.
    flat_report = {
        'run_id': session_id,
        'kind': 'agentdojo_official_TEN',
        'ready': True,  # validate_run above is fail-closed
        'validation': quality,
        'scenario': meta['scenario'],
        'source_task_lineage': meta['lineage'],
        'model_requested': meta['backbone'],
        'reasoning_effort_requested': meta.get('reasoning_effort'),
        'engine': 'agentdojo-official',
        'benchmark_version': tj.get('benchmark_version'),
        'suite': tj.get('suite_name'),
        'user_task_id': tj.get('user_task_id'),
        'injection_task_id': tj.get('injection_task_id'),
        'attack': tj.get('attack_type'),
        'clock_origin': report.get('clock_origin'),
        'task_started_at': report.get('task_started_at'),
        'task_ended_at': report.get('task_ended_at'),
        'clock_policy': report.get('clock_policy'),
        # Coordinator QA (preserved from the raw run report, never fabricated):
        'endpoint': report.get('endpoint'),
        'network': report.get('network'),
        'emodality': report.get('emodality'),
        'receiver_audit_saved': report.get('receiver_audit_saved'),
    }
    (stage_dir / 'report.json').write_text(json.dumps(flat_report, ensure_ascii=False, indent=2), encoding='utf-8')

    # Original injections/error/oracle and exfil audits remain in raw/, never T/E/N.
    labels = trajectory_labels(tj, meta, session_id)
    (stage_dir / 'labels.json').write_text(json.dumps(labels, ensure_ascii=False, indent=2), encoding='utf-8')

    # Per-session catalog CSVs (pack_official_session preserves them verbatim).
    _write_csv(stage_dir / 'session_manifest.csv',
               ['session_id', 'source_task_group_id', 'scenario', 'backbone',
                'collection_ready', 'coverage_T', 'coverage_E', 'coverage_N'],
               {'session_id': session_id, 'source_task_group_id': meta['lineage'],
                'scenario': meta['scenario'], 'backbone': meta['backbone'],
                'collection_ready': True,
                **{k:quality[k] for k in ('coverage_T','coverage_E','coverage_N')}})
    _write_csv(stage_dir / 'labels.csv',
               ['session_id', 'source_task_group_id', 'user_task_id', 'injection_task_id', 'attack_type', 'y_attempt', 'y_harm',
                'first_harm_time', 'task_success', 'exposed_injection', 'oracle_revision'],
               labels)

    # Retain the original evidence until publication and verify the raw copy.
    raw_dst = stage_dir / 'raw'
    shutil.copytree(run_dir, raw_dst)
    for source in run_dir.rglob('*'):
        if source.is_file() and digest(source.read_bytes()) != digest((raw_dst/source.relative_to(run_dir)).read_bytes()):
            raise ValueError('Raw copy hash mismatch')
    return session_id, stage_dir, flat_report, labels


def build_meta(run_dir, batch_id, scenario):
    """Build the per-run pack metadata from the run's frozen ``00_plan.json``.

    attack / user_tasks / injection_tasks / model_id are recovered from the run
    itself (not hardcoded), which is what makes multi-task x multi-strategy sampling
    and the benign (attack=none) case pack correctly. ``lineage`` is stable per
    user_task so lineage-level train/val/test splits never leak a task across splits.
    """
    run_dir = Path(run_dir)
    plan_path = run_dir / '00_plan.json'
    plan = json.loads(plan_path.read_text(encoding='utf-8'))
    attack = plan['attack']
    user_tasks = plan['user_tasks']
    if len(user_tasks) != 1 or scenario.lower() != plan['suite']:
        raise ValueError('Expected one task and matching scenario')
    lineage = 'asb-%s-%s' % (scenario.lower(), user_tasks[0])
    return {
        'batch_id': batch_id,
        'scenario': scenario,
        'dataset_directory': '%s/%s' % (batch_id, scenario.lower()),
        'collection_revision': 'official-single-task-r2',
        'runtime_image': 'logbench-official-agent:r1',
        'tracee_image': 'aquasec/tracee:0.24.1',
        'benchmark_version': plan['benchmark_version'],
        'user_tasks': user_tasks,
        'injection_tasks': plan['injection_tasks'],
        'attack': attack,
        'model_id': plan['model_id'],
        'backbone': plan['model_id'].removeprefix('cn:'),
        'reasoning_effort': plan.get('reasoning_effort'),
        'lineage': lineage,
    }


def pack_into_dataset(run_dir, dataset_batch_dir, meta):
    """Copy, validate and publish once. Never remove the source or an old session."""
    run_dir = Path(run_dir).resolve()
    dataset = Path(dataset_batch_dir)
    if str(run_dir) not in {p for frozen in frozen_cohorts(dataset) for p in frozen['run_dirs']}:
        raise ValueError('Run not in frozen batch')
    session_id = json.loads((run_dir/'report.json').read_text(encoding='utf-8'))['run_id']
    destination = dataset/'sessions'/session_id
    if destination.exists():
        raise FileExistsError('Session already published: ' + session_id)
    stage = dataset/('.stage-' + uuid.uuid4().hex[:12])
    session_id, stage, report, labels = build_flat_session(run_dir, stage, meta)
    packed = pack_official_session(stage, meta)
    destination.parent.mkdir(exist_ok=True)
    os.rename(stage, destination)
    catalog = rebuild_catalog(dataset)
    update_summary(dataset)
    return {'session_id':session_id,'pack':packed,'catalog':catalog,'labels':labels}


def frozen_cohorts(dataset):
    manifest = Path(dataset)/'manifest'
    return [json.loads(p.read_text(encoding='utf-8')) for p in
            [manifest/'frozen.json', *sorted((manifest/'extensions').glob('*.json'))]]


def write_frozen(dataset_batch_dir, plan):
    """Freeze the whole cohort once, before collecting or packing any slot."""
    manifest = Path(dataset_batch_dir)/'manifest'
    manifest.mkdir(parents=True, exist_ok=True)
    path = manifest/'frozen.json'
    extension = plan.get('plan',{}).get('extension_id')
    if extension:
        if Path(extension).name != extension or extension in ('.','..') or not path.is_file():
            raise ValueError('Extension requires an existing batch and a basename ID')
        path = manifest/'extensions'/(extension+'.json')
        path.parent.mkdir(exist_ok=True)
    if path.exists():
        existing = json.loads(path.read_text(encoding='utf-8'))
        if existing != plan:
            # A packing fix may reprocess the same immutable task/sensor evidence.
            packing = {'scripts/agentdojo_to_atif.py','scripts/session_storage.py',
                       'scripts/pack_official_batch.py','logbench/agentdojo_asb/enrich.py'}
            changed = {p for p in set(existing.get('source_hashes',{})) | set(plan.get('source_hashes',{}))
                       if existing.get('source_hashes',{}).get(p) != plan.get('source_hashes',{}).get(p)}
            if ({k:v for k,v in existing.items() if k!='source_hashes'} !=
                {k:v for k,v in plan.items() if k!='source_hashes'} or not changed or not changed <= packing):
                raise ValueError('Frozen collection differs; use a new plan')
            revision = {'frozen_manifest':path.relative_to(manifest).as_posix(),
                        'changed_packing_sources':sorted(changed),'source_hashes':plan['source_hashes']}
            data = json.dumps(revision,sort_keys=True,indent=2).encode('utf-8')
            revisions = manifest/'packing-revisions'
            revisions.mkdir(exist_ok=True)
            target = revisions/(digest(data)+'.json')
            if not target.exists():
                with target.open('xb') as stream:
                    stream.write(data)
        return
    if extension and {p for frozen in frozen_cohorts(dataset_batch_dir) for p in frozen['run_dirs']} & set(plan['run_dirs']):
        raise ValueError('Extension repeats an existing run slot')
    with path.open('x', encoding='utf-8') as stream:
        json.dump(plan, stream, ensure_ascii=False, indent=2)


def update_summary(dataset):
    manifest = Path(dataset)/'manifest'
    with (manifest/'labels.csv').open(encoding='utf-8-sig',newline='') as stream:
        labels = list(csv.DictReader(stream))
    summary = {'planned':sum(len(p['run_dirs']) for p in frozen_cohorts(dataset)), 'published':len(labels),
        'retained_benign':sum(r['y_attempt']=='0' for r in labels),
        'retained_planned_attacks':sum(r['y_attempt']=='1' for r in labels),
        'retained_harm_positive':sum(r['y_harm']=='1' for r in labels),
        'retained_harm_negative':sum(r['y_harm']=='0' for r in labels),
        'retained_harm_unknown':sum(r['y_harm'] not in ('0','1') for r in labels),
        'retained_harm_negative_exposed':None,
        'note':'Development cohort; planned-attack labels; exposure unverified.'}
    tmp = manifest/('.summary-' + uuid.uuid4().hex[:12])
    tmp.write_text(json.dumps(summary,indent=2),encoding='utf-8')
    os.replace(tmp,manifest/'selection_summary.json')
