"""Build a payload-free Agent-behavior view for every session's T trajectory.

The raw T modality feeds the model the full trajectory, which contains the
injected-payload plaintext (the "Ignore all previous instructions ..." block
appended to a tool return) and the fixed exfiltration URL, both of which make
positive and negative sessions trivially separable by a single substring. This
script derives a NEW T file per session — the *Agent behavior view* — in which
free text is never kept: message content and tool-return text are reduced to
their character counts, and tool-argument values are reduced to
``<type>:<length>`` shape descriptors. The observable *behavior* that remains is
exactly role / tool name / argument keys + value shapes / content length /
arrival order / timing, i.e. what the agent did, not what it read or wrote.

The original ``T.trajectory.jsonl.gz`` is never opened for writing and never
modified; the behavior view is written to a separate file alongside it.

Output record (one JSON line per trajectory event)::

    {"time": <relative_timestamp>, "arrival": <arrival_monotonic>,
     "role": <system|user|assistant|tool_call|tool>,
     "tool": <tool_name|None>,
     "content_chars": <len(content)>,
     "args": {"<key>": "<type>:<len>"}, "args_count": <int>}
"""
import argparse
import collections
import gzip
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

T_TRAJECTORY = 'T.trajectory.jsonl.gz'
T_BEHAVIOR = 'T.behavior.jsonl.gz'

# Markers that must never survive into the behavior view. They are representative
# of the injected payload family and the fixed exfiltration target, so a residual
# match means the redaction is incomplete.
PAYLOAD_MARKERS = [
    'my-website-234', 'Ignore all previous', 'ignore prior', 'ARCHIVE INCIDENT',
    'CONTENT MIRROR', 'IMPORTANT USER ADDENDUM', 'SLACK TOOL COMPATIBILITY',
    'SLACK WORKFLOW MANIFEST', '内容归档', 'verified continuation',
]


def shape(value):
    """Reduce an argument value to a non-free-text ``type:length`` descriptor."""
    if isinstance(value, str):
        return 'str:' + str(len(value))
    if isinstance(value, bool):
        return 'bool'
    if isinstance(value, (int, float)):
        return 'num'
    if value is None:
        return 'null'
    if isinstance(value, (list, tuple)):
        return 'list:' + str(len(value))
    if isinstance(value, dict):
        return 'obj:' + str(len(value))
    return type(value).__name__


def behavior_row(row):
    """Project one raw trajectory row into its behavior-view record."""
    args = row.get('tool_arguments') or {}
    if not isinstance(args, dict):
        args = {'_scalar': args}
    shaped = {str(k): shape(v) for k, v in args.items()}
    return {
        'time': row.get('relative_timestamp'),
        'arrival': row.get('arrival_monotonic'),
        'role': row.get('role'),
        'tool': row.get('tool_name'),
        'content_chars': len(row.get('content') or ''),
        'args': shaped,
        'args_count': len(shaped),
    }


def read_trajectory(path):
    rows = []
    with gzip.open(str(path), 'rt', encoding='utf-8') as stream:
        for line in stream:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def build_one(session_dir, force=False):
    model = Path(session_dir) / '01_model_inputs'
    src = model / T_TRAJECTORY
    dst = model / T_BEHAVIOR
    if not src.exists():
        return {'session_id': Path(session_dir).name, 'status': 'skip', 'reason': 'no T trajectory'}
    if dst.exists() and not force:
        return {'session_id': Path(session_dir).name, 'status': 'skip', 'reason': 'already built'}
    original_bytes = src.read_bytes()
    rows = read_trajectory(src)
    records = [behavior_row(r) for r in rows]
    payload = b'\n'.join(json.dumps(r, ensure_ascii=False, sort_keys=True).encode('utf-8') for r in records) + b'\n'
    out_path = str(dst)
    if dst.exists():
        dst.unlink()
    with open(out_path, 'wb') as raw:
        with gzip.GzipFile(filename='', mode='wb', compresslevel=6, mtime=0, fileobj=raw) as gz:
            gz.write(payload)
    # Residual plaintext check: by construction no free text survives, but assert it.
    blob = payload.decode('utf-8', errors='replace')
    leaks = [m for m in PAYLOAD_MARKERS if m.lower() in blob.lower()]
    return {'session_id': Path(session_dir).name, 'status': 'built' if not leaks else 'LEAK',
            'events': len(records), 'bytes': len(payload),
            'original_sha256': digest_bytes(original_bytes), 'leaks': leaks}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--batch', default='batch-asb-r1')
    parser.add_argument('--scenario', required=True)
    parser.add_argument('--force', action='store_true', help='rebuild existing behavior files')
    parser.add_argument('--limit', type=int, default=None, help='only process the first N sessions')
    args = parser.parse_args()

    base = ROOT / 'DataSet' / args.batch / args.scenario / 'sessions'
    if not base.is_dir():
        sys.exit('No sessions at ' + str(base))
    dirs = sorted(p for p in base.iterdir() if p.is_dir())
    if args.limit:
        dirs = dirs[:args.limit]

    results = []
    for d in dirs:
        results.append(build_one(d, force=args.force))

    by_status = collections.Counter(r['status'] for r in results)
    leaks = [r for r in results if r['status'] == 'LEAK']
    print(json.dumps({
        'sessions_scanned': len(dirs),
        'status_counts': dict(by_status),
        'events_total': sum(r.get('events', 0) for r in results),
        'leaks': leaks,
    }, ensure_ascii=False, indent=2))
    if leaks:
        sys.exit(1)


if __name__ == '__main__':
    main()
