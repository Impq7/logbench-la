"""Prepare isolated new infrastructure without touching prior experiment directories."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import time

BASE = Path('/root/wxq/agent_benchmark/logbench-la-clean')
BASE.mkdir(parents=True, exist_ok=True)
report = {'timestamp_utc': datetime.datetime.utcnow().isoformat() + 'Z',
          'root': str(BASE), 'checks': []}


def run(args, timeout=120):
    start = time.monotonic()
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=timeout)
        row = {'argv': args, 'returncode': p.returncode,
               'stdout': p.stdout, 'stderr': p.stderr}
    except subprocess.TimeoutExpired as exc:
        row = {'argv': args, 'error': 'TimeoutExpired', 'timeout_seconds': timeout}
    row['elapsed_seconds'] = round(time.monotonic() - start, 3)
    report['checks'].append(row)
    return row


for image in ['docker.io/aquasec/tracee:0.24.1', 'docker.io/library/python:3.11-slim-bookworm']:
    check = run(['docker', 'image', 'inspect', image, '--format', '{{json .RepoDigests}}'])
    if check.get('returncode') != 0:
        run(['docker', 'pull', image])
    run(['docker', 'image', 'inspect', image, '--format', '{{json .RepoDigests}}'])
run(['docker', 'run', '--pull', 'never', '--rm', '--network', 'none', '--entrypoint', '/tracee/tracee', 'docker.io/aquasec/tracee:0.24.1', '--help'], 30)
run(['docker', 'run', '--pull', 'never', '--rm', '--network', 'none', 'docker.io/library/python:3.11-slim-bookworm', 'python', '--version'], 30)
report['ready'] = all(row.get('returncode') == 0 for row in report['checks'][-2:])
stamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
(BASE / ('prepare_' + stamp + '.json')).write_text(json.dumps(report, indent=2))
print(json.dumps(report))
