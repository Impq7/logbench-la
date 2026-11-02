"""Load exactly the hash-verified freshly downloaded infrastructure archive."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

config = json.loads(sys.stdin.readline())
root = Path('/root/wxq/agent_benchmark/logbench-la-clean').resolve()
archive = Path(config['archive']).resolve()
if archive.parent != root or not archive.name.startswith('images-'):
    raise ValueError('Invalid archive location')
h = hashlib.sha256()
with archive.open('rb') as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        h.update(chunk)
if h.hexdigest() != config['sha256']:
    raise ValueError('Archive hash mismatch')
report = {'archive_sha256': h.hexdigest(), 'checks': []}
commands = [
    ['docker', 'load', '-i', str(archive)],
    ['docker', 'image', 'inspect', 'aquasec/tracee:0.19.0', '--format', '{{.Id}}'],
    ['docker', 'image', 'inspect', 'python:3.11-slim-bookworm', '--format', '{{.Id}}'],
    ['docker', 'run', '--pull', 'never', '--rm', '--network', 'none', '--entrypoint', '/tracee/tracee', 'aquasec/tracee:0.19.0', '--help'],
    ['docker', 'run', '--pull', 'never', '--rm', '--network', 'none', 'python:3.11-slim-bookworm', 'python', '--version'],
]
for args in commands:
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True, timeout=180)
    report['checks'].append({'argv': args, 'returncode': p.returncode,
                             'stdout': p.stdout, 'stderr': p.stderr})
    if p.returncode != 0:
        break
report['ready'] = len(report['checks']) == len(commands) and all(c['returncode'] == 0 for c in report['checks'])
(root / ('import_' + config['sha256'][:16] + '.json')).write_text(json.dumps(report, indent=2))
print(json.dumps(report))
