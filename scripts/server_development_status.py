"""Read-only cleanup audit for exactly the recorded new-development container identities."""
import datetime
import json
from pathlib import Path
import re
import subprocess

root = Path('/root/wxq/agent_benchmark/logbench-la-clean')
info = subprocess.run(['docker', 'info', '--format', '{{.ServerVersion}}'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
if info.returncode:
    raise RuntimeError('Docker daemon unavailable; cannot establish cleanup state')
containers = []
for path in sorted((root / 'development').glob('native-session-*/report.json')):
    report = json.loads(path.read_text())
    name = report['run_id']
    if not re.fullmatch(r'native-session-[0-9a-f]{12}', name) or path.parent.name != name:
        raise ValueError('Unexpected development identity')
    for identity in (report['target_container_id'], name + '-tracee'):
        process = subprocess.run(['docker', 'inspect', '--format', '{{.State.Running}}', identity],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        absent = process.returncode != 0 and ('No such object' in process.stderr or 'No such container' in process.stderr)
        containers.append({'session_id': name, 'identity': identity, 'removed': absent,
            'running': process.stdout.strip() == 'true' if process.returncode == 0 else None,
            'inspection_error': None if absent or process.returncode == 0 else process.stderr[:200]})
result = {'kind': 'recorded_development_container_cleanup', 'timestamp_utc': datetime.datetime.utcnow().isoformat() + 'Z',
    'root': str(root), 'containers': containers, 'ready': bool(containers) and all(c['removed'] for c in containers),
    'generation_requests': 0, 'mutations': 0}
print(json.dumps(result))
