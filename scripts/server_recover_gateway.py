"""Read only this project's new diagnostic records; no API calls or old samples."""
import json
from pathlib import Path
import subprocess

root = Path('/root/wxq/agent_benchmark/logbench-la-clean/diagnostics')
report = {'kind': 'recover_gateway_diagnostics', 'root': str(root),
          'candidates': [], 'recovery_dirs': []}
if root.is_dir():
    folders = sorted(root.glob('gateway-contract-*'), key=lambda p: p.stat().st_mtime, reverse=True)
    for folder in folders[:30]:
        if not folder.is_dir() or folder.resolve().parent != root.resolve():
            continue
        item = {'run_id': folder.name, 'report_exists': (folder / 'report.json').is_file()}
        if item['report_exists']:
            data = json.loads((folder / 'report.json').read_text())
            item.update(timestamp_utc=data.get('timestamp_utc'), ready=data.get('ready'),
                        termination=data.get('gateway', {}).get('termination'))
        labels_path = folder / 'labels.json'
        if labels_path.is_file():
            labels = json.loads(labels_path.read_text())
            item.update(planned_injection=labels.get('planned_injection'),
                        exposed_injection=labels.get('exposed_injection'),
                        y_attempt=labels.get('y_attempt'), y_harm=labels.get('y_harm'))
            if labels.get('planned_injection'):
                report['recovery_dirs'].append(str(folder))
        report['candidates'].append(item)
p = subprocess.run(['docker', 'ps', '-a', '--filter', 'name=gateway-contract-', '--format', '{{json .}}'],
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=15)
report['project_gateway_containers'] = p.stdout.splitlines()
report['docker_inspect_returncode'] = p.returncode
print(json.dumps(report))
