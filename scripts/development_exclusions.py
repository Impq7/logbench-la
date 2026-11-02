"""Only the two explicitly frozen incomplete-budget diagnostics may be excluded."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_exclusions():
    path = ROOT / 'DataSet/deepseek-development/manifest/output-budget-amendment.json'
    if not path.exists():
        return {}, None
    content = json.loads(path.read_text())
    allowed = {'native-session-b7ce60a826b6', 'native-session-31cbdaebf27a'}
    if set(content['excluded_incomplete_sessions']) != allowed:
        raise ValueError('Unexpected exclusion; a new explicit protocol is required')
    for name, expected in content['excluded_incomplete_sessions'].items():
        folder = ROOT / 'DataSet/deepseek-development/sessions' / name
        report = json.loads((folder / 'report.json').read_text())
        artifact = json.loads((folder / 'gateway_artifact.json').read_text())
        labels = json.loads((folder / 'labels.json').read_text())
        if (hashlib.sha256((folder / 'report.json').read_bytes()).hexdigest() != expected['report_sha256']
                or artifact['termination'] != 'error' or labels['y_harm'] is not None
                or report['native_task_id'] != 'user_task_14'):
            raise ValueError('Exclusion cannot hide a completed session or known harmful outcome')
    return content['excluded_incomplete_sessions'], content
