"""Infrastructure-only completion diagnosis, no tool execution or hidden-reasoning persistence."""
import datetime
import hashlib
import json
from pathlib import Path
import urllib.error
import urllib.request
import uuid

config = gateway_config
key = config.pop('api_key')
root = Path('/root/wxq/agent_benchmark/logbench-la-clean')
source_root = Path(globals().get('budget_source_root', str(root / 'development')))
output_root = Path(globals().get('budget_output_root', str(root / 'api_status')))
output_root.mkdir(parents=True, exist_ok=True)
cases = []
for name in ('native-session-b7ce60a826b6', 'native-session-31cbdaebf27a'):
    folder = source_root / name
    trajectory = [json.loads(x) for x in (folder / 'trajectory.jsonl').read_text().splitlines()]
    artifact = json.loads((folder / 'gateway_artifact.json').read_text())
    messages = []
    for row in trajectory:
        if row['role'] not in ('system', 'user', 'assistant', 'tool'):
            continue
        fields = ('role', 'content', 'tool_calls') if row['role'] == 'assistant' else ('role', 'content', 'tool_call_id')
        messages.append({field: row[field] for field in fields if field in row})
    for budget in (1024, 4096):
        body = json.dumps({'model': config['model_requested'], 'messages': messages,
            'tools': artifact['tool_schemas'], 'tool_choice': 'auto', 'stream': False, 'max_tokens': budget}).encode()
        request = urllib.request.Request(config['gateway_base_url'].rstrip('/') + '/chat/completions', data=body,
            headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key})
        row = {'source_session': name, 'max_tokens': budget, 'input_sha256': hashlib.sha256(body).hexdigest()}
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                payload = json.loads(response.read())
                choice = (payload.get('choices') or [{}])[0]
                row.update(http_status=response.status, returned_model=payload.get('model'),
                    response_id=payload.get('id'), finish_reason=choice.get('finish_reason'), usage=payload.get('usage'),
                    tool_call_count=len(choice.get('message', {}).get('tool_calls') or []))
        except urllib.error.HTTPError as exc:
            row.update(http_status=exc.code, error_type=type(exc).__name__)
        except Exception as exc:
            row['error_type'] = type(exc).__name__
        cases.append(row)
result = {'kind': 'completion_budget_diagnostic', 'timestamp_utc': datetime.datetime.utcnow().isoformat() + 'Z',
    'scope': 'Visible context replay only, no agent tool execution, no benchmark samples',
    'history_limitation': 'Only retained visible history replayed; provider hidden continuation is deliberately absent',
    'model_requested': config['model_requested'], 'gateway_base_url': config['gateway_base_url'],
    'cases': cases, 'eligible_for_training': False, 'eligible_for_formal_results': False}
out = output_root / ('completion-budget-' + uuid.uuid4().hex[:12] + '.json')
out.write_text(json.dumps(result, indent=2))
result['remote_evidence'] = str(out)
print(json.dumps(result))
