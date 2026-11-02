"""Read the authenticated model catalog; never generates with alternative models."""
import datetime
import hashlib
import json
from pathlib import Path
import urllib.error
import urllib.request
import uuid

config = globals()['gateway_config']
key = config.pop('api_key')
report = {'kind': 'authenticated_gateway_catalog', 'gateway_key_name': config['key_name'],
          'gateway': config['gateway_base_url'], 'requested_model': config['model_requested'],
          'timestamp_utc': datetime.datetime.utcnow().isoformat() + 'Z', 'tls_verified': True,
          'generation_requests': 0}
request = urllib.request.Request(config['gateway_base_url'].rstrip('/') + '/models',
                                headers={'Authorization': 'Bearer ' + key})
try:
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read()
        body = json.loads(raw)
        report.update(http_status=response.status, response_sha256=hashlib.sha256(raw).hexdigest(),
                      model_ids=[item['id'] for item in body.get('data', [])])
    report['requested_model_listed'] = config['model_requested'] in report['model_ids']
    report['case_insensitive_model_matches'] = [m for m in report['model_ids'] if m.casefold() == config['model_requested'].casefold()]
except Exception as exc:
    report.update(http_status=getattr(exc, 'code', None), error_type=type(exc).__name__,
                  error_reason=str(getattr(exc, 'reason', ''))[:1000].replace(key, '[REDACTED]'))
root = Path('/root/wxq/agent_benchmark/logbench-la-clean/api_status')
root.mkdir(parents=True, exist_ok=True)
path = root / ('catalog-' + uuid.uuid4().hex[:12] + '.json')
report['remote_evidence'] = str(path)
path.write_text(json.dumps(report, indent=2))
print(json.dumps(report))
