"""Freeze development lineage splits before any task model calls."""
import datetime
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
out = root / 'DataSet/deepseek-development/manifest/frozen.json'
out.parent.mkdir(parents=True, exist_ok=True)
native = root / 'configs/native-development.json'
gateway = root / 'configs/pilot.json'
content = {'created_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'eligible_for_formal_results': False, 'uses_historical_samples': False,
    'native_manifest': json.loads(native.read_text()), 'gateway_snapshot': json.loads(gateway.read_text()),
    'native_manifest_sha256': hashlib.sha256(native.read_bytes()).hexdigest(),
    'gateway_config_sha256': hashlib.sha256(gateway.read_bytes()).hexdigest()}
groups = [t['lineage'] for t in content['native_manifest']['tasks']]
if len(set(groups)) != len(groups):
    raise ValueError('Duplicate task lineage in manifest')
with out.open('x', encoding='utf-8') as stream:
    json.dump(content, stream, indent=2)
print(str(out))
