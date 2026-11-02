"""Timestamp the declared detector search before validation/test task model calls."""
import datetime
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = root / 'configs/development-detectors.json'
out = root / 'DataSet/deepseek-development/manifest/detector-plan.json'
with out.open('x', encoding='utf-8') as stream:
    json.dump({'created_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'settings_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
        'settings': json.loads(source.read_text())}, stream, indent=2)
print(str(out))
