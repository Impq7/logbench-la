"""Append exact, hash-matched training sources without changing any run result."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('folder', type=Path)
args = parser.parse_args()
metrics = json.loads((args.folder / 'metrics.json').read_text())
out = args.folder / 'sources'
out.mkdir(exist_ok=False)
retained = {}
for name, expected in metrics['source_code_sha256'].items():
    if Path(name).name != name:
        raise ValueError('Invalid source name')
    source = (ROOT / 'scripts' / name).read_bytes()
    if hashlib.sha256(source).hexdigest() != expected:
        raise ValueError('Current source no longer matches the fitted run: ' + name)
    with (out / name).open('xb') as stream:
        stream.write(source)
    retained[name] = expected
with (out / 'manifest.json').open('x', encoding='utf-8') as stream:
    json.dump(retained, stream, indent=2)
print(json.dumps({'retained_sources': len(retained), 'all_hashes_match_fitted_run': True}))
