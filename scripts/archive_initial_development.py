"""Retain the initial five-session annotation-parser diagnostic without using it for fitting."""
import datetime
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = (root / 'DataSet/deepseek-development').resolve()
destination = (root / 'DataSet/deepseek-development-initial-label-parser').resolve()
if source.parent != (root / 'DataSet').resolve() or destination.parent != source.parent or destination.exists():
    raise ValueError('Archive paths must stay in the explicitly named project DataSet directory')
sessions = sorted(p.name for p in (source / 'sessions').glob('native-session-*'))
if len(sessions) != 5:
    raise ValueError('Expected exactly the five initial diagnostics')
record = {'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'sessions': sessions,
    'reason': 'Exact-string payload matching missed native YAML folded text. Initial labels include a false negative exposure.',
    'eligible_for_training': False, 'eligible_for_formal_results': False, 'fitted_models': 0,
    'new_version': 'banking-native-development-loop-v2'}
with (source / 'excluded_version.json').open('x', encoding='utf-8') as stream:
    json.dump(record, stream, indent=2)
source.rename(destination)
print(str(destination))
