"""Reconstruct development metrics from persisted predictions and frozen decisions only."""
import argparse
import hashlib
import json
from pathlib import Path

from train_development_detectors import metrics

parser = argparse.ArgumentParser()
parser.add_argument('folder', type=Path)
args = parser.parse_args()
selection_path = args.folder / 'frozen_selection.json'
selection = json.loads(selection_path.read_text())
selection_sha = hashlib.sha256(selection_path.read_bytes()).hexdigest()
predictions = [json.loads(row) for row in (args.folder / 'predictions.jsonl').read_text().splitlines()]
errors = []
for row in predictions:
    method = selection['selected'][row['method']]
    if (row['frozen_selection_sha256'] != selection_sha or row['threshold_F1'] != method['threshold_F1']
            or row['alert_F1'] != (row['score'] >= row['threshold_F1'])
            or row['threshold_normal_quantile'] != method['threshold_normal_quantile']
            or row['alert_normal_quantile'] != (row['score'] > row['threshold_normal_quantile'])):
        errors.append('prediction_not_from_frozen_threshold:' + row['session_id'])
rebuilt = {method: {split: metrics([r for r in predictions if r['method'] == method and r['split'] == split])
    for split in ('validation', 'test')} for method in selection['selected']}
recorded = json.loads((args.folder / 'metrics.json').read_text())
if recorded['methods'] != rebuilt:
    errors.append('metrics_not_reproducible_from_predictions')
result = {'passed': not errors, 'errors': errors, 'methods': rebuilt, 'prediction_rows': len(predictions)}
with (args.folder / 'rebuilt_metrics_audit.json').open('x', encoding='utf-8') as stream:
    json.dump(result, stream, indent=2, allow_nan=False)
print(json.dumps({'passed': result['passed'], 'prediction_rows': len(predictions), 'errors': errors}))
raise SystemExit(0 if result['passed'] else 1)
