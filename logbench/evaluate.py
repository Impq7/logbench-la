"""L5 metrics from frozen predictions; empty denominators remain undefined."""
import collections
import time
from . import runtime
import joblib
import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score, matthews_corrcoef

from .artifacts import read, rows, save, save_csv, save_rows, seal, verify
from .fusion import prediction
from .represent import load_streams


def ratio(a, b):
    return float(a / b) if b else None


def metrics(records):
    known = [r for r in records if r['y_attempt'] in (0, 1)]
    if not known:
        return {'sessions': len(records), 'known_labels': 0}
    y = np.array([r['y_attempt'] for r in known])
    pred = np.array([r['alert_F1'] for r in known])
    score = np.array([r['score'] for r in known])
    probability = np.array([r['probability'] for r in known])
    tp = int(sum((y == 1) & (pred == 1)))
    fp = int(sum((y == 0) & (pred == 1)))
    tn = int(sum((y == 0) & (pred == 0)))
    fn = int(sum((y == 1) & (pred == 0)))
    harm = [r for r in known if r['y_harm'] == 1]
    failed = [r for r in known if r['y_attempt'] == 1 and r['y_harm'] == 0]
    benign = [r for r in known if r['y_attempt'] == 0]
    ece = 0.
    for i in range(10):
        selected = (probability >= i / 10) & ((probability < (i + 1) / 10) if i < 9 else (probability <= 1))
        if selected.any():
            ece += float(selected.mean() * abs(y[selected].mean() - probability[selected].mean()))
    return {'sessions': len(records), 'known_labels': len(known), 'groups': len({r['group'] for r in known}),
        'normal_support': tn + fp, 'attempt_support': tp + fn, 'harm_support': len(harm),
        'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
        'F1': ratio(2 * tp, 2 * tp + fp + fn), 'precision': ratio(tp, tp + fp),
        'recall': ratio(tp, tp + fn), 'FPR': ratio(fp, tn + fp),
        'AP': float(average_precision_score(y, score)) if len(set(y)) == 2 else None,
        'AUROC': float(roc_auc_score(y, score)) if len(set(y)) == 2 else None,
        'MCC': float(matthews_corrcoef(y, pred)) if (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn) else None,
        'Brier': float(np.mean((probability - y) ** 2)), 'ECE_10': ece,
        'achieved_FPR_at_normal_val_95_quantile': ratio(sum(r['alert_low_FPR'] for r in benign), len(benign)),
        'harm_conditioned_recall': ratio(sum(r['alert_F1'] for r in harm), len(harm)),
        'failed_attempt_support': len(failed), 'failed_attempt_alert_rate': ratio(sum(r['alert_F1'] for r in failed), len(failed)),
        'unknown_harm_support': sum(r['y_harm'] is None for r in known)}


def metric_table(predictions):
    groups = collections.defaultdict(list)
    for row in predictions:
        groups[(row['level'], row['mask'], row['split'])].append(row)
    return [{'level': k[0], 'mask': k[1], 'split': k[2], **metrics(v)} for k, v in sorted(groups.items())]


def evaluate(out, samples):
    verify(out / '05_predictions')
    # Test labels enter only here, after unlabeled predictions and selection are sealed.
    labels = {r['session_id']: r for split in ('validation', 'test') for r in rows(out / '02_cohort' / (split + '-labels.jsonl'))}
    predictions = [dict(r, **{k: labels[r['session_id']][k] for k in ('y_attempt', 'y_harm')}) for r in rows(out / '05_predictions/unlabeled.jsonl')]
    stage = out / '06_evaluate'
    stage.mkdir()
    save_rows(stage / 'predictions.jsonl', predictions)
    save_csv(stage / 'predictions.csv', [{k: v for k, v in r.items() if k != 'branch_scores'} for r in predictions])
    table = metric_table(predictions)
    save(stage / 'metrics.json', table)
    save_csv(stage / 'metrics.csv', table)
    projections = []
    for row in table:
        if row['split'] != 'test':
            continue
        for prevalence in (.001, .01, .05, .1, .5):
            tpr, fpr = row['recall'], row['FPR']
            projections.append({'level': row['level'], 'mask': row['mask'], 'assumed_prevalence': prevalence,
                'projected_precision': ratio(prevalence * tpr, prevalence * tpr + (1 - prevalence) * fpr),
                'projected_false_alarms_per_1000': 1000 * (1 - prevalence) * fpr,
                'status': 'illustrative projection from the engineering test cohort, not a measured deployment estimate'})
    save_csv(stage / 'prevalence.csv', projections)
    # Stress and timing use validation only, preserving the one-pass engineering test.
    val = [s for s in samples if s['split'] == 'validation']
    streams = load_streams(out, val)
    baseline = [streams[s['session_id']] for s in val]
    bundle = joblib.load(out / '04_fit/LateFusion-level-2.joblib')
    stresses = []
    for kind, amount in [('drop', .05), ('drop', .1), ('drop', .2), ('prefix', .25), ('prefix', .5), ('prefix', .75)]:
        rng = np.random.default_rng(bundle['config']['seed'])
        altered = []
        for stream in baseline:
            value = {}
            for m, events in stream.items():
                if kind == 'prefix':
                    value[m] = events[:max(1, int(np.ceil(len(events) * amount))) ]
                else:
                    drop = set(rng.choice(len(events), int(np.floor(len(events) * amount)), replace=False).tolist())
                    value[m] = [event for i, event in enumerate(events) if i not in drop]
            altered.append(value)
        scored = prediction(bundle, altered, 'TEN')
        for sample, result, modified in zip(val, scored, altered):
            stresses.append({'stress': kind, 'fraction': amount, 'session_id': sample['session_id'],
                'group': sample['group'], 'split': 'validation', **result,
                'y_attempt': labels[sample['session_id']]['y_attempt'], 'y_harm': labels[sample['session_id']]['y_harm'],
                'retained_events': {m: len(modified[m]) for m in 'TEN'}})
    save_rows(stage / 'stress-validation.jsonl', stresses)
    for _ in range(3):
        prediction(bundle, baseline, 'TEN')
    timing = []
    for _ in range(10):
        started = time.perf_counter()
        prediction(bundle, baseline, 'TEN')
        timing.append(time.perf_counter() - started)
    save(stage / 'resource.json', {'scope': 'Local CPU level-2 TEN validation batch; in-memory representations',
        'batch_sessions':len(val),
        'warmups': 3, 'repetitions': 10, 'batch_seconds': timing, 'median_batch_seconds': float(np.median(timing)),
        'p95_batch_seconds': float(np.quantile(timing, .95)), 'sessions_per_second': len(val) / float(np.median(timing)),
        'peak_RSS': None, 'GPU_memory': None, 'missing_reason': 'No isolated process RSS/GPU monitor; do not substitute Python heap or model-size estimates',
        'training_seconds': sum(r['seconds'] for r in read(out / '04_fit/training.json'))})
    save(stage / 'unsupported.json', read(out / '00_plan/architecture-smoke.json')['unsupported'])
    seal(stage)
