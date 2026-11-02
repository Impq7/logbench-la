"""L4 train-only linear branches, validation fusion selection, frozen inference."""
import itertools
import time
from . import runtime
import joblib
import numpy as np
from scipy.special import expit
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from .artifacts import now, read, rows, save, save_rows, seal, sha, verify, verify_subset
from .represent import features, load_streams


def threshold(y, score):
    records = []
    for tau in list(np.unique(score)) + [np.nextafter(max(score), np.inf)]:
        pred = score >= tau
        tp, fp, fn = sum(pred & (y == 1)), sum(pred & (y == 0)), sum(~pred & (y == 1))
        records.append({'threshold': float(tau), 'F1': float(2 * tp / (2 * tp + fp + fn)) if 2 * tp + fp + fn else 0.,
            'FPR': float(np.mean(pred[y == 0]))})
    return max(records, key=lambda r: (r['F1'], -r['FPR'], r['threshold'])), records


def candidates(mask):
    result = [{'rule': 'mean', 'weights': [1 / len(mask)] * len(mask)}]
    if len(mask) > 1:
        result.append({'rule': 'max', 'weights': None})
        for weights in itertools.product(range(5), repeat=len(mask)):
            if sum(weights) == 4:
                result.append({'rule': 'weighted', 'weights': [w / 4 for w in weights]})
    return result


def combine(matrix, candidate):
    return np.max(matrix, axis=1) if candidate['rule'] == 'max' else matrix @ np.array(candidate['weights'])


def transform(head, values):
    matrix = head['encoder'].transform(values)
    return head['scaler'].transform(matrix) if head['scaler'] is not None else matrix


def branch_scores(head, streams, modality, level, cfg):
    return np.array([float(np.max(head['model'].decision_function(transform(head, features(s[modality], modality, level, cfg)))))
                     for s in streams])


def normalized_scores(bundle, streams):
    result = {}
    for modality, head in bundle['heads'].items():
        raw = branch_scores(head, streams, modality, bundle['level'], bundle['config'])
        # g uses only benign validation scores; a declared unit scale handles one row.
        result[modality] = (raw - head['normal_val_center']) / head['normal_val_scale']
    return result


def fit(out, samples):
    cfg = read(out / '00_plan/architecture-smoke.json')
    train = [s for s in samples if s['split'] == 'train']
    val = [s for s in samples if s['split'] == 'validation']
    verify_subset(out / '02_cohort', ['samples.json', 'train-labels.jsonl', 'validation-labels.jsonl'])
    verify_subset(out / '03_represent', [s['session_id'] + '/' + m + '.jsonl' for s in train + val for m in 'TEN'])
    # No test labels, no test feature files opened in this function.
    labels = {r['session_id']: r for split in ('train', 'validation') for r in rows(out / '02_cohort' / (split + '-labels.jsonl'))}
    streams = load_streams(out, train + val)
    yv = np.array([labels[s['session_id']]['y_attempt'] for s in val])
    if set(yv) != {0, 1}:
        raise ValueError('Validation requires both classes')
    stage = out / '04_fit'
    stage.mkdir()
    selections, trials, training = [], [], []
    for level in cfg['levels']:
        bundle = {'level': level, 'config': cfg, 'heads': {}, 'selections': {}}
        for modality in 'TEN':
            started = time.perf_counter()
            values, targets, weights, window_counts = [], [], [], []
            for sample in train:
                fs = features(streams[sample['session_id']][modality], modality, level, cfg)
                values.extend(fs)
                targets.extend([labels[sample['session_id']]['y_attempt']] * len(fs))
                weights.extend([1. / len(fs)] * len(fs))
                window_counts.append(len(fs))
            if modality in ('T', 'E'):
                encoder = HashingVectorizer(analyzer='char', ngram_range=(3, 5), n_features=4096,
                    alternate_sign=False, norm='l2')
                matrix = encoder.transform(values)
                scaler = None
            else:
                encoder = DictVectorizer(sparse=True)
                matrix = encoder.fit_transform(values)
                scaler = StandardScaler(with_mean=False).fit(matrix, sample_weight=weights)
                matrix = scaler.transform(matrix)
            model = LogisticRegression(C=cfg['linear_head_C'], solver='liblinear', random_state=cfg['seed'], max_iter=1000)
            model.fit(matrix, targets, sample_weight=weights)
            if model.n_iter_.max() >= 1000:
                raise RuntimeError('Linear head did not converge')
            head = {'encoder': encoder, 'scaler': scaler, 'model': model}
            score = branch_scores(head, [streams[s['session_id']] for s in val], modality, level, cfg)
            head['normal_val_center'] = float(np.mean(score[yv == 0]))
            std = float(np.std(score[yv == 0]))
            head['normal_val_scale'] = std if std > 0 else 1.
            bundle['heads'][modality] = head
            training.append({'level': level, 'modality': modality, 'seconds': time.perf_counter() - started,
                'sessions': len(train), 'windows': len(values), 'dimensions': matrix.shape[1],
                'train_window_count_range': [min(window_counts), max(window_counts)], 'length_strata': 1,
                'normal_validation_support': int(sum(yv == 0)), 'unit_scale_fallback': std == 0,
                'calibration_center': head['normal_val_center'], 'calibration_scale': head['normal_val_scale'],
                'fit_ids': [s['session_id'] for s in train]})
        normalized = normalized_scores(bundle, [streams[s['session_id']] for s in val])
        for mask in cfg['masks']:
            matrix = np.column_stack([normalized[m] for m in mask])
            grid = candidates(mask)
            if len(grid) > cfg['max_trials_per_level_mask']:
                raise ValueError('Search budget exceeded')
            best = None
            for index, rule in enumerate(grid):
                score = combine(matrix, rule)
                choice, thresholds = threshold(yv, score)
                rank = (choice['F1'], -choice['FPR'])
                trials.append({'level': level, 'mask': mask, 'trial': index, **rule, 'status': 'completed',
                    'validation_scores': score.tolist(), 'threshold_candidates': thresholds, 'selection': choice})
                if best is None or rank > best['rank']:
                    best = {'rank': rank, 'rule': rule, 'score': score, 'choice': choice}
            score = best['score']
            mapping = LogisticRegression(C=1, solver='liblinear', random_state=cfg['seed']).fit(score.reshape(-1, 1), yv)
            selection = {'level': level, 'mask': mask, **best['rule'], 'threshold_F1': best['choice']['threshold'],
                'threshold_low_FPR': float(np.quantile(score[yv == 0], .95, method='higher')),
                'low_FPR_comparator': '>', 'F1_comparator': '>=',
                'normal_validation_support': int(sum(yv == 0)), 'validation_F1': best['choice']['F1'],
                'validation_FPR': best['choice']['FPR'], 'probability_coefficient': float(mapping.coef_[0, 0]),
                'probability_intercept': float(mapping.intercept_[0])}
            bundle['selections'][mask] = selection
            selections.append(selection)
        file = stage / ('LateFusion-level-' + str(level) + '.joblib')
        joblib.dump(bundle, file)
        reloaded = joblib.load(file)
        roundtrip = normalized_scores(reloaded, [streams[s['session_id']] for s in val])
        if any(not np.array_equal(normalized[m], roundtrip[m]) for m in 'TEN'):
            raise ValueError('Model reload changed branch scores')
    save(stage / 'training.json', training)
    save_rows(stage / 'trials.jsonl', trials)
    save(stage / 'selection.json', {'frozen_utc': now(), 'fit_ids': [s['session_id'] for s in train],
        'validation_ids': [s['session_id'] for s in val], 'test_opened': False, 'selections': selections,
        'model_hashes': {p.name: sha(p) for p in stage.glob('*.joblib')}})
    seal(stage)


def prediction(bundle, streams, mask):
    branch = normalized_scores(bundle, streams)
    choice = bundle['selections'][mask]
    score = combine(np.column_stack([branch[m] for m in mask]), choice)
    probability = expit(score * choice['probability_coefficient'] + choice['probability_intercept'])
    return [{'score': float(s), 'probability': float(p), 'alert_F1': int(s >= choice['threshold_F1']),
        'alert_low_FPR': int(s > choice['threshold_low_FPR']),
        'branch_scores': {m: float(branch[m][i]) for m in mask}} for i, (s, p) in enumerate(zip(score, probability))]


def score(out, samples):
    verify(out / '04_fit')
    selected = [s for s in samples if s['split'] in ('validation', 'test')]
    streams = load_streams(out, selected)
    cfg = read(out / '00_plan/architecture-smoke.json')
    results = []
    for level in cfg['levels']:
        bundle = joblib.load(out / '04_fit' / ('LateFusion-level-' + str(level) + '.joblib'))
        # Branch inference once per session/level; reuse scores across masks.
        branch = normalized_scores(bundle, [streams[s['session_id']] for s in selected])
        for mask in cfg['masks']:
            choice = bundle['selections'][mask]
            values = combine(np.column_stack([branch[m] for m in mask]), choice)
            probabilities = expit(values * choice['probability_coefficient'] + choice['probability_intercept'])
            for i, sample in enumerate(selected):
                value = float(values[i])
                results.append({'session_id': sample['session_id'], 'group': sample['group'], 'split': sample['split'],
                    'scenario': sample['scenario'], 'method': 'LateFusion', 'level': level, 'mask': mask,
                    'score': value, 'probability': float(probabilities[i]), 'alert_F1': int(value >= choice['threshold_F1']),
                    'alert_low_FPR': int(value > choice['threshold_low_FPR']),
                    'branch_scores': {m: float(branch[m][i]) for m in mask}})
    stage = out / '05_predictions'
    stage.mkdir()
    save_rows(stage / 'unlabeled.jsonl', results)
    save(stage / 'inference.json', {'scored_utc': now(), 'selection_sha256': sha(out / '04_fit/selection.json'),
        'test_label_files_opened_by_inference': False, 'rows': len(results)})
    seal(stage)
