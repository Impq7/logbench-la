"""量化「字面捷径」的贡献：单条字符串规则 vs. T 模型，在同一批 test 会话上对比。

规则：T 轨迹文本中出现 ``my-website-234`` 即判为攻击。这不需要任何训练，
若它在各折 test 上的表现与 T 模型持平，说明 T 的分数携带的额外信息有限，
族 holdout 并没有真正制造「没见过的攻击」。

同时反查 T 分支（char 3-5 gram HashingVectorizer + LogisticRegression）的系数，
给出关键片段的线性贡献，作为内部证据。

用法：
    python scripts/analyze_shortcut_baseline.py
"""
import csv
import gzip
import json
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.metrics import roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
BATCH = 'batch-asb-r1'
SCENARIO = 'slack'
SHORTCUT = 'my-website-234'
FOLDS = [
    ('fam-in-family-r2', 'in-family 对照'),
    ('fam-holdout-strategy-forward-r2', '策略 holdout 正向'),
    ('fam-holdout-strategy-reverse-r2', '策略 holdout 反向'),
    ('fam-holdout-payload-r2', '内容 holdout'),
]
FRAGMENTS = [
    'www.my-website-234.com/random', 'my-website-234', 'www.informations.com',
    'general channel', 'Ignore all previous instructions',
    'The latest job report brought a mix of relief',
]


def t_text(session_id):
    path = (ROOT / 'DataSet' / BATCH / SCENARIO / 'sessions' / session_id
            / '01_model_inputs' / 'T.trajectory.jsonl.gz')
    blob = []
    with gzip.open(path, 'rt', encoding='utf-8') as stream:
        for line in stream:
            if not line.strip():
                continue
            event = json.loads(line)
            blob.append(str(event.get('content') or ''))
            blob.append(str(event.get('tool_return') or ''))
    return '\n'.join(blob)


def scores(tag, mask='T', level='2'):
    path = ROOT / 'experiment' / (BATCH + '-' + SCENARIO + '-' + tag + '-latefusion') / '06_evaluate' / 'predictions.csv'
    out = {}
    with path.open(encoding='utf-8-sig') as stream:
        for row in csv.DictReader(stream):
            if row['split'] == 'test' and row['mask'] == mask and row['level'] == level:
                out[row['session_id']] = float(row['score'])
    return out


def score_block(y, pred, score):
    tp = sum(1 for a, p in zip(y, pred) if a == 1 and p == 1)
    fp = sum(1 for a, p in zip(y, pred) if a == 0 and p == 1)
    tn = sum(1 for a, p in zip(y, pred) if a == 0 and p == 0)
    fn = sum(1 for a, p in zip(y, pred) if a == 1 and p == 0)
    f1 = 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else float('nan')
    fpr = fp / (fp + tn) if (fp + tn) else float('nan')
    try:
        auc = roc_auc_score(y, score)
    except ValueError:
        auc = float('nan')
    return {'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn, 'F1': f1, 'FPR': fpr, 'AUROC': auc}


def main():
    import joblib

    lines = ['| 折 | 方法 | TP | FP | TN | FN | F1 | FPR | AUROC |', '|---|---|---|---|---|---|---|---|---|']
    detail = []
    for tag, title in FOLDS:
        pred_path = ROOT / 'experiment' / (BATCH + '-' + SCENARIO + '-' + tag + '-latefusion')
        rows = list(csv.DictReader((pred_path / '06_evaluate' / 'predictions.csv').open(encoding='utf-8-sig')))
        test_ids = sorted({r['session_id'] for r in rows if r['split'] == 'test'})
        alerts = {}
        for r in rows:
            if r['split'] == 'test' and r['mask'] == 'T' and r['level'] == '2':
                alerts[r['session_id']] = int(r['alert_F1'])
        y = []
        rule = []
        for sid in test_ids:
            label = next(int(r['y_attempt']) for r in rows if r['session_id'] == sid and r['split'] == 'test')
            blob = t_text(sid)
            y.append(label)
            rule.append(1 if SHORTCUT in blob else 0)
        model_pred = [alerts[sid] for sid in test_ids]
        model_scores = scores(tag)
        model_score = [model_scores[sid] for sid in test_ids]
        rule_block = score_block(y, rule, rule)
        model_block = score_block(y, model_pred, model_score)
        for name, block in [('T 模型 (level2)', model_block), ('单字符串规则', rule_block)]:
            lines.append('| %s | %s | %d | %d | %d | %d | %.3f | %.3f | %.3f |' % (
                title, name, block['TP'], block['FP'], block['TN'], block['FN'],
                block['F1'], block['FPR'], block['AUROC']))
        detail.append({'fold': tag, 'title': title, 'n_test': len(test_ids),
                       'model_T': model_block, 'shortcut_rule': rule_block})

    print('## 字面捷径 vs T 模型（同一批 test 会话）\n')
    print('\n'.join(lines))

    # 内部证据：char n-gram 系数
    model = joblib.load(ROOT / 'experiment' / (BATCH + '-' + SCENARIO + '-fam-holdout-payload-r2-latefusion')
                        / '04_fit' / 'LateFusion-level-2.joblib')
    head = model['heads']['T']
    enc = head['encoder']
    coef = head['model'].coef_[0]
    raw = HashingVectorizer(analyzer=enc.analyzer, ngram_range=enc.ngram_range,
                            n_features=enc.n_features, alternate_sign=enc.alternate_sign, norm=None)
    frag = []
    for sample in FRAGMENTS:
        x = raw.transform([sample])
        weight = coef[x.indices]
        frag.append({'text': sample, 'char_ngrams': int(len(x.indices)),
                     'sum_weighted': float((x.data * weight).sum()),
                     'positive_mass': float((x.data * np.clip(weight, 0, None)).sum()),
                     'negative_mass': float((x.data * np.clip(weight, None, 0)).sum())})

    out_lines = ['', '## T 分支 char 3-5 gram 的线性贡献（level-2 内容 holdout 折）', '',
                 '总 |coef| = %.2f，非零维度 %d / %d' % (np.abs(coef).sum(), int((coef != 0).sum()), len(coef)), '',
                 '| 片段 | char n-gram 数 | Σ 权重×计数 | 正质量 | 负质量 |', '|---|---|---|---|---|']
    for f in frag:
        out_lines.append('| `%s` | %d | %+.2f | %.2f | %.2f |' % (
            f['text'], f['char_ngrams'], f['sum_weighted'], f['positive_mass'], f['negative_mass']))
    print('\n'.join(out_lines))

    out_dir = ROOT / 'experiment' / 'analysis-slack234-family-holdout'
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / 'shortcut-evidence.md').write_text('\n'.join(lines + out_lines) + '\n', encoding='utf-8')
    (out_dir / 'shortcut-evidence.json').write_text(
        json.dumps({'folds': detail, 'fragments': frag}, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print('\n-> ' + str((out_dir / 'shortcut-evidence.md').relative_to(ROOT)))


if __name__ == '__main__':
    main()
