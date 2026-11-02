"""Screen each N multi-protocol feature family for benign-vs-attempt signal.

Runs the families defined in ``logbench.n_protocol_features`` over a named batch
and reports per-family CV AUROC (5x5 stratified, LogisticRegression C=1.0, the same
learner used by the LateFusion heads). This is the benchmark-framing counterpart
to ``screen_e_subsets.py`` / ``screen_n_variants.py``: it validates that the
multi-protocol parser + feature layer run end-to-end, and it quantifies whether any
family already carries signal in the *current* data (which spans only one
dimension: gateway-TLS + plaintext-tool-backend).

A family with zero coverage (e.g. ``dns`` when the gateway is IP-literal and the
agent resolves no names) is reported as ``no_coverage`` rather than a fake AUROC.
"""
import sys
import json
import collections
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'logbench'))

import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.feature_extraction import DictVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import RepeatedStratifiedKFold, cross_val_score

from session_storage import load_model_inputs, SessionStore
from logbench.n_protocol_features import (FAMILIES, TOKEN_FAMILIES, NUMERIC_FAMILIES,
                                          extract, family_views)

SCENARIOS = ('slack', 'banking', 'travel', 'workspace')
BATCH = 'batch-hunyuan-chat-r1'


def load_cohort():
    sessions = []
    for sc in SCENARIOS:
        base = ROOT / 'DataSet' / BATCH / sc / 'sessions'
        for f in sorted(p for p in base.iterdir() if p.is_dir()):
            v = load_model_inputs(f)
            y = SessionStore(f).json('labels.json')['y_attempt']
            sessions.append({'id': f.name, 'scenario': sc, 'y': y, 'n': v['N'], 'folder': f})
    return sessions


def _cv(X, ys, seed=7):
    if len(set(ys)) < 2 or X.shape[1] == 0:
        return np.nan, np.nan
    model = LogisticRegression(C=1.0, solver='liblinear', random_state=seed, max_iter=1000)
    cv = RepeatedStratifiedKFold(n_splits=5, n_repeats=5, random_state=seed)
    s = cross_val_score(model, X, np.array(ys), cv=cv, scoring='roc_auc', n_jobs=1)
    return float(np.mean(s)), float(np.std(s))


def main():
    sessions = load_cohort()
    ys = [s['y'] for s in sessions]
    print('cohort: %d sessions (%d benign / %d attempt)' %
          (len(sessions), sum(1 for y in ys if y == 0), sum(1 for y in ys if y == 1)))

    summaries = {}
    for s in sessions:
        summaries[s['id']] = extract(s['folder'], s['n'])

    # coverage counters
    cov = collections.Counter()
    for s in sessions:
        sm = summaries[s['id']]
        if sm.get('tls'):
            cov['tls_fingerprint'] += 1
            cov['handshake'] += 1
        if sm.get('dns'):
            cov['dns'] += 1
        if sm.get('flows'):
            cov['topology'] += 1
            cov['timing'] += 1
        if sm.get('http'):
            cov['http_body'] += 1
    for fam in FAMILIES:
        print('  family coverage: %-16s %d/%d sessions' % (fam, cov.get(fam, 0), len(sessions)))

    hv = HashingVectorizer(analyzer='char', ngram_range=(3, 5), n_features=4096,
                           alternate_sign=False, norm='l2')
    results = {}
    print('\n=== per-family CV AUROC (5x5 stratified, LogReg C=1.0) ===')
    for fam in FAMILIES:
        if fam in TOKEN_FAMILIES or fam == 'topology':
            docs = [token_doc(summaries[s['id']], fam) for s in sessions]
            if not any(docs):
                print('  %-16s no_coverage (empty token docs)' % fam)
                results[fam] = {'status': 'no_coverage', 'auroc': None, 'std': None}
                continue
            X = hv.transform(np.array(docs, dtype=object))
            auc, std = _cv(X, ys)
            kind = 'token'
        else:
            vecs = [numeric_vec(summaries[s['id']], fam) for s in sessions]
            dv = DictVectorizer(sparse=True)
            X = dv.fit_transform(vecs)
            if X.shape[1] == 0:
                print('  %-16s no_coverage (zero numeric dims)' % fam)
                results[fam] = {'status': 'no_coverage', 'auroc': None, 'std': None}
                continue
            X = StandardScaler(with_mean=False).fit_transform(X)
            auc, std = _cv(X, ys)
            kind = 'numeric'
        results[fam] = {'status': 'ok', 'auroc': float(auc) if not np.isnan(auc) else None,
                        'std': float(std) if not np.isnan(std) else None, 'kind': kind}
        print('  %-16s AUROC=%s ± %s  [%s]' % (
            fam, '%.3f' % auc if not np.isnan(auc) else 'nan',
            '%.3f' % std if not np.isnan(std) else 'nan', kind))

    # combined token document (all token families)
    combined = ['\n'.join(token_doc(summaries[s['id']], fam) for fam in TOKEN_FAMILIES)
                for s in sessions]
    if any(combined):
        X = hv.transform(np.array(combined, dtype=object))
        auc, std = _cv(X, ys)
        print('\n  combined token families    AUROC=%s ± %s' % ('%.3f' % auc, '%.3f' % std))
        results['combined_token'] = {'status': 'ok', 'auroc': float(auc), 'std': float(std), 'kind': 'token'}

    out = ROOT / 'experiment' / 'n-protocol-screening'
    out.mkdir(exist_ok=True)
    (out / 'results.json').write_text(json.dumps({'coverage': dict(cov), 'results': results}, indent=2),
                                      encoding='utf-8')
    print('\nwrote -> %s/results.json' % out)


def token_doc(summary, family):
    from logbench.n_protocol_features import token_document
    return token_document(summary, family)


def numeric_vec(summary, family):
    from logbench.n_protocol_features import numeric_vector
    return numeric_vector(summary, family)


if __name__ == '__main__':
    main()
