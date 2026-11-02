"""Discrimination screening for three N-modality variants over batch-hunyuan-chat-r1.

  metadata    — current pipeline: packet-level summary (length/direction/protocol/timing),
                what project_n + count_window already uses.
  sidechannel — HTTP-request-level metadata from real pcap bytes: content_length (body size),
                request count, body-length distribution, inter-arrival timing, method/endpoint.
                No body *text* is used — only sizes/timing/endpoints.
  body        — tokenized HTTP body text (tool name + arguments), char 3-5 gram, aligned with T/E.

Each session -> one feature vector/document -> LogisticRegression(C=1.0), repeated
stratified 5-fold CV AUROC. This ranks which N representation carries benign-vs-attempt
signal, before any full training run.
"""
import sys
import json
import collections
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

import numpy as np
from scipy import stats
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import RepeatedStratifiedKFold, cross_val_score

from session_storage import load_model_inputs, SessionStore
from n_http_extract import extract_session
from logbench.represent import project_n, count_window, windows

SCENARIOS = ('slack', 'banking', 'travel', 'workspace')
BATCH = 'batch-hunyuan-chat-r1'


def load_cohort():
    sessions = []
    for sc in SCENARIOS:
        base = ROOT / 'DataSet' / BATCH / sc / 'sessions'
        for f in sorted(p for p in base.iterdir() if p.is_dir()):
            v = load_model_inputs(f)
            y = SessionStore(f).json('labels.json')['y_attempt']
            first, last = v['T'][0]['relative_timestamp'], v['T'][-1]['relative_timestamp']
            n_task = [project_n(r) for r in v['N'] if first <= r['relative_timestamp'] <= last]
            http = [r for r in extract_session(f, v['N'])
                    if r['relative_timestamp'] is not None and first <= r['relative_timestamp'] <= last]
            sessions.append({'id': f.name, 'scenario': sc, 'y': y, 'N': n_task, 'http': http})
    return sessions


def metadata_vector(sess, cfg):
    """Aggregate packet-level features (mirror project_n + count_window bins)."""
    events = sess['N']
    if not events:
        return {}
    c = count_window(events, 'N', 2)
    return c


def sidechannel_vector(sess):
    reqs = sess['http']
    if not reqs:
        return {'n_requests': 0}
    lens = [r['content_length'] for r in reqs]
    times = sorted(r['relative_timestamp'] for r in reqs)
    iats = np.diff(times) if len(times) > 1 else [0.0]
    vec = {'n_requests': len(reqs),
           'total_body_bytes': int(sum(lens)),
           'mean_body': float(np.mean(lens)),
           'max_body': float(np.max(lens)),
           'min_body': float(np.min(lens)),
           'std_body': float(np.std(lens)) if len(lens) > 1 else 0.0,
           'duration': float(times[-1] - times[0]),
           'mean_iat': float(np.mean(iats)),
           'max_iat': float(np.max(iats)),
           'n_iat_gt_2s': int(sum(1 for x in iats if x > 2.0))}
    # body-length histogram bins (size side-channel, no text)
    bins = np.searchsorted([16, 32, 64, 128, 256, 512], lens)
    for b in bins:
        vec['len_bin_%d' % b] = vec.get('len_bin_%d' % b, 0) + 1
    return vec


def body_document(sess):
    parts = []
    for r in sess['http']:
        args = json.dumps(r['arguments'] or {}, sort_keys=True, ensure_ascii=False)
        parts.append('[NAME=%s][ARGS=%s]' % (r['name'] or '', args))
    return '\n'.join(parts)


def cv_auroc_docs(docs, ys, seed=7):
    if len(set(ys)) < 2 or not any(docs):
        return np.nan, np.nan
    hv = HashingVectorizer(analyzer='char', ngram_range=(3, 5), n_features=4096,
                           alternate_sign=False, norm='l2')
    X = hv.transform(np.array(docs, dtype=object))
    return _cv(X, ys, seed)


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
    print('sessions with tool HTTP:', sum(1 for s in sessions if s['http']),
          '| total HTTP requests:', sum(len(s['http']) for s in sessions))

    # (a) sidechannel via DictVectorizer
    side = [sidechannel_vector(s) for s in sessions]
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.preprocessing import StandardScaler
    dv = DictVectorizer(sparse=True)
    X_side = dv.fit_transform(side)
    X_side = StandardScaler(with_mean=False).fit_transform(X_side)

    # (b) body text
    body_docs = [body_document(s) for s in sessions]
    hv = HashingVectorizer(analyzer='char', ngram_range=(3, 5), n_features=4096,
                           alternate_sign=False, norm='l2')
    X_body = hv.transform(np.array(body_docs, dtype=object))

    # (c) metadata (packet-level, dict)
    meta = [metadata_vector(s, None) for s in sessions]
    X_meta = dv.fit_transform(meta)
    X_meta = StandardScaler(with_mean=False).fit_transform(X_meta)

    print('\n=== N variant CV AUROC (5x5 stratified, LogisticRegression C=1.0) ===')
    for name, X in (('metadata(packet-level)', X_meta), ('sidechannel(HTTP sizes/timing)', X_side),
                    ('body(HTTP tool text)', X_body)):
        auc, std = _cv(X, ys)
        print('  %-30s AUROC=%s ± %s' % (name, '%.3f' % auc if not np.isnan(auc) else 'nan',
                                          '%.3f' % std if not np.isnan(std) else 'nan'))

    # sidechannel univariate: body-length class difference (the key side-channel)
    print('\n=== side-channel univariate: body length (benign vs attempt) ===')
    for k in ('n_requests', 'total_body_bytes', 'mean_body', 'max_body', 'mean_iat'):
        ben = [sidechannel_vector(s)[k] for s in sessions if s['y'] == 0]
        att = [sidechannel_vector(s)[k] for s in sessions if s['y'] == 1]
        u, p = stats.mannwhitneyu(att, ben, alternative='two-sided')
        print('  %-18s benign mean=%.2f  attempt mean=%.2f  MWU p=%.3f' %
              (k, np.mean(ben), np.mean(att), p))


if __name__ == '__main__':
    main()
