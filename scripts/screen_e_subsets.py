"""Offline discrimination screening for the E modality (batch-hunyuan-chat-r1, 74 sessions).

Goal: answer *which subset of E events carries benign-vs-attempt signal* before doing any
denoising. Three axes are swept (role x semantic x denoise) and every subset is scored two
ways:

  (a) activity   — per-session event rate (events in subset / task-window E events),
                   standardized mean difference (Cohen's d) + Mann-Whitney U p.
  (b) end-to-end — per-session token document -> char 3-5 HashingVectorizer(4096) ->
                   LogisticRegression(C=1.0) -> repeated stratified 5-fold AUROC.

Labels: y_attempt (0=benign, 1=attempt). Encoding mirrors logbench/fusion.py for E.
This is screening, not a formal result; CV is used only to rank subsets by relative signal.
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
from sklearn.pipeline import make_pipeline

from session_storage import load_model_inputs, SessionStore
from logbench.represent import project_e

SCENARIOS = ('slack', 'banking', 'travel', 'workspace')
BATCH = 'batch-hunyuan-chat-r1'

HIGH_SEM = ('security_file_open', 'openat', 'openat2', 'open', 'execve', 'execveat',
            'connect', 'accept', 'accept4', 'bind', 'listen', 'unlink', 'unlinkat',
            'rename', 'renameat', 'chmod', 'fchmodat', 'truncate', 'mkdir', 'rmdir')
IO_SEM = ('read', 'write', 'close', 'socket', 'sendto', 'recvfrom', 'getsockname',
          'getpeername', 'shutdown', 'futex', 'poll', 'epoll_wait', 'nanosleep', 'readv',
          'writev', 'mmap', 'munmap', 'brk', 'mprotect', 'lseek', 'fcntl', 'dup', 'dup2')

NOISE_PREFIXES = ('/etc/ssl/', '/proc/', '/sys/', '/dev/', '/usr/', '/lib/', '/lib64/',
                  '/opt/', '__pycache__', '/var/lib/')


def load_cohort():
    sessions = []
    for sc in SCENARIOS:
        base = ROOT / 'DataSet' / BATCH / sc / 'sessions'
        for f in sorted(p for p in base.iterdir() if p.is_dir()):
            v = load_model_inputs(f)
            y = SessionStore(f).json('labels.json')['y_attempt']
            first, last = v['T'][0]['relative_timestamp'], v['T'][-1]['relative_timestamp']
            ev = [project_e(r) for r in v['E']
                  if r['observation_role'] == 'task' and first <= r['relative_timestamp'] <= last]
            sessions.append({'id': f.name, 'scenario': sc, 'y': y, 'E': ev})
    return sessions


def subset_filter(e, role, semantic, denoise):
    if role == 'agent' and e['role'] != 'agent':
        return False
    if role == 'backend' and e['role'] != 'backend':
        return False
    if semantic == 'high' and e['event'] not in HIGH_SEM:
        return False
    if semantic == 'io' and e['event'] not in IO_SEM:
        return False
    if denoise == 'clean':
        path = e.get('path') or ''
        if any(path.startswith(p) for p in NOISE_PREFIXES):
            return False
    return True


def token_document(events, subset):
    parts = []
    for e in events:
        if not subset(e):
            continue
        part = '[EVT=%s][ROLE=%s]' % (e['event'], e['role'])
        part += '[PROC=%s][DIR=%s]' % (e['process'], e['direction'])
        if e['sock_remote']:
            rip, rport, proto = e['sock_remote']
            part += '[SOCK=%s:%s][PROTO=%s]' % (rip, rport, proto)
        if e['path']:
            part += '[PATH=%s]' % e['path']
        if e['path_class']:
            part += '[PCLS=%s]' % e['path_class']
        part += '[RES=%s]' % e['result']
        parts.append(part)
    return '\n'.join(parts)


def cohens_d(a, b):
    na, nb = len(a), len(b)
    if na < 2 or nb < 2:
        return 0.0
    sp = np.sqrt(((na - 1) * np.var(a, ddof=1) + (nb - 1) * np.var(b, ddof=1)) / (na + nb - 2))
    return float((np.mean(a) - np.mean(b)) / sp) if sp > 0 else 0.0


def cv_auroc(X, ys, seed=7):
    if len(set(ys)) < 2:
        return np.nan, np.nan
    if X.shape[0] == 0 or X.shape[1] == 0:
        return np.nan, np.nan
    model = LogisticRegression(C=1.0, solver='liblinear', random_state=seed, max_iter=1000)
    cv = RepeatedStratifiedKFold(n_splits=5, n_repeats=5, random_state=seed)
    scores = cross_val_score(model, X, np.array(ys), cv=cv, scoring='roc_auc', n_jobs=1)
    return float(np.mean(scores)), float(np.std(scores))


def main():
    sessions = load_cohort()
    ys = [s['y'] for s in sessions]
    print('cohort: %d sessions (%d benign / %d attempt)' %
          (len(sessions), sum(1 for y in ys if y == 0), sum(1 for y in ys if y == 1)), flush=True)

    subsets = []
    for role in ('all', 'agent', 'backend'):
        for semantic in ('all', 'high', 'io'):
            for denoise in ('raw', 'clean'):
                subsets.append((role, semantic, denoise))

    grid = []
    # Precompute subset event counts + rates per session once.
    per_session = {}
    for role, semantic, denoise in subsets:
        key = (role, semantic, denoise)
        rows = []
        for s in sessions:
            total = len(s['E'])
            sel = [e for e in s['E'] if subset_filter(e, role, semantic, denoise)]
            rows.append({'id': s['id'], 'y': s['y'], 'n': len(sel),
                         'rate': len(sel) / total if total else 0.0})
        per_session[key] = rows

    for role, semantic, denoise in subsets:
        key = (role, semantic, denoise)
        rows = per_session[key]
        ben = [r for r in rows if r['y'] == 0]
        att = [r for r in rows if r['y'] == 1]
        n_events = sum(r['n'] for r in rows)
        ben_rate = [r['rate'] for r in ben]
        att_rate = [r['rate'] for r in att]
        d = cohens_d(att_rate, ben_rate)
        u, p = stats.mannwhitneyu(att_rate, ben_rate, alternative='two-sided')
        docs = [token_document(s['E'], lambda e, ro=role, se=semantic, de=denoise:
                               subset_filter(e, ro, se, de)) for s in sessions]
        n_tokens = len(set(tok for doc in docs for tok in doc.split('\n') if tok))
        if n_tokens:
            hv = HashingVectorizer(analyzer='char', ngram_range=(3, 5), n_features=4096,
                                   alternate_sign=False, norm='l2')
            X = hv.transform(docs)
        else:
            X = np.zeros((len(docs), 0))
        auc, auc_std = cv_auroc(X, ys)
        grid.append({'role': role, 'semantic': semantic, 'denoise': denoise,
                     'n_events': n_events, 'n_distinct_tokens': n_tokens,
                     'cohens_d_rate': round(d, 3), 'mwu_p': (round(float(p), 4) if not np.isnan(p) else None),
                     'cv_auroc': (round(auc, 4) if not np.isnan(auc) else None),
                     'cv_auroc_std': (round(auc_std, 4) if not np.isnan(auc_std) else None)})

    out = ROOT / 'experiment' / 'e-subsets-screening'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'grid.json').write_text(json.dumps(grid, ensure_ascii=False, indent=2), encoding='utf-8')

    # Print grid sorted by |AUROC-0.5| then by AUROC.
    print('\n=== subset grid (sorted by |AUROC-0.5|) ===', flush=True)
    print('%-8s %-8s %-7s %7s %8s %9s %8s %9s  %s' %
          ('role', 'sem', 'denoise', 'events', 'd_rate', 'mwu_p', 'auroc', 'auc_std', 'distinct_tokens'))
    for r in sorted(grid, key=lambda r: (-abs((r['cv_auroc'] or 0.5) - 0.5), -(r['cv_auroc'] or 0))):
        auc = r['cv_auroc'] if r['cv_auroc'] is not None else float('nan')
        print('%-8s %-8s %-7s %7d %+8.3f %9s %8.3f %8.3f  %d' %
              (r['role'], r['semantic'], r['denoise'], r['n_events'], r['cohens_d_rate'],
               r['mwu_p'], auc, r['cv_auroc_std'] or 0, r['n_distinct_tokens']))

    # Section 3: denoised agent high-semantic residual frequency comparison.
    print('\n=== residual frequency: agent + high-semantic + clean (per event/path token) ===', flush=True)
    nb = sum(1 for y in ys if y == 0)
    na = sum(1 for y in ys if y == 1)
    resid = collections.defaultdict(lambda: [set(), set(), 0, 0])
    for s in sessions:
        idx = 0 if s['y'] == 0 else 1
        for e in s['E']:
            if not subset_filter(e, 'agent', 'high', 'clean'):
                continue
            tok = ('%s|%s' % (e['event'], e['path'])) if e['path'] else ('%s|%s' % (e['event'], e['sock_remote']))
            resid[tok][idx].add(s['id'])
            resid[tok][idx + 2] += 1
    rows = []
    for tok, (bs, at, be, ae) in resid.items():
        bp, ap = len(bs) / nb, len(at) / na
        rows.append((ap - bp, ap, bp, ae, be, tok))
    rows.sort(key=lambda r: -abs(r[0]))
    for diff, ap, bp, ae, be, tok in rows[:20]:
        print('  diff=%+.3f  att_prev=%.3f(%d ev)  ben_prev=%.3f(%d ev)  %s' %
              (diff, ap, ae, bp, be, tok))

    print('\nwrote grid -> %s' % (out / 'grid.json'), flush=True)


if __name__ == '__main__':
    main()
