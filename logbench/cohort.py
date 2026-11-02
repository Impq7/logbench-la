"""L1 reuse and L2 source-group cohort freeze; no historical dataset loader."""
import collections
from pathlib import Path
import shutil
from scripts.session_storage import SessionStore,pack_session

from .artifacts import ROOT, now, read, rows, save, save_rows, save_csv, seal, sha, verify


def assert_group_split(samples):
    assignment = {}
    for sample in samples:
        group, split = sample['group'], sample['split']
        if split not in ('train', 'validation', 'test'):
            raise ValueError('Unknown split')
        if group in assignment and assignment[group] != split:
            raise ValueError('Source-task lineage crosses splits: ' + group)
        assignment[group] = split
    return assignment


def build(out):
    from collection_session import normalize
    verify(out / '00_plan')
    cfg = read(out / '00_plan/architecture-smoke.json')
    frozen = read(out / '00_plan/collection-frozen.json')
    tasks = {t['task_id']: t for t in frozen['native_manifest']['tasks'] if t['task_id'] in cfg['tasks']}
    selected = {}
    base = ROOT / 'DataSet' / cfg['dataset_directory'] / 'sessions'
    for path in sorted(base.glob('native-session-*')):
        report = read(path / 'report.json')
        task_id = report['native_task_id']
        if task_id not in tasks:
            continue
        key = (task_id, report['condition'])
        if key in selected:
            raise ValueError('Duplicate pair needs explicit exclusion: ' + repr(key))
        selected[key] = path
    expected = {(task, c) for task in tasks for c in ('benign', 'injected')}
    if set(selected) != expected:
        raise ValueError('Incomplete planned cohort: ' + repr(expected - set(selected)))
    contract = out / '01_contract'
    contract.mkdir()
    samples, labels, checks, input_hashes = [], [], [], {}
    for (task_id, condition), source in selected.items():
        report = read(source / 'report.json')
        if report.get('collection_revision') != cfg['collection_revision']:
            # The collector records revision in gateway settings on some runs.
            if read(source / 'collection_validation.json').get('collection_revision') != cfg['collection_revision']:
                raise ValueError('Wrong collector revision')
        destination = contract / source.name
        destination.mkdir()
        inputs = dict(report['sha256'])
        inputs['report.json'] = sha(source / 'report.json')
        for name, digest in inputs.items():
            if Path(name).name != name or sha(source / name) != digest:
                raise ValueError('Raw source hash mismatch')
            (destination / name).write_bytes(SessionStore(source).read_bytes(name))
            input_hashes[(source / name).relative_to(ROOT).as_posix()] = digest
        result = normalize(destination, frozen['collection_settings'])
        if not result['passed']:
            raise ValueError('Contract gate failed: ' + source.name + repr(result['errors']))
        task = tasks[task_id]
        if report['source_task_lineage'] != task['lineage']:
            raise ValueError('Lineage does not match frozen task')
        samples.append({'session_id': source.name, 'group': task['lineage'], 'split': task['split'],
            'scenario': 'Banking', 'backbone': report['model_requested'],
            'canonical': destination.relative_to(out).as_posix()})
        label = read(destination / 'labels.json')
        labels.append({'session_id': source.name, 'y_attempt': label['y_attempt'], 'y_harm': label['y_harm'],
            'task_success': label['task_success'], 't_harm': label['first_harm_time'],
            'exposed': label['exposed_injection'], 'oracle_revision': label['oracle_revision']})
        checks.append({'session_id': source.name, 'passed': True, 'counts': result['counts'],
            'coverage': result['coverage'], 'warnings': result['warnings']})
        pack_session(destination)
    assignment = assert_group_split(samples)
    if len({s['session_id'] for s in samples}) != len(samples):
        raise ValueError('Repeated session')
    label_map = {r['session_id']: r for r in labels}
    for split in ('train', 'validation', 'test'):
        if {label_map[s['session_id']]['y_attempt'] for s in samples if s['split'] == split} != {0, 1}:
            raise ValueError('Both attempt classes required in this smoke split')
    save(contract / 'checks.json', checks)
    save(contract / 'source_hashes.json', input_hashes)
    seal(contract)
    cohort = out / '02_cohort'
    cohort.mkdir()
    save(cohort / 'samples.json', samples)
    for split in ('train', 'validation', 'test'):
        ids = {s['session_id'] for s in samples if s['split'] == split}
        save_rows(cohort / (split + '-labels.jsonl'), [r for r in labels if r['session_id'] in ids])
    save_csv(cohort / 'session_manifest.csv', samples)
    save_csv(cohort / 'labels.csv', labels)
    save(cohort / 'deviations.json', {'created_utc': now(), 'eligible_for_formal_results': False,
        'session_counts': dict(collections.Counter(s['split'] for s in samples)),
        'group_counts': dict(collections.Counter(assignment.values())),
        'zero_group_overlap': True, 'scenarios': ['Banking'], 'backbones': sorted({s['backbone'] for s in samples}),
        'paper_validation_and_test_target_each': 1200, 'actual_validation_and_test_each': 2,
        'selection_basis': 'Frozen source tasks and conditions, never attack success',
        'native_task_8_utility': 'Always true upstream; no strong utility claim',
        'unknown_harm_policy': 'Preserved null, never relabeled benign',
        'prior_debug_groups': 'All groups were development groups and are ineligible for formal test'})
    seal(cohort)
    return samples
