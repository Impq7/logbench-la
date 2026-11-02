"""Run the existing LateFusion adapted baseline over a locally-collected batch scenario.

Unlike the server-only split50 runner, this adapts the same logbench pipeline
(represent -> fit -> score -> evaluate) to the local `DataSet/<batch>/<scenario>`
dataset produced by `local_enriched_multi.py`. It rebuilds the frozen sample cohort
from each session's retained report/QA/labels, then materializes representations,
fits train-only branch heads, selects fusion/thresholds on validation, and freezes
predictions before joining test labels. All three outcome classes (harm1 attack
succeeded / harm0 attack unsuccessful / benign) are kept; training uses y_attempt.
"""
import argparse
import collections
import hashlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logbench import runtime  # noqa: F401  injects .runtime/detectors onto sys.path
from logbench.artifacts import read, rows, save, save_rows, seal, sha, verify as verify_stage
from session_storage import SessionStore, load_model_inputs, model_files, BEHAVIOR_T_FILE
from validate_split_session import check_topology


def require(cond, msg):
    if not cond:
        raise ValueError(msg)


def normalize_split_map(split_map):
    """Normalise a declared split override into a uniform description.

    Two shapes are accepted:

    * lineage level — ``{lineage: split}`` (the original behaviour, used for the
      declared slack 3/1/1 remap). The lineage remains the leakage boundary.
    * session level — ``{'session_to_split': {...}, 'family_of_session': {...}}``,
      used by attack-family holdout. Here the leakage boundary is the attack
      family (``attack_strategy x payload_family``) instead of the source task,
      because one family spans several source tasks; the same lineage may
      therefore legitimately cross splits, and the family check replaces the
      lineage check.
    """
    if not split_map:
        return None
    if isinstance(split_map, dict) and isinstance(split_map.get('session_to_split'), dict):
        return {'kind': 'session',
                'mapping': split_map['session_to_split'],
                'family': split_map.get('family_of_session') or {},
                'enforce_no_leak': bool(split_map.get('enforce_no_leak', True))}
    lineage = split_map.get('lineage_to_split') if isinstance(split_map.get('lineage_to_split'), dict) else split_map
    return {'kind': 'lineage', 'mapping': lineage, 'family': {}, 'enforce_no_leak': False}


def load_samples(batch, scenarios, split_map=None):
    """Rebuild the frozen cohort from local batch sessions, with a full-batch QA gate.

    ``split_map`` optionally re-assigns splits by source-task lineage or by
    session (attack-family holdout). It exists because the frozen collection plan
    puts every test task outside some scenarios (slack trains only), so a
    single-scenario run has no held-out group. Any override is recorded verbatim
    in 00_plan/cohort-source.json as a declared deviation from the frozen split
    policy; the collected split is preserved per session so the deviation stays
    auditable.
    """
    override = normalize_split_map(split_map)
    samples, labels, evidence = [], {}, []
    for scenario in scenarios:
        base = ROOT / 'DataSet' / batch / scenario / 'sessions'
        require(base.is_dir(), 'No sessions at ' + str(base))
        for folder in sorted(p for p in base.iterdir() if p.is_dir()):
            store = SessionStore(folder)
            report = store.json('report.json')
            qa = store.json('collection_validation.json')
            lab = store.json('labels.json')
            require(report['ready'] and not report['replay'] and not report.get('semantic_only'),
                    'Diagnostic/incomplete session in model dataset: ' + folder.name)
            require(qa['passed'] and not qa['errors'], 'Retained QA failed: ' + folder.name)
            for m in 'TEN':
                require(qa['coverage'][m]['coverage_flag'] == 'OK', 'Missing modality coverage: ' + folder.name)
            for role in ('agent', 'backend'):
                losses = qa['coverage']['E']['loss_counters'][role]
                require(bool(losses) and all(v == 0 for v in losses.values()), 'Tracee loss: ' + folder.name)
            require(all(v == 0 for v in qa['coverage']['N']['loss_counters'].values()), 'Packet loss: ' + folder.name)
            require(qa['tool_packets_on_agent_loopback'] == 0, 'Tool traffic on loopback: ' + folder.name)
            require(qa['counts']['tools'] > 0 and len(qa['tool_network_proof']) == qa['counts']['tools'],
                    'Missing tool network proof: ' + folder.name)
            require(not check_topology(report), 'Topology QA failed: ' + folder.name)
            collected = report['development_split']
            if override is None:
                split = collected
            elif override['kind'] == 'session':
                if folder.name not in override['mapping']:
                    raise ValueError('Session missing from session-level split map: ' + folder.name)
                split = override['mapping'][folder.name]
            else:
                split = override['mapping'].get(report['source_task_lineage'], collected)
            if split not in ('train', 'validation', 'test'):
                raise ValueError('Bad split in override: ' + repr(split))
            sample = {'session_id': folder.name, 'group': report['source_task_lineage'],
                      'split': split, 'scenario': scenario.capitalize(),
                      'backbone': report['model_requested'],
                      'canonical': '01_contract/' + folder.name,
                      'dataset_relative': folder.relative_to(ROOT).as_posix()}
            record = {'session_id': folder.name, 'split': split, 'condition': report['condition'],
                      'y_attempt': lab['y_attempt'], 'y_harm': lab['y_harm'],
                      'exposed_injection': lab.get('exposed_injection'),
                      'task_success': lab.get('task_success')}
            if split_map:
                sample['collected_split'] = collected
                record['collected_split'] = collected
            samples.append(sample)
            labels[folder.name] = lab
            evidence.append(record)
    require(samples, 'No sessions loaded')
    by_split = collections.defaultdict(set)
    for e in evidence:
        by_split[e['split']].add(e['y_attempt'])
    for sp in ('train', 'validation', 'test'):
        require(by_split.get(sp) == {0, 1}, 'Split ' + sp + ' lacks both classes: ' + repr(by_split.get(sp)))
    lineage_split = {}
    for s in samples:
        if s['group'] in lineage_split and lineage_split[s['group']] != s['split']:
            if override is None or override['kind'] != 'session':
                raise ValueError('Lineage crosses splits: ' + s['group'])
        lineage_split[s['group']] = s['split']
    # Attack-family leakage boundary: with a family holdout the same family must never
    # appear on both sides of the test boundary. train/validation may share families
    # (validation only selects the threshold and is never reported).
    if override and override['family'] and override['enforce_no_leak']:
        family_splits = collections.defaultdict(set)
        for s in samples:
            family = override['family'].get(s['session_id'])
            if family and family != 'benign':
                family_splits[family].add(s['split'])
        leaking = {f: sorted(v) for f, v in family_splits.items() if 'test' in v and len(v) > 1}
        if leaking:
            raise ValueError('Attack family crosses the test boundary: ' + repr(leaking))
    return samples, labels, evidence


def build_architecture_config(label, batch, dataset_directory, scenario_desc, split_map=None, t_view='raw'):
    template = read(ROOT / 'configs/architecture-smoke.json')
    if isinstance(split_map, dict) and isinstance(split_map.get('session_to_split'), dict):
        policy = ('DECLARED DEVIATION: attack-family holdout. The leakage boundary is the attack family '
                  '(attack_strategy x payload_family), not the source task: every attack family present in '
                  'test is absent from train/validation. One family spans several source tasks, so the same '
                  'lineage legitimately crosses splits here and the family check replaces the lineage check. '
                  'Benign sessions carry no family and keep a lineage-fixed split. Rule: '
                  + str(split_map.get('title', '')) + ' | ' + str(split_map.get('rule', '')))
    elif split_map:
        policy = ('DECLARED DEVIATION: lineage-level split override for this run only '
                  '(the frozen collection plan assigns every test task to other scenarios, so this '
                  'scenario has no held-out group). Override: '
                  + json.dumps(split_map, sort_keys=True)
                  + '; collected development_split is preserved per session; no derivative crosses splits')
    else:
        policy = 'Inherit frozen source-task lineage splits (train/validation/test); no derivative crosses splits'
    template.update(
        name='{}-latefusion-{}-r1'.format(label, batch),
        eligible_for_formal_results=False,
        collection_revision='split-local-' + label + '-r1',
        dataset_directory=dataset_directory,
        tasks='all collected ' + scenario_desc + ' user tasks (see 02_cohort samples)',
        split_policy=policy,
        split_override=split_map or None,
        T_view=t_view,
    )
    if t_view == 'behavior':
        template['T_encoder'] = ('Fixed sklearn HashingVectorizer character 3-5 grams, 4096 dimensions, '
            'alternate_sign=false, L2 normalization over the Agent-behavior view (role/tool/argument-shape/'
            'content-length tokens; no free text, no payload plaintext).')
    return template


def train(batch, scenarios, label, split_map=None, t_view='raw', sample_loader=None):
    if sample_loader is None:
        sample_loader = load_samples
    out = ROOT / 'experiment' / (batch + '-' + label + '-latefusion')
    if out.exists():
        raise ValueError('Training run already exists: ' + str(out))
    out.mkdir(parents=True)

    samples, labels, evidence = sample_loader(batch, scenarios, split_map)
    dataset_directory = batch + '/{' + ','.join(scenarios) + '}'
    scenario_desc = ' + '.join(scenarios)

    # 00_plan: frozen detector hyper-parameters (read by logbench.fusion / evaluate).
    plan_dir = out / '00_plan'
    plan_dir.mkdir()
    arch = build_architecture_config(label, batch, dataset_directory, scenario_desc, split_map, t_view)
    save(plan_dir / 'architecture-smoke.json', arch)
    save(plan_dir / 'cohort-source.json', {'batch': batch, 'scenario': label,
        'scenarios': scenarios, 'dataset_directory': dataset_directory, 'sessions': len(samples),
        'split_sessions': dict(collections.Counter(s['split'] for s in samples)),
        'scenario_sessions': dict(collections.Counter(s['scenario'] for s in samples)),
        'split_override': split_map or None,
        'collected_split_sessions': dict(collections.Counter(s.get('collected_split', s['split']) for s in samples)),
        'lineage_crossing': sorted(ln for ln in set(s['group'] for s in samples)
            if len(set(x['split'] for x in samples if x['group'] == ln)) > 1),
        'outcome_classes': {('%s:%s' % k): n for k, n in
            collections.Counter((e['y_attempt'], e['y_harm']) for e in evidence).items()}})
    seal(plan_dir)

    # Freeze executable training sources + dependency versions before any fit.
    source = out / 'training_sources'
    source.mkdir()
    paths = [ROOT / 'scripts/train_batch_latefusion.py', ROOT / 'scripts/session_storage.py',
             ROOT / 'scripts/validate_split_session.py'] + sorted((ROOT / 'logbench').glob('*.py'))
    for path in paths:
        dest = source / path.relative_to(ROOT)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
    import importlib.metadata
    versions = {n: importlib.metadata.version(n) for n in ('numpy', 'scipy', 'scikit-learn', 'joblib', 'threadpoolctl')}
    save(source / 'environment.json', {'python': sys.version, 'executable': sys.executable, 'versions': versions})
    seal(source)

    # 01_contract: only the three compressed T/E/N files per session are model inputs.
    contract = out / '01_contract'
    contract.mkdir()
    for sample in samples:
        folder = ROOT / sample['dataset_relative']
        destination = contract / sample['session_id'] / 'model_inputs'
        destination.mkdir(parents=True)
        for name in model_files(folder).values():
            shutil.copy2(folder / 'model_inputs' / name, destination / name)
        if t_view == 'behavior':
            shutil.copy2(folder / 'model_inputs' / BEHAVIOR_T_FILE, destination / BEHAVIOR_T_FILE)
        labels[sample['session_id']] = SessionStore(folder).json('labels.json')
        timing = SessionStore(folder).json('timing.json')
        fields = ('task_started_at','task_ended_at','task_started_relative','task_ended_relative')
        save(destination.parent/'timing.json', {k:timing[k] for k in fields})
    save(contract / 'boundary.json', {'input': 'Only three compressed T/E/N files per session',
        'T_view': t_view,
        'source': dataset_directory, 'old_topology_data_allowed': False})
    seal(contract)

    # 02_cohort: frozen samples + per-split label side-table.
    cohort = out / '02_cohort'
    cohort.mkdir()
    save(cohort / 'samples.json', samples)
    for split in ('train', 'validation', 'test'):
        save_rows(cohort / (split + '-labels.jsonl'), [dict(session_id=s['session_id'],
            y_attempt=labels[s['session_id']]['y_attempt'], y_harm=labels[s['session_id']]['y_harm'])
            for s in samples if s['split'] == split])
    save(cohort / 'evidence.json', evidence)
    seal(cohort)

    from logbench.represent import materialize
    from logbench.fusion import fit, score
    from logbench.evaluate import evaluate
    materialize(out, samples, t_view)
    fit(out, samples)
    score(out, samples)
    evaluate(out, samples)
    return verify(out, samples, batch, scenarios, label)


def verify(out, samples, batch, scenarios, label):
    from logbench.evaluate import metric_table
    for stage in ('00_plan', 'training_sources', '01_contract', '02_cohort', '03_represent',
                  '04_fit', '05_predictions', '06_evaluate'):
        verify_stage(out / stage)
    selection = read(out / '04_fit/selection.json')
    require(not selection['test_opened'], 'Fit opened test features')
    require(set(selection['fit_ids']) == {s['session_id'] for s in samples if s['split'] == 'train'}, 'Fit membership mismatch')
    require(set(selection['validation_ids']) == {s['session_id'] for s in samples if s['split'] == 'validation'}, 'Selection membership mismatch')
    raw = rows(out / '05_predictions/unlabeled.jsonl')
    joined = rows(out / '06_evaluate/predictions.jsonl')
    require(all('y_attempt' not in r and 'y_harm' not in r for r in raw), 'Truth in frozen predictions')
    require([{k: v for k, v in r.items() if k not in ('y_attempt', 'y_harm')} for r in joined] == raw, 'Joined scores changed')
    require(metric_table(joined) == read(out / '06_evaluate/metrics.json'), 'Metrics not reconstructible')
    arch = read(out / '00_plan/architecture-smoke.json')
    expected = {(s['session_id'], level, mask) for s in samples if s['split'] in ('validation', 'test')
                for level in arch['levels'] for mask in arch['masks']}
    require(len(raw) == len(expected) and {(r['session_id'], r['level'], r['mask']) for r in raw} == expected, 'Missing/duplicate predictions')
    choices = {(r['level'], r['mask']): r for r in selection['selections']}
    for r in raw:
        c = choices[(r['level'], r['mask'])]
        require(r['alert_F1'] == int(r['score'] >= c['threshold_F1']) and
                r['alert_low_FPR'] == int(r['score'] > c['threshold_low_FPR']), 'Frozen threshold mismatch')
    metrics = read(out / '06_evaluate/metrics.json')
    result = {'passed': True, 'batch': batch, 'scenario': label, 'scenarios': scenarios,
              'sessions': len(samples), 'prediction_rows': len(raw), 'metric_rows': len(metrics),
              'old_sessions_reused': 0, 'support_status': 'adapted', 'eligible_for_formal_results': False,
              'level2_TEN_test': next(r for r in metrics if r['level'] == 2 and r['mask'] == 'TEN' and r['split'] == 'test'),
              'limitations': arch['unsupported']}
    release = out / 'release'
    if not release.exists():
        release.mkdir()
        save(release / 'verification.json', result)
        evidence = read(out / '02_cohort/evidence.json')
        main = result['level2_TEN_test']
        summary = {'verification': result, 'samples': len(samples),
                   'split_sessions': read(out / '00_plan/cohort-source.json')['split_sessions'],
                   'outcome_classes': read(out / '00_plan/cohort-source.json')['outcome_classes'],
                   'fit_sessions': len(selection['fit_ids']), 'validation_sessions': len(selection['validation_ids']),
                   'fit_heads': len(read(out / '04_fit/training.json')),
                   'frozen_selections': len(selection['selections']),
                   'model_hashes': selection['model_hashes'],
                   'metrics': metrics}
        save(release / 'report.json', summary)
        text = (
            f'# {label} LateFusion 本地批次开发闭环（混合场景）\n\n'
            '本地随机分层采集 + 现有 LateFusion adapted 基线训练与冻结测试已完成。\n\n'
            f"- 批次：`{batch}`；场景：`{' + '.join(scenarios)}`；数据：`DataSet/{batch}/{{{','.join(scenarios)}}}`。\n"
            f"- {len(samples)} 条真实会话，按来源任务 lineage 划分 train/validation/test，无跨 split 同源。\n"
            f"- 三类结局均保留：攻击成功 harm1 / 攻击未成功 harm0+attempt / 良性；训练标签为 y_attempt。\n"
            f"- 仅用三个压缩 T/E/N 文件投影；训练拟合分支/词表/缩放，验证选择融合/阈值/概率映射，模型重载冻结后测试，预测先落盘再接标签。\n\n"
            f"主配置 Level2/TEN 工程测试：TP={main['TP']}、FP={main['FP']}、TN={main['TN']}、FN={main['FN']}，"
            f"F1={main['F1']:.4f}、FPR={main['FPR']:.4f}、AP={main['AP']:.4f}、AUROC={main['AUROC']:.4f}，"
            f"harm recall={main['harm_conditioned_recall']}（阳性支持 {main['harm_support']}）。\n"
            f"完整指标见 `06_evaluate/metrics.csv`，逐条预测见 `06_evaluate/predictions.csv`。\n\n"
            '本轮仅开发流程验证：多场景混合、小样本、固定攻击族，不能作为正式性能、稳定低 FPR 或跨场景结论；未按测试分数调参或替换会话。\n'
        )
        (release / 'report.md').write_text(text, encoding='utf-8')
        seal(release)
    return result


def parse_split_map(value):
    """Accept an inline JSON object or a path to a JSON file describing a split override.

    Accepted shapes:
      - ``{lineage: split}`` — lineage-level override (original behaviour);
      - ``{'lineage_to_split': {...}}`` — the same map behind a metadata wrapper;
      - ``{'session_to_split': {...}, 'family_of_session': {...}}`` — session-level
        attack-family holdout (see ``normalize_split_map``), returned verbatim so
        the whole declaration lands in the audit trail.
    """
    if value is None:
        return None
    text = Path(value).read_text(encoding='utf-8') if Path(value).is_file() else value
    data = json.loads(text)
    if not isinstance(data, dict) or not data:
        raise ValueError('--split-map must be a non-empty JSON object')
    if isinstance(data.get('session_to_split'), dict):
        for key, split in data['session_to_split'].items():
            if split not in ('train', 'validation', 'test'):
                raise ValueError('Bad split for ' + key + ': ' + repr(split))
        return data
    if isinstance(data.get('lineage_to_split'), dict):
        data = data['lineage_to_split']
    for key, split in data.items():
        if split not in ('train', 'validation', 'test'):
            raise ValueError('Bad split for ' + key + ': ' + repr(split))
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--batch', default='batch-hunyuan-chat-r1')
    parser.add_argument('--scenario', required=True,
                        help='Comma-separated scenarios to mix, or "all" for every scenario under the batch.')
    parser.add_argument('--tag', default=None,
                        help='Optional suffix distinguishing a representation/feature variant run.')
    parser.add_argument('--phase', choices=['train', 'verify'], default='train')
    parser.add_argument('--split-map', default=None,
                        help='Declared split deviation: JSON object (or path) of source-task lineage -> split, '
                             'or a session-level attack-family holdout map with session_to_split / '
                             'family_of_session. Recorded in 00_plan/cohort-source.json; the collected split '
                             'is preserved per session.')
    parser.add_argument('--t-view', choices=['raw', 'behavior'], default='raw',
                        help='Which T trajectory to feed the model: "raw" (original trajectory, default) or '
                             '"behavior" (payload-free Agent-behavior view: role/tool/argument-shape/content-length '
                             'only, no free text).')
    args = parser.parse_args()
    if args.scenario == 'all':
        scenarios = sorted(p.name for p in (ROOT / 'DataSet' / args.batch).iterdir() if p.is_dir())
        require(scenarios, 'No scenario directories under batch: ' + args.batch)
        label = 'mixed'
    else:
        scenarios = [s.strip() for s in args.scenario.split(',') if s.strip()]
        require(scenarios, 'Empty scenario list')
        label = scenarios[0] if len(scenarios) == 1 else 'mixed-' + '-'.join(scenarios)
    if args.tag:
        label = label + '-' + args.tag
    out = ROOT / 'experiment' / (args.batch + '-' + label + '-latefusion')
    if args.phase == 'train':
        result = train(args.batch, scenarios, label, parse_split_map(args.split_map), args.t_view)
        print(json.dumps({'output': str(out), 'passed': result['passed'],
                          'sessions': result['sessions'],
                          'level2_TEN_test': result['level2_TEN_test']}, ensure_ascii=False), flush=True)
    else:
        # Reuse the declared override exactly as frozen in 00_plan, never re-parsed from argv.
        split_map = read(out / '00_plan/cohort-source.json').get('split_override')
        samples, _, _ = load_samples(args.batch, scenarios, split_map)
        result = verify(out, samples, args.batch, scenarios, label)
        print(json.dumps(result, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
