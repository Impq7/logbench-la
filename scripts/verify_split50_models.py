"""Post-fit verification only: exact inputs, disjoint lineages and frozen model replay."""
import argparse
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from logbench import runtime
import joblib
from logbench.artifacts import read, rows, save, seal, sha
from logbench.fusion import prediction
from logbench.represent import load_streams
from run_split50 import get_plan
from split50_training import require, verify
from session_storage import SessionStore


def audit(out, output_name='closeout'):
    require(Path(output_name).name == output_name and output_name.startswith('closeout'), 'Audit output must be a local closeout directory')
    plan = get_plan(out)
    verified = verify(out, plan)
    samples = read(out / '02_cohort/samples.json')
    evidence = {e['session_id']: e for e in read(out / 'quality/sessions.json')}
    group_sets = {k: {s['group'] for s in samples if s['split'] == k} for k in ('train', 'validation', 'test')}
    require(not (group_sets['train'] & group_sets['validation'] or group_sets['train'] & group_sets['test'] or
        group_sets['validation'] & group_sets['test']), 'Lineage overlap')
    fields = {'T': {'time', 'arrival', 'role', 'tool', 'content', 'arguments'},
        'E': {'time', 'arrival', 'event', 'process_role', 'direction', 'path_class', 'result', 'socket_known'},
        'N': {'time', 'arrival', 'protocol', 'direction', 'length', 'application_role', 'ip_version', 'dns_questions'}}
    label_rows = {r['session_id']: r for k in group_sets for r in rows(out / '02_cohort' / (k + '-labels.jsonl'))}
    for s in samples:
        expected = ROOT / 'DataSet' / plan['settings']['dataset_directory'] / 'sessions' / s['session_id']
        require((ROOT / s['dataset_relative']).resolve() == expected.resolve(), 'Dataset boundary mismatch')
        for name, digest in evidence[s['session_id']]['model_input_hashes'].items():
            require(sha(out / s['canonical'] / '01_model_inputs' / name) == digest, 'Fit copy differs from QA input')
        truth = SessionStore(expected).json('labels.json')
        require(all(label_rows[s['session_id']][k] == truth[k] for k in ('y_attempt', 'y_harm')), 'Cohort labels differ from oracle side table')
        for m in 'TEN':
            require(all(set(r) == fields[m] for r in rows(out / '03_represent' / s['session_id'] / (m + '.jsonl'))), 'Unexpected feature field')
    # No fit/selection calls here. Replay the already frozen models and configurations.
    selected = [s for s in samples if s['split'] in ('validation', 'test')]
    streams = load_streams(out, selected)
    frozen = {(r['session_id'], r['level'], r['mask']): r for r in rows(out / '05_predictions/unlabeled.jsonl')}
    checked = 0
    cfg = read(out / '00_plan/architecture-smoke.json')
    for level in cfg['levels']:
        bundle = joblib.load(out / '04_fit' / ('LateFusion-level-' + str(level) + '.joblib'))
        require(bundle['config'] == cfg, 'Model configuration differs from frozen plan')
        for mask in cfg['masks']:
            replayed = prediction(bundle, [streams[s['session_id']] for s in selected], mask)
            for s, r in zip(selected, replayed):
                original = frozen[(s['session_id'], level, mask)]
                require(all(original[k] == v for k, v in r.items()), 'Frozen model replay changed prediction')
                checked += 1
    main = verified['level2_TEN_test']
    qa = read(out / 'quality/report.json')
    validation_ids = {s['session_id'] for s in samples if s['split'] == 'validation'}
    normal_val = sum(r['y_attempt'] == 0 for sid, r in label_rows.items() if sid in validation_ids)
    result = {'passed': True, 'batch_id': plan['batch_id'], 'sessions': len(samples),
        'source_groups': {k: sorted(v) for k, v in group_sets.items()},
        'model_input_copy_hashes_checked': len(samples) * 3, 'cohort_labels_match_independent_side_tables': True,
        'representation_fields_exclude_labels_ids_and_oracles': True, 'exact_frozen_prediction_replays': checked,
        'new_fit_or_selection_calls': 0, 'old_data_reused': 0,
        'level2_TEN_F1_threshold': {k: main[k] for k in ('F1', 'FPR', 'TP', 'FP', 'TN', 'FN', 'AP', 'AUROC')},
        'level2_TEN_normal_val_quantile_threshold': {'test_FPR': main['achieved_FPR_at_normal_val_95_quantile'],
            'test_normal_support': main['normal_support'], 'calibration_normal_support': normal_val,
            'interpretation': 'This engineering run does not establish a low-FPR operating point'},
        'eligible_for_formal_results': False,
        'limitations': plan['configuration']['limitations'] + ['Shared fixed payload family across development splits; no attack-family holdout',
            'No harm-positive model sessions; harm recall remains undefined']}
    stage = out / output_name
    save(stage / 'audit.json', result)
    shutil.copy2(__file__, stage / 'verify_split50_models.py')
    content = f'''# 双容器 50 会话：采集与 LateFusion 开发闭环

已完成{len(samples)}条全新会话、整批QA、LateFusion adapted训练/验证/工程测试与独立复核。旧拓扑和先前split会话复用数均为0。

- 10个Banking来源组，各2正常+3注入；条数35/5/10按来源组7/1/2划分。全部属于开发用途。
- T{qa['counts']['T']} / E{qa['counts']['E']} / 主N{qa['counts']['N_primary']}，{qa['API_requests']}次API、{qa['counts']['tools']}次工具；注入暴露{qa['exposed_injection']}/{qa['attempts']}，定义的密码篡改危害阳性{qa['harm_positive']}、unknown{qa['harm_unknown']}，native utility=true {qa['task_success']}/{len(samples)}（task8恒true）。
- 每会话双容器、独立命名空间及业务bridge；工具均有两端E和双向PCAP，Agent lo工具包0。传感器报告丢失0，原始SHA、到达索引、初态、并发隔离、清理回执及四层压缩目录通过。
- 20次无模型语义诊断单独留档，不计模型样本。DataLoader只读01的三个gzip。
- {len(read(out / '04_fit/training.json'))}个分支头、{len(read(out / '04_fit/selection.json')['selections'])}个冻结配置；{verified['prediction_rows']}行预测、{verified['metric_rows']}行指标。独立复核{len(samples)*3}个模型输入副本SHA、同源组隔离、标签侧表和可观测字段边界；保存模型重载后的{checked}条冻结预测全部精确复现，没有新增拟合或选择调用。

| Level2/TEN工程测试操作点 | 结果 |
| --- | --- |
| 验证F1选择阈值 | TP{main['TP']} / FP{main['FP']} / TN{main['TN']} / FN{main['FN']}；F1={main['F1']:.4f}，precision={main['precision']}，recall={main['recall']:.4f}，FPR={main['FPR']}；AP={main['AP']} / AUROC={main['AUROC']} |
| 正常验证95%分位阈值（严格>） | 测试FPR={main['achieved_FPR_at_normal_val_95_quantile']}；测试正常支持{main['normal_support']}，校准正常支持{normal_val}，不能认为满足低误报要求 |
| harm-conditioned recall | {main['harm_conditioned_recall']}；危害阳性支持{main['harm_support']} |

只有1个验证来源组、2个工程测试来源组，并且载荷族固定、同源重复较多；这些数字不能作为正式性能、稳定低FPR或跨场景结论。没有按测试结果调参、重采或替换。网关返回名只作报告身份。

数据：`DataSet/{plan['settings']['dataset_directory']}`，服务器：`/root/wxq/agent_benchmark/logbench-la-clean/{plan['settings']['remote_subdirectory']}`。

- [整批质量报告](../quality/report.json)
- [模型与验证选择记录](../04_fit/selection.json)
- [逐样本预测](../06_evaluate/predictions.csv) / [完整指标](../06_evaluate/metrics.csv)
- [采集训练完整报告](../release/report.json) / [本次独立复核](audit.json)
'''
    with (stage / 'report.md').open('x', encoding='utf-8') as stream:
        stream.write(content)
    seal(stage)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--output-name', default='closeout')
    args = parser.parse_args()
    import json
    print(json.dumps(audit(args.run_dir.resolve(), args.output_name), ensure_ascii=False))
