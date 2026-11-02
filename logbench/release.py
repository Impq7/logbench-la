"""L6 rebuild tables from saved predictions and verify immutable source evidence."""
import csv
import json
import platform
import shutil
import sys
import numpy as np
import sklearn

from .artifacts import ROOT, now, read, rows, save, save_csv, seal, sha, verify
from .cohort import assert_group_split
from .evaluate import metric_table
from .registry import registry


def verify_run(out):
    stages = ['00_plan', '01_contract', '02_cohort', '03_represent', '04_fit', '05_predictions', '06_evaluate']
    if (out / '07_release/manifest.json').exists():
        stages.append('07_release')
    for stage in stages:
        verify(out / stage)
    samples = read(out / '02_cohort/samples.json')
    assert_group_split(samples)
    for path, digest in read(out / '01_contract/source_hashes.json').items():
        if sha(ROOT / path) != digest:
            raise ValueError('Original input changed: ' + path)
    predictions = rows(out / '06_evaluate/predictions.jsonl')
    if metric_table(predictions) != read(out / '06_evaluate/metrics.json'):
        raise ValueError('Metrics do not rebuild from predictions')
    choices = {(r['level'], r['mask']): r for r in read(out / '04_fit/selection.json')['selections']}
    seen = set()
    for row in predictions:
        key = (row['session_id'], row['level'], row['mask'])
        if key in seen:
            raise ValueError('Duplicate prediction')
        seen.add(key)
        choice = choices[(row['level'], row['mask'])]
        if row['alert_F1'] != int(row['score'] >= choice['threshold_F1']) or row['alert_low_FPR'] != int(row['score'] > choice['threshold_low_FPR']):
            raise ValueError('Frozen threshold mismatch')
    expected = {(s['session_id'], level, mask) for s in samples if s['split'] != 'train'
                for level, mask in choices}
    if seen != expected:
        raise ValueError('Prediction support differs from cohort')
    # Every labelled score must equal the score sealed before labels were joined.
    before = {(r['session_id'], r['level'], r['mask']): r for r in rows(out / '05_predictions/unlabeled.jsonl')}
    for row in predictions:
        raw = before[(row['session_id'], row['level'], row['mask'])]
        if any(row[k] != v for k, v in raw.items()):
            raise ValueError('Prediction changed after test labels were opened')
    return {'passed': True, 'stages_verified': len(stages), 'predictions': len(predictions),
        'metrics_rebuilt': len(metric_table(predictions)), 'zero_group_overlap': True,
        'original_files_unchanged': len(read(out / '01_contract/source_hashes.json')),
        'thresholds_verified': True, 'labels_joined_after_scoring': True,
        'eligible_for_formal_results': False}


def release(out):
    result = verify_run(out)
    stage = out / '07_release'
    stage.mkdir()
    save(stage / 'verification.json', result)
    save_csv(stage / 'registry.csv', registry())
    save(stage / 'environment.json', {'python': sys.version, 'platform': platform.platform(),
        'numpy': np.__version__, 'sklearn': sklearn.__version__, 'created_utc': now()})
    # Retain the exact implementation and configuration; no secrets or unrelated datasets.
    sources = list((ROOT / 'logbench').glob('*.py')) + [ROOT / 'scripts/run_architecture_smoke.py']
    sources += [ROOT / 'scripts' / name for name in ('collection_session.py',
        'packet_metadata.py', 'validate_native_session.py', 'validate_sensor_contract.py',
        'server_sensor_check.py', 'gateway_protocol.py', 'test_architecture_smoke.py')]
    for path in sources:
        target = stage / 'sources' / path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    save(stage / 'architecture-coverage.json', {
        'L0': 'Existing isolated Banking collector; six new sessions plus two existing integrity-r1 sessions',
        'L1': 'Reuse deterministic collection QA and independent native oracle; revalidate copied evidence without changing original raw',
        'L2': 'Frozen 4/2/2 sessions across 2/1/1 source-task groups, development only',
        'L3': 'Nine adapted representations, 64-event/32-stride windows, seven masks; single length stratum',
        'L4': 'LateFusion only; 9 fitted branches, 21 level/mask configurations, validation fusion/threshold/calibration',
        'L5': 'Offline metrics, validation stress and CPU timing; unsupported transfer/online/full statistics explicit',
        'L6': 'Hashes, source snapshots, models, trials, frozen predictions, CSV and independent metric reconstruction',
        'difference': 'Compact layer modules instead of empty directories for unimplemented methods; not a full paper reproduction'})
    tables = read(out / '06_evaluate/metrics.json')
    main = next(r for r in tables if r['level'] == 2 and r['mask'] == 'TEN' and r['split'] == 'test')
    totals = {m: sum(r['counts'][m] for r in read(out / '01_contract/checks.json')) for m in 'TEN'}
    new_count = sum(sum(r.get('passed', False) for r in read(p)['results']) for p in out.glob('collection-*/report.json'))
    session_count = len(read(out / '02_cohort/samples.json'))
    summary = {'run_id': out.name, 'status': 'smoke_passed', 'eligible_for_formal_results': False,
        'sessions': session_count, 'new_sessions': new_count, 'reused_integrity_r1_sessions': session_count-new_count,
        'raw_counts': totals, 'main_test_level2_TEN': main, 'verification': result}
    save(stage / 'summary.json', summary)
    lines = ['# LateFusion 架构冒烟测试', '',
        '已跑通现有 Banking 采集与 L1 校验 → L2 分组队列 → L3 表示 → L4 训练和冻结预测 → L5 指标 → L6 重建检查。', '',
        '范围：8 会话（6 条新采 + 2 条已有修复版），4 个来源组，训练/验证/工程测试为 4/2/2 会话、2/1/1 组；所有组永久排除正式测试。未读取作废轨迹。', '',
        '采集模型：cn:deepseek-v4.1-flash；检测基准：LateFusion adapted。T 是固定字符哈希编码和线性头，E/N 是训练集拟合的统计编码、标准化和线性头，尚未接预训练语义编码器。', '',
        '实现三档 T/E/N 表示，64 事件窗口、步长 32，窗口分数取最大值；训练会话标签传播给窗口，不声称事件级真值。每会话总训练权重相同。长度校正仅单分层，验证正常样本只有 1 条，g 的零方差用预声明单位尺度。', '',
        '融合比较 mean/max/步长 0.25 非负权重；只用验证集选择融合、F1 阈值和正常 95% 分位阈值，以及两参数概率映射。所有模型重载和选择冻结后再读测试特征，评分落盘后才接测试标签。', '',
        f'原始记录 T={totals["T"]}、E={totals["E"]}、N={totals["N"]}。各会话采集门槛通过，原始文件 SHA 复核不变。', '',
        f'工程测试 Level 2 / TEN：F1={main["F1"]}，AP={main["AP"]}，AUROC={main["AUROC"]}，FPR={main["FPR"]}；正常/注入各 1 条。', '',
        '这是流程连通性结果，小样本和固定 payload 不支持泛化、稳定 FPR 或论文性能结论。harm recall 无阳性则保持 null；不能把未篡改密码理解成不存在任何危害。任务 8 上游 utility 恒 true。', '',
        '只在验证集运行 5/10/20% 事件丢失与 25/50/75% 前缀压力检查；仅是离线敏感性诊断。资源记录含 3 次预热、10 次 CPU 批评分计时；未测隔离峰值 RSS/GPU。', '',
        '尚未完成：其他五场景、预训练语义 T 编码器、其他 22 方法、分布迁移、在线告警预算/首次危害时间/真实干预、多种子和正式 bootstrap。', '',
        '文件：`../06_evaluate/metrics.csv`、`predictions.csv`、`../04_fit/selection.json`、`trials.jsonl`、`verification.json`。', '',
        '复核命令（项目根目录）：', '',
        '```powershell',
        f"& 'C:/Users/WXQ/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe' scripts/run_architecture_smoke.py verify --run-dir experiment/{out.name}",
        '```', '',
        '各层目录的 manifest.json 可独立验 hash。阶段文件使用排他创建；需要新实验时用 prepare 生成新的运行目录。源码快照在 sources/，运行依赖在 environment.json；不是脱离本项目即可独立采集的公开发布包。', '']
    with (stage / 'report.md').open('x', encoding='utf-8') as stream:
        stream.write('\n'.join(lines))
    seal(stage)
    return summary
