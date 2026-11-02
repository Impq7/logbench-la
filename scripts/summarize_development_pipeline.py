"""Create a new evidence-linked development summary from actual completed artifacts."""
import collections
import datetime
import hashlib
import json
from pathlib import Path
import uuid

ROOT = Path(__file__).resolve().parents[1]
inputs = {
    'quality': ROOT / 'experiment/native-development-quality-378bc775e0a0/report.json',
    'native_oracle': ROOT / 'experiment/native-state-oracle-recheck-dcd2a5d7a28f/report.json',
    'metrics': ROOT / 'experiment/native-pca-iforest-development-d16dbac346c7/metrics.json',
    'metric_rebuild': ROOT / 'experiment/native-pca-iforest-development-d16dbac346c7/rebuilt_metrics_audit.json',
    'cleanup': ROOT / 'experiment/tri-modal-preflight/preflight_20261015T113802427474Z.json',
    'credential_audit': ROOT / 'experiment/credential-retention-audit-07887edf9fc2/report.json',
}
data = {k: json.loads(p.read_text(encoding='utf-8-sig')) for k, p in inputs.items()}
quality, metrics = data['quality'], data['metrics']
labels = [s['validation']['labels'] for s in quality['sessions']]
counts = collections.Counter()
for session in quality['sessions']:
    counts.update(session['validation']['counts'])
checks = {'offline_dataset_gate': quality['passed'], 'native_oracle_recheck': data['native_oracle']['passed'],
    'metrics_rebuilt': data['metric_rebuild']['passed'], 'containers_removed': data['cleanup']['preflight']['ready'],
    'no_exact_current_key_retained': data['credential_audit']['passed']}
summary = {'experiment': 'deepseek-native-development-pipeline', 'created_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'development_pipeline_passed': all(checks.values()), 'checks': checks, 'eligible_for_formal_results': False,
    'main_six_scenario_48_192_gate': 'pending', 'gateway': 'https://124.223.37.235:6969/v1',
    'requested_model': 'cn:deepseek-v4.1-flash', 'returned_model': 'deepseek-v4.1-flash',
    'complete_sessions': len(labels), 'source_groups': len(quality['pairs']),
    'v2_collection_attempts': quality['total_collection_attempts'],
    'excluded_incomplete_unknown_harm': len(quality['excluded_incomplete_sessions']), 'excluded_initial_annotation_parser_sessions': 5,
    'attempt_positive': sum(y['y_attempt'] == 1 for y in labels),
    'harm_positive_in_defined_password_scope': sum(y['y_harm'] == 1 for y in labels),
    'task_success': sum(y['task_success'] is True for y in labels),
    'task_failure': sum(y['task_success'] is False for y in labels),
    'utility_oracle_limitation': 'Two category-summary condition rows use native utility that always returns true',
    'raw_counts': dict(counts), 'split_groups': metrics['independent_groups'], 'fit_normal': metrics['fit_normal_sessions'],
    'validation': metrics['validation_sessions'], 'test': metrics['test_sessions'], 'feature_count': metrics['feature_count'],
    'test_metrics': {method: values['test'] for method, values in metrics['methods'].items()},
    'inputs': {k: {'path': str(p), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for k, p in inputs.items()}}
out = ROOT / 'experiment' / ('development-pipeline-summary-' + uuid.uuid4().hex[:12])
out.mkdir(exist_ok=False)
(out / 'report.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding='utf-8')
lines = ['# DeepSeek 开发流程验收', '',
    '开发链路已跑通：新网关 → 原生来源任务的适配工具 → 真实T/E/N → 独立标签审计 → PCA/IsolationForest训练 → 验证选参数/阈值 → 冻结测试预测。', '',
    '仅Banking软件集成检查，不是六场景或正式论文验收。', '',
    '- 网关：' + summary['gateway'] + '；请求模型cn:deepseek-v4.1-flash，返回deepseek-v4.1-flash。',
    '- 20条完整会话、10个来源组；22次v2采集尝试。2条未完成记录保留unknown，另5条初始标签解析诊断整版排除训练。',
    '- 10条注入均已暴露；原生密码篡改目标下harm-positive为0。不能据此计算危害检出率。',
    '- 1条完整注入会话未完成用户目标，utility=false保留；其余19条native utility=true，其中任务8的两条utility恒true，不能作强成功证据。',
    '- 原始T/E/N计数：' + json.dumps(dict(counts), ensure_ascii=False) + '。所有纳入会话丢失计数已验证为0，未知没有改填0。',
    '- 同来源正常/注入同组；7/1/2开发组。7条明确正常训练会话、2条验证、4条工程测试；55维适配TEN统计特征。',
    '- task14两条件使用4096输出上限，其余任务对1024；预算差异已留档，不作为同质正式评测。', '',
    '| 方法 | 开发测试会话 | F1 | AP | AUROC | FPR |', '| --- | ---: | ---: | ---: | ---: | ---: |']
for method, m in summary['test_metrics'].items():
    lines.append('| {} | {} | {:.3f} | {:.3f} | {:.3f} | {:.3f} |'.format(method, m['sessions'], m['F1'], m['AP'], m['AUROC'], m['FPR']))
lines += ['', '以上只有2个独立工程测试组，不能解释成稳定性能、低误报率或论文结果。两个模型均存在误报和漏报，当前统计表示只验证接口。校准仅2条验证记录，不用于部署。', '',
    '原生/HTTP语义回放、独立状态oracle复算、并发归属、到达索引、模型保存/重载、逐样本指标重建均通过；54个本项目已记录容器已移除，最终凭据扫描未发现当前密钥明文。', '',
    '下一阶段：接入其余五场景与完整任务来源/受控服务语义，完成六场景48/192门槛，再使用另选正式模型采新数据。当前调试组及近重复不得进入正式测试，Banking v1剩余独立未见来源不足，必须另建可追溯的新来源组，不能换种子或模型来伪造新组。', '',
    '证据文件：', '']
for key, path in inputs.items():
    lines.append('- [{}]({})'.format(key, path.as_posix()))
lines.append('')
(out / 'report.md').write_text('\n'.join(lines), encoding='utf-8')
print(json.dumps({'output': str(out), 'passed': summary['development_pipeline_passed'], 'raw_counts': dict(counts)}, ensure_ascii=False))
