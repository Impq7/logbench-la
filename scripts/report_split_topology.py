"""Immutable topology-change report from explicit new session IDs; never retrain."""
import argparse
import collections
import json
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

from collection_session import read, rows, sha, save, save_rows, save_csv

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--sessions',nargs=2,required=True)
    parser.add_argument('--diagnostics',nargs=2,required=True)
    args=parser.parse_args()
    settings=read(ROOT/'configs/split-containers.json')
    base=ROOT/'DataSet'/settings['dataset_directory']
    out=ROOT/'experiment'/('split-topology-change-'+uuid.uuid4().hex[:12])
    out.mkdir()
    sample_rows,proof,summary,input_hashes=[],[],[],{}
    for category,ids in [('sessions',args.sessions),('diagnostics',args.diagnostics)]:
        for sid in ids:
            if not sid.startswith('split-session-') or Path(sid).name!=sid:
                raise ValueError('Invalid explicit session ID')
            folder=base/category/sid if category=='sessions' else base/category/'sessions'/sid
            quality=read(folder/'collection_validation.json')
            report=read(folder/'report.json')
            if not quality['passed'] or quality['replay'] != (category=='diagnostics'):
                raise ValueError('Wrong category or failed gate')
            for name,expected in report['sha256'].items():
                if sha(folder/name)!=expected:
                    raise ValueError('Raw hash changed')
                input_hashes[(folder/name).relative_to(ROOT).as_posix()]=expected
            cleanup=[c for c in report['checks'] if c['argv'][:3]==['docker','rm','-f']]
            network_cleanup=[c for c in report['checks'] if c['argv'][:3]==['docker','network','rm']]
            if len(cleanup)!=4 or not all(c['returncode']==0 for c in cleanup+network_cleanup) or len(network_cleanup)!=1:
                raise ValueError('New app/sensor containers or private network cleanup failed')
            label=read(folder/'labels.json')
            entry={'session_id':sid,'category':category,'condition':report['condition'],
                'source_task_group_id':report['source_task_lineage'],'y_attempt':label['y_attempt'],'y_harm':label['y_harm'],
                'exposed':label['exposed_injection'],'task_success':label['task_success'],
                'T':quality['counts']['T'],'E':quality['counts']['E'],'N_primary':quality['counts']['N_primary'],
                'API_requests':quality['API_requests'],'tool_calls':quality['counts']['tools'],
                'agent_business_interface':report['agent_business_interface'],
                'tool_loopback_packets':quality['tool_packets_on_agent_loopback'],'all_passed':True}
            sample_rows.append(entry)
            proof.extend(dict(p,session_id=sid,category=category) for p in quality['tool_network_proof'])
            if category=='sessions':
                from development_features import extract
                vector=extract(folder)
                save(out/(sid+'-feature-interface-check.json'),{'feature_count':len(vector),'feature_names':list(vector),
                    'finite_nonnegative':all(__import__('math').isfinite(v) and v>=0 for v in vector.values()),
                    'note':'Observable-only feature smoke; no detector fitting, threshold selection or test scoring'})
    actual=[r for r in sample_rows if r['category']=='sessions']
    if {r['condition'] for r in actual}!={'benign','injected'}:
        raise ValueError('Need one real pair, no duplicate conditions')
    modules=['test_chat_transport','test_collection_integrity','test_contracts','test_label_audit',
        'test_native_development','test_split_containers','test_session_storage']
    tests=subprocess.run([sys.executable,'-m','unittest','-v']+modules,
        cwd=ROOT/'scripts',stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8')
    (out/'unit-tests.stdout.log').write_text(tests.stdout,encoding='utf-8')
    (out/'unit-tests.stderr.log').write_text(tests.stderr,encoding='utf-8')
    if tests.returncode:
        raise ValueError('Unit/regression test failure; logs retained')
    import re
    count=int(re.search(r'Ran (\d+) tests',tests.stderr)[1])
    sources=['split_access.ps1','split_remote_access.py','server_split_collect.py','split_agent_worker.py',
        'split_tool_backend.py','validate_split_session.py','test_split_containers.py','report_split_topology.py',
        'native_banking.py','gateway_protocol.py','collection_session.py','packet_metadata.py',
        'validate_native_session.py','development_features.py','session_storage.py']
    target=out/'sources'
    target.mkdir()
    for name in sources:
        shutil.copy2(ROOT/'scripts'/name,target/name)
    shutil.copy2(ROOT/'logbench/represent.py',target/'represent.py')
    shutil.copy2(ROOT/'configs/split-containers.json',out/'frozen-config.json')
    save_csv(out/'session_manifest.csv',list(sample_rows[0]),sample_rows)
    save_rows(out/'tool-network-proof.jsonl',proof)
    save(out/'raw-input-hashes.json',input_hashes)
    data={'passed':True,'scope':'Split container topology acceptance, two real development sessions plus two diagnostic replays',
        'eligible_for_formal_results':False,'sessions':sample_rows,'actual_model_session_totals':{
            key:sum(r[key] for r in actual) for key in ('T','E','N_primary','API_requests','tool_calls')},
        'unit_tests_passed':count,'reported_sensor_losses':0,
        'raw_files_unchanged':len(input_hashes),'app_and_sensor_containers_removed':16,'session_networks_removed':4,
        'model_training_runs':0,'data_merged_with_loopback_revision':False,
        'test_modules':modules,'previous_detector_architecture_suite':{
            'status':'unavailable','reason':'DataSet/runtime-detectors is absent; joblib import fails. No dependencies installed for this collection-only topology change.'},
        'sources_sha256':{p.name:sha(p) for p in target.iterdir()}}
    # Source input hashes must still agree after feature/test checks.
    if any(sha(ROOT/name)!=expected for name,expected in input_hashes.items()):
        raise ValueError('Raw inputs changed during verification')
    save(out/'verification.json',data)
    totals=data['actual_model_session_totals']
    lines=['# Agent / mock 后端双容器拓扑验收','',
        '每个会话创建独立 Agent 容器和独立 mock 后端容器，mount/net namespace 和 IP 均不同。', '',
        'Agent 通过默认 bridge 的 API 网卡访问既有 HTTPS 模型网关；业务网卡连接会话专用 internal bridge。后端仅连接 internal bridge，没有端口发布或网关凭据。两个业务容器均 cap-drop ALL/no-new-privileges；可信宿主协调器拥有 Docker 权限，模型没有。', '',
        '业务 HTTP 只开放 /call，返回 content/error；任务状态只在后端内存。原生 oracle 和状态快照在 Agent task_end 后，通过 Docker stdin 控制通道导出，不经过模型可见工具通道。', '',
        'E 为两个独立 Tracee 传感器，按两个容器的 mount namespace 归属，并以 session/role/process 标识区分 PID 重号。N 主流为 Agent API 网卡 + Agent 业务网卡；后端网卡仅作交叉验证，lo 仅作迁移核对，不重复累计模型 N。', '',
        f'已完成正常/注入两条无模型原生语义回放（均有已知危害阳性对照），再完成正常/注入两条模型会话。模型会话合计 T={totals["T"]}、E={totals["E"]}、主 N={totals["N_primary"]}；{totals["API_requests"]} 次 API、{totals["tool_calls"]} 次工具调用。', '',
        f'{count} 项单元/回归测试通过。四个运行的原始 {len(input_hashes)} 个文件 SHA 不变；16 个本次记录容器及 4 个会话网络清理命令全部成功。', '',
        '逐调用五元组、Agent E connect、后端 E accept、Agent/后端独立网卡包数在 tool-network-proof.jsonl；四个运行的 Agent lo 工具包均为0。传感器报告丢失均为0，unknown 仍不能填0。', '',
        '正常/注入标签、暴露、危害与 utility 见 session_manifest.csv。诊断回放的已知危害阳性不计论文模型样本；真实模型会话保持独立开发目录。首次危害精确时间保持unknown。', '',
        '拆分已验证网络路径可见性和归属，不保证包级元数据能区分恶意语义。未训练/调参/重评检测器，不宣称检测性能改善。原loopback版本及其结果按历史版本保留，不与新版合并。', '',
        '回归范围为采集/协议/标签/新拓扑与表示接口。首次全目录测试因本地 DataSet/runtime-detectors 已缺失、joblib 无法导入而中止，日志保留在此前的 split-topology-change 失败目录；本轮未安装检测器依赖或重跑旧检测实验。', '',
        '入口：scripts/split_access.ps1 -Mode replay-benign|replay-injected|benign|injected。真实模型入口要求当前源码的两条件回放先通过。配置 configs/split-containers.json；新数据 DataSet/deepseek-split-containers/；服务器证据 /root/wxq/agent_benchmark/logbench-la-clean/development-split/。','']
    (out/'report.md').write_text('\n'.join(lines),encoding='utf-8')
    save(out/'manifest.json',{p.relative_to(out).as_posix():sha(p) for p in out.rglob('*') if p.is_file()})
    print(json.dumps({'output':str(out),'passed':True,'totals':totals,'unit_tests':count},ensure_ascii=False,indent=2))


if __name__=='__main__':
    main()
