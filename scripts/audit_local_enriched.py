"""Read only this explicitly named pilot; independently verify retained sample evidence."""
import argparse
import collections
import csv
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys

from session_storage import SessionStore,verify_packed,load_model_inputs,DIRECTORIES
from validate_native_session import audit_labels
from validate_split_session import check_topology
from validate_sensor_contract import loss_values


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def audit(data,run):
    plan=read(run/'00_plan/frozen.json')
    images=read(run/'00_plan/launcher_sources/images.json')
    summary=read(data/'manifest/selection_summary.json')
    if read(data/'manifest/frozen.json')!=plan or data.name!=plan['batch_id']:
        raise ValueError('Wrong named dataset')
    folders=sorted((data/'sessions').iterdir())
    rows={name:list(csv.DictReader((data/'manifest'/name).open(encoding='utf-8-sig',newline='')))
          for name in ('sessions.csv','labels.csv')}
    for table in rows.values():
        if len(table)!=len(folders) or {r['session_id'] for r in table}!={p.name for p in folders}:
            raise ValueError('Top level manifest membership differs')
    counts=collections.Counter()
    entries=[]
    for folder in folders:
        if {p.name for p in folder.iterdir()}!=set(DIRECTORIES):
            raise ValueError('Four directory boundary violated')
        storage=verify_packed(folder)
        store=SessionStore(folder)
        for table,kind in (('sessions.csv','session'),('labels.csv','labels')):
            row=next(r for r in rows[table] if r['session_id']==folder.name)
            for key,value in store.manifest['catalog'][kind].items():
                if row[key]!=('NaN' if value is None else str(value)):
                    raise ValueError('Top-level CSV value differs from sealed per-session catalog')
        report,qa,y=[store.json(n) for n in ('report.json','collection_validation.json','labels.json')]
        if report['replay'] or report['collection_revision']!=plan['settings']['collection_revision']:
            raise ValueError('Replay or other topology mixed into model queue')
        if report['model_requested']!='cn:hunyuan-chat' or check_topology(report):
            raise ValueError('Model or container topology mismatch')
        for role in ('agent','backend'):
            if report['roles'][role]['image_id']!=images[plan['settings']['runtime_image_'+role]]:
                raise ValueError('Role image differs from frozen launch identity')
        if not qa['passed'] or not qa['label_audit']['passed'] or qa['tool_packets_on_agent_loopback']!=0:
            raise ValueError('Retained sample failed QA')
        if qa['validator_sha256']!=plan['source_hashes']['validate_split_session.py']:
            raise ValueError('Semantic validator differs from frozen source')
        for role in ('agent','backend'):
            before=loss_values(store.read_bytes('tracee_'+role+'_before.txt').decode())
            after=loss_values(store.read_bytes('tracee_'+role+'_after.txt').decode())
            if not before or before.keys()!=after.keys() or any(after[k]-before[k]!=0 for k in before):
                raise ValueError('Recomputed Tracee losses are unknown/nonzero')
        for name,meta in report['captures'].items():
            drop=re.search(r'(\d+) packets dropped by kernel',store.read_bytes(name+'.log').decode())
            if not drop or int(drop[1])!=0 or meta['exit_code']!=0:
                raise ValueError('Recomputed PCAP loss gate failed')
        for name,digest in report['sha256'].items():
            if hashlib.sha256(store.read_bytes(name)).hexdigest()!=digest:
                raise ValueError('Original raw hash changed')
        inputs=load_model_inputs(folder)
        if any(not inputs[m] for m in 'TEN'):
            raise ValueError('Empty modality')
        if len(inputs['T'])!=qa['counts']['T'] or len(inputs['E'])!=qa['counts']['E'] or len(inputs['N'])!=qa['counts']['N_primary']:
            raise ValueError('Model input counts differ')
        clock=qa['clock_alignment']
        if not clock['raw_timestamps_preserved'] or max(clock['boot_monotonic_uncertainty_seconds'],clock['packet_alignment_max_uncertainty_seconds'])>.005:
            raise ValueError('Clock uncertainty gate failed')
        agent,backend=store.json('agent_artifact.json'),store.json('backend_artifact.json')
        payload=next((p['text'] for p in plan['payloads'] if hashlib.sha256(p['text'].encode()).hexdigest()==backend['provenance']['payload_sha256']),None)
        if payload is None:
            raise ValueError('Payload not in frozen candidate set')
        artifact=dict(agent,**{k:backend[k] for k in ('receipts','pre_state','post_state','state_snapshots','provenance')})
        labels=audit_labels(inputs['T'],artifact,y,report['condition'],attempt_basis='confirmed_payload',payload=payload)
        if not labels['passed']:
            raise ValueError('Independent label reaudit failed: '+repr(labels['errors']))
        expected=1 if report['condition']=='injected' else 0
        if y['y_attempt']!=expected or y['y_harm']!=expected or y['first_harm_time'] is not None:
            raise ValueError('Selection rule or unknown exact harm time violated')
        task=next(t for t in plan['source_tasks'] if t['task_id']==report['native_task_id'])
        if report['source_task_lineage']!=task['lineage'] or report['development_split']!=task['split']:
            raise ValueError('Source lineage partition changed')
        if y['y_harm']==1 and not y['exposed_injection']:
            raise ValueError('Harm positive without actual payload exposure')
        proofs=qa['tool_network_proof']
        if len(proofs)!=qa['counts']['tools'] or any(not (r['agent_E_connect'] and r['backend_E_accept'] and r['agent_business_packets'] and r['backend_verification_packets']) for r in proofs):
            raise ValueError('Cross container tool proof incomplete')
        for modality in 'TEN': counts[modality]+=len(inputs[modality])
        counts['API_requests']+=qa['API_requests']
        counts['tools']+=qa['counts']['tools']
        counts['harm_positive' if expected else 'benign']+=1
        counts['task_success']+=bool(y['task_success'])
        counts['source_bytes']+=storage['source_bytes']
        counts['stored_bytes']+=storage['stored_bytes']
        entry={'session_id':folder.name,'condition':report['condition'],'source_group':task['lineage'],
               'split':task['split'],'y_attempt':y['y_attempt'],'y_harm':y['y_harm'],
               'task_success':y['task_success'],'counts':qa['counts'],'clock':clock,
               'model_returned':sorted({r.get('returned_model') for r in agent['requests'] if r.get('returned_model')}),
               'model_input_sha256':{m:hashlib.sha256((folder/'01_model_inputs'/n).read_bytes()).hexdigest()
                                      for m,n in __import__('session_storage').MODEL_FILES.items()}}
        entries.append(entry)
    if counts['benign']!=summary['retained_benign'] or counts['harm_positive']!=summary['retained_harm_positive']:
        raise ValueError('Aggregate retention counts disagree')
    discarded=summary['completed_no_harm_discarded']+summary['early_aborted_unknown']+summary['unknown_discarded']
    if discarded+counts['harm_positive']!=summary['attack_attempts'] or summary['raw_rejected_files_persisted']!=0:
        raise ValueError('Attempt accounting mismatch')
    if {p.name for p in data.iterdir()}!={'manifest','sessions'}:
        raise ValueError('Unpublished or rejected raw data present in dataset')
    if summary.get('supplement_retained',0):
        amendment=read(data/'manifest/completion_amendment.json')
        if not amendment['original_frozen_plan_preserved'] or amendment['additional_attack_attempts']!=0:
            raise ValueError('Supplement changed attack policy')
        if summary['supplement_retained']>len(amendment['supplement_tasks']):
            raise ValueError('Supplement exceeded frozen normal slots')
    return {'passed':True,'batch_id':data.name,'target_total_met':len(entries)==10,
            'target_balance_met':counts['benign']==5 and counts['harm_positive']==5,
            'counts':dict(counts),'selection':summary,'sessions':entries,'old_data_reused':0,
            'formal_performance':False,'unretained_attempt_reaudit':'Unsupported by explicit user-requested deletion; aggregate counts only',
            'limitations':['Outcome selection precludes natural ASR or prevalence estimates',
                          'All groups are development; preserve lineage if training',
                          'Exact first harm time unknown; replay positives excluded',
                          'Gateway returned name is not independent backend identity proof']}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--data',type=Path,required=True)
    parser.add_argument('--run',type=Path,required=True)
    args=parser.parse_args()
    result=audit(args.data,args.run)
    out=args.run/'audit'
    out.mkdir()
    shutil.copy2(__file__,out/'audit_local_enriched.py')
    (out/'audit.json').write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
    print(json.dumps({'passed':result['passed'],'target_total_met':result['target_total_met'],'counts':result['counts']}))


if __name__=='__main__': main()
