"""Apply the explicitly authorized four-directory compaction to this round only."""
import csv
import json
from pathlib import Path
import shutil
import sys
import uuid

from session_storage import SessionStore,pack_session,rebuild_catalog,write_json,digest,verify_packed

ROOT=Path(__file__).resolve().parents[1]


def main():
    out=ROOT/'experiment'/('storage-layout-change-'+uuid.uuid4().hex[:12])
    out.mkdir()
    shutil.copy2(ROOT/'scripts/session_storage.py',out/'session_storage.py')
    planned=[]
    for name,remote in [('deepseek-collection-integrity','development-integrity'),('deepseek-split-containers','development-split')]:
        base=ROOT/'DataSet'/name
        for category in ('sessions','diagnostics'):
            parent=base/category
            if not parent.exists():
                continue
            source_parent=parent/'sessions' if category=='diagnostics' and (parent/'sessions').exists() else parent
            for folder in sorted(source_parent.iterdir()):
                if not folder.is_dir() or not folder.name.startswith(('native-session-','split-session-')):
                    continue
                destination=(parent/'sessions'/folder.name) if category=='diagnostics' else folder
                planned.append({'source':str(folder),'destination':str(destination),'dataset':name,'category':category,
                    'remote_root':'/root/wxq/agent_benchmark/logbench-la-clean/'+remote,
                    'remote_old':'/root/wxq/agent_benchmark/logbench-la-clean/'+remote+'/'+folder.name,
                    'remote_new':'/root/wxq/agent_benchmark/logbench-la-clean/'+remote+('/diagnostics' if category=='diagnostics' else '')+'/sessions/'+folder.name})
    write_json(out/'plan.json',planned)
    results=[]
    try:
        for row in planned:
            folder=Path(row['source']).resolve()
            if (ROOT/'DataSet').resolve() not in folder.parents:
                raise ValueError('Migration path escaped this project')
            store=SessionStore(folder)
            before=None
            if row['category']=='sessions':
                from development_features import compute
                t,e,n=store.rows('trajectory.jsonl'),store.rows('endpoint.events.jsonl'),store.rows('network.events.jsonl')
                before=compute(t,e,[p for p in n if (p.get('primary_N') and p.get('capture')=='network_api') or ('primary_N' not in p and p['interface']=='eth0')],
                    [p for p in n if (p.get('primary_N') and p.get('capture')=='network_tools') or ('primary_N' not in p and p['interface']=='lo')])
            result=pack_session(folder)
            target=Path(row['destination'])
            if target.resolve()!=folder:
                if target.exists() or (ROOT/'DataSet').resolve() not in target.resolve().parents:
                    raise ValueError('Unsafe or occupied diagnostic destination')
                target.parent.mkdir(parents=True,exist_ok=True)
                folder.rename(target)
            if before is not None:
                from development_features import extract
                if extract(target)!=before:
                    raise ValueError('Model features changed during storage migration')
            results.append(dict(row,**result,feature_equivalence=before is not None))
            print(json.dumps({'session':target.name,'passed':True,'before':result['source_bytes'],'after':result['stored_bytes']}),flush=True)
        catalogs={}
        for name in ('deepseek-collection-integrity','deepseek-split-containers'):
            base=ROOT/'DataSet'/name
            catalogs[name]=rebuild_catalog(base)
            diagnostics=base/'diagnostics'
            if (diagnostics/'sessions').exists():
                (diagnostics/'manifest').mkdir(exist_ok=True)
                frozen=diagnostics/'manifest/frozen.json'
                if not frozen.exists():
                    write_json(frozen,{'scope':'infrastructure_diagnostics_only','eligible_for_model_cohort':False,
                        'source_frozen_sha256':digest((base/'manifest/frozen.json').read_bytes())})
                catalogs[name+'/diagnostics']=rebuild_catalog(diagnostics)
        write_json(out/'report.json',{'passed':True,'sessions':results,'catalogs':catalogs,'model_requests':0,'model_training_runs':0,
            'source_bytes':sum(r['source_bytes'] for r in results),'stored_bytes':sum(r['stored_bytes'] for r in results),
            'all_original_logical_hashes_preserved':True,'model_feature_equivalence_sessions':sum(r['feature_equivalence'] for r in results)})
    except Exception as exc:
        write_json(out/'failure.json',{'error':type(exc).__name__+': '+str(exc),'completed':results})
        raise
    print(json.dumps({'output':str(out),'sessions':len(results),'catalogs':catalogs}),flush=True)


if __name__=='__main__':
    main()
