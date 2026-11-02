"""Actual pilot data through the baseline's observable projections, without fitting."""
import argparse
import collections
import hashlib
import importlib.metadata
import json
from pathlib import Path
import shutil
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from session_storage import load_model_inputs
from logbench.represent import project_t,project_e,project_n,features


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--data',type=Path,required=True)
    parser.add_argument('--run',type=Path,required=True)
    args=parser.parse_args()
    audit=json.loads((args.run/'audit/audit.json').read_text(encoding='utf-8'))
    if not audit['passed'] or audit['batch_id']!=args.data.name or not audit['target_total_met']:
        raise ValueError('Independent whole-pilot audit and ten retained samples required')
    cfg=json.loads((Path(__file__).resolve().parents[1]/'configs/architecture-smoke.json').read_text(encoding='utf-8'))
    support={split:collections.Counter() for split in ('train','validation','test')}
    counts=[]
    for sample in audit['sessions']:
        folder=args.data/'sessions'/sample['session_id']
        values=load_model_inputs(folder)
        first,last=values['T'][0]['relative_timestamp'],values['T'][-1]['relative_timestamp']
        streams={'T':[project_t(r) for r in values['T']],
                 'E':[project_e(r) for r in values['E'] if r['observation_role']=='task' and first<=r['relative_timestamp']<=last],
                 'N':[project_n(r) for r in values['N'] if first<=r['relative_timestamp']<=last]}
        if any(not stream for stream in streams.values()):
            raise ValueError('Empty task-window modality after baseline projection')
        record={'session_id':sample['session_id'],'source_group':sample['source_group'],'split':sample['split'],
                'events':{m:len(v) for m,v in streams.items()},'feature_windows':{}}
        for m,stream in streams.items():
            stream.sort(key=lambda r:r['arrival'])
            for level in cfg['levels']:
                windows=features(stream,m,level,cfg)
                if not windows:
                    raise ValueError('Baseline representation empty')
                record['feature_windows'][str(level)+m]=len(windows)
        support[sample['split']][str(sample['y_attempt'])]+=1
        counts.append(record)
    missing=[split for split,counts_by_class in support.items() if set(counts_by_class)!={'0','1'}]
    result={'passed':True,'stage':'LateFusion observable DataLoader/projection/representation smoke',
            'actual_data_only':True,'dataset':args.data.name,'old_data_reused':0,
            'supports':{k:dict(v) for k,v in support.items()},'sessions':counts,
            'supervised_LateFusion_eligible':not missing,'missing_attempt_classes_splits':missing,
            'training_executed':False,'test_predictions_or_metrics_generated':False,
            'training_gate_reason':'Both classes are required for supervised branch fitting and validation calibration' if missing else 'Class-support gate passed; fitting is separate',
            'environment':{'executable':sys.executable,'prefix':sys.prefix,
                           'packages':{n:importlib.metadata.version(n) for n in ('numpy','scipy','scikit-learn','joblib','threadpoolctl')}}}
    out=args.run/'model-input-check'
    out.mkdir()
    shutil.copy2(__file__,out/'check_local_model_inputs.py')
    for path in ('logbench/represent.py','logbench/fusion.py','configs/architecture-smoke.json'):
        source=Path(__file__).resolve().parents[1]/path
        target=out/'sources'/path
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(source,target)
    (out/'report.json').write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('sessions','environment')}))


if __name__=='__main__':main()
