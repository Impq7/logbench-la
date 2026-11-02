"""Freeze a complete official cohort, then publish only validated individual runs."""
import argparse
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_enrich():
    spec = importlib.util.spec_from_file_location('official_enrich', ROOT/'logbench/agentdojo_asb/enrich.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def frozen_plan(path):
    plan = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    samples = plan['samples']
    if not samples or type(plan['seed']) is not int or len(samples) != plan['total']:
        raise ValueError('Incomplete batch plan')
    runs = []
    for row in samples:
        if row['attack'] not in ('none','asb_concat','asb_context_ignore','asb_fake_completion','asb_escape'):
            raise ValueError('Unknown attack')
        if not row['user_task'] or (row['attack'] != 'none' and not row['injection_task']):
            raise ValueError('Missing task selection')
        run = (ROOT/'experiment'/row['run_dir']).resolve()
        if run.parent != ROOT/'experiment' or not run.name.startswith('agentdojo-official-'):
            raise ValueError('Run path outside official experiment directory')
        runs.append(str(run))
    if len(set(runs)) != len(runs):
        raise ValueError('Duplicate run slots')
    source_paths = ['scripts/agentdojo_official_run.py','scripts/agentdojo_official_ten_coordinator.py',
        'scripts/agentdojo_official_ten.py','scripts/validate_official_session.py',
        'scripts/agentdojo_to_atif.py','scripts/session_storage.py','scripts/packet_metadata.py',
        'scripts/exfil_receiver.py','scripts/dns_server.py','logbench/agentdojo_asb/attacks.py',
        'logbench/agentdojo_asb/exfil.py','logbench/agentdojo_asb/enrich.py','scripts/pack_official_batch.py',
        'scripts/clock_alignment.py','scripts/collect_official_slack_80.ps1']
    return {'revision':'official-single-task-r2','plan':plan,'run_dirs':runs,
            'image_ids':{name:subprocess.check_output(['docker','image','inspect',name,'--format','{{.Id}}'],text=True).strip()
                for name in ('logbench-official-agent:r1','logbench-native-dev:82f7911781dc78ba',
                             'logbench-local-coordinator:r1','aquasec/tracee:0.24.1')},
            'source_hashes':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in source_paths}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_dirs', nargs='*',type=Path)
    parser.add_argument('--plan',required=True,type=Path)
    parser.add_argument('--batch-id',required=True)
    parser.add_argument('--freeze-only',action='store_true')
    args = parser.parse_args(argv)
    if Path(args.batch_id).name != args.batch_id or args.batch_id in ('.','..'):
        raise ValueError('Batch ID must be a basename')
    frozen = frozen_plan(args.plan)
    scenario = frozen['plan']['scenario'].lower()
    if scenario not in ('slack','banking','travel','workspace'):
        raise ValueError('Unknown suite')
    dataset = ROOT/'DataSet'/args.batch_id/scenario
    enrich = _load_enrich()
    enrich.write_frozen(dataset,frozen)
    if args.freeze_only:
        return 0
    if not args.run_dirs:
        raise ValueError('No run specified')
    for run in args.run_dirs:
        run = run.resolve()
        index = frozen['run_dirs'].index(str(run))
        expected = frozen['plan']['samples'][index]
        meta = enrich.build_meta(run,args.batch_id,scenario)
        report = json.loads((run/'report.json').read_text(encoding='utf-8'))
        if any(report.get('image_ids',{}).get(name) != digest for name,digest in frozen['image_ids'].items()
               if name != 'logbench-local-coordinator:r1'):
            raise ValueError('Runtime images differ from frozen cohort')
        if meta['user_tasks'] != [expected['user_task']] or meta['attack'] != expected['attack']:
            raise ValueError('Collected run differs from frozen slot')
        if expected['attack'] != 'none' and meta['injection_tasks'] != [expected['injection_task']]:
            raise ValueError('Injection task differs from frozen slot')
        for field in ('model_id','reasoning_effort'):
            if field in frozen['plan'] and meta.get(field) != frozen['plan'][field]:
                raise ValueError('Model settings differ from frozen plan: ' + field)
        result = enrich.pack_into_dataset(run,dataset,meta)
        print(json.dumps({'published':result['session_id'],'dataset':str(dataset)}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
