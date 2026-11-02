"""Small real collection and frozen L2-L6 LateFusion development smoke run."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'DataSet/runtime-detectors'))
from logbench.artifacts import now, read, save, sha, seal, verify


def prepare():
    out = ROOT / 'experiment' / ('architecture-latefusion-smoke-' + uuid.uuid4().hex[:12])
    out.mkdir()
    plan = out / '00_plan'
    plan.mkdir()
    for name in ('architecture-smoke.json', 'collection-integrity.json'):
        shutil.copy2(ROOT / 'configs' / name, plan / name)
    shutil.copy2(ROOT / 'DataSet/deepseek-collection-integrity/manifest/frozen.json', plan / 'collection-frozen.json')
    shutil.copy2(ROOT / '实验架构设计.md', plan / 'architecture.md')
    save(plan / 'identity.json', {'created_utc': now(), 'run_id': out.name, 'eligible_for_formal_results': False})
    seal(plan)
    return out


def collect(out):
    raise RuntimeError('This frozen smoke plan uses retired loopback topology. New collection uses scripts/split_access.ps1; run/verify remain available for retained evidence.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=['prepare', 'collect', 'run', 'verify'])
    parser.add_argument('--run-dir', type=Path)
    args = parser.parse_args()
    if args.phase == 'prepare':
        out = prepare()
    else:
        if args.run_dir is None:
            parser.error('--run-dir is required')
        out = args.run_dir.resolve()
        if out.parent != ROOT / 'experiment' or not out.name.startswith('architecture-latefusion-smoke-'):
            raise ValueError('Run must be inside this project experiment directory')
        if args.phase == 'collect':
            collect(out)
        elif args.phase == 'run':
            from logbench.pipeline import run
            run(out)
        else:
            from logbench.release import verify_run
            print(json.dumps(verify_run(out)), flush=True)
    print(json.dumps({'phase': args.phase, 'output': str(out)}), flush=True)


if __name__ == '__main__':
    main()
