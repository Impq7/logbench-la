"""Run the minimal architecture in order; never overwrite a completed stage."""
import time
import traceback
import uuid
import shutil
from .artifacts import ROOT, now, save, seal
from . import cohort, represent, fusion, evaluate, release


def run(out):
    timings = []
    try:
        snapshot = out / 'run_sources'
        snapshot.mkdir()
        for path in list((ROOT / 'logbench').glob('*.py')) + list((ROOT / 'scripts').glob('*.py')):
            target = snapshot / path.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
        seal(snapshot)
        samples = None
        for name, action in [('cohort', lambda: cohort.build(out)),
                             ('represent', lambda: represent.materialize(out, samples)),
                             ('fit', lambda: fusion.fit(out, samples)),
                             ('score', lambda: fusion.score(out, samples)),
                             ('evaluate', lambda: evaluate.evaluate(out, samples)),
                             ('release', lambda: release.release(out))]:
            started = time.perf_counter()
            print('Starting ' + name, flush=True)
            result = action()
            if name == 'cohort':
                samples = result
            timings.append({'stage': name, 'seconds': time.perf_counter() - started})
            print('Completed ' + name, flush=True)
        save(out / 'pipeline.json', {'passed': True, 'created_utc': now(), 'stages': timings})
    except Exception as exc:
        save(out / ('failure-' + uuid.uuid4().hex[:12] + '.json'), {'passed': False, 'created_utc': now(),
            'stages': timings, 'error': type(exc).__name__ + ': ' + str(exc), 'traceback': traceback.format_exc()})
        raise
