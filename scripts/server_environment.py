"""Host stdlib Docker orchestration; dependencies live only in the project venv."""
import json
import os
from pathlib import Path
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]
BASE = Path('/root/wxq/agent_benchmark/logbench-la-clean')
VENV = ROOT / '.venv'
ENVIRONMENT = ROOT / 'runtime/environment.json'


def docker_args(image, writable_data=False, install=False):
    args = ['docker', 'run', '--rm', '--pull', 'never', '--name', 'logbench-pipeline-' + uuid.uuid4().hex[:12],
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--network', 'bridge' if install else 'none',
        '-e', 'PYTHONDONTWRITEBYTECODE=1', '-e', 'PIP_CACHE_DIR=' + str(ROOT / '.cache/pip'),
        '-e', 'TMPDIR=' + str(ROOT / 'runtime/tmp'), '-v', str(ROOT) + ':' + str(ROOT) + (':rw' if install else ':ro')]
    if not install:
        for name in ('experiment', 'runtime'):
            args += ['-v', str(ROOT / name) + ':' + str(ROOT / name) + ':rw']
        args += ['-v', str(ROOT / 'DataSet') + ':' + str(ROOT / 'DataSet') + (':rw' if writable_data else ':ro')]
        # Existing data stays at its original server location; no raw data copies.
        for link in (ROOT / 'DataSet').iterdir():
            if link.is_symlink():
                data = link.resolve()
                if data.parent != BASE or not data.name.startswith('development-split50-'):
                    raise ValueError('Dataset link escaped current project')
                args += ['-v', str(data) + ':' + str(data) + (':rw' if writable_data else ':ro')]
    return args + ['-w', str(ROOT), image]


def setup():
    ROOT.joinpath('runtime/tmp').mkdir(parents=True, exist_ok=True)
    ROOT.joinpath('.cache/pip').mkdir(parents=True, exist_ok=True)
    if ENVIRONMENT.exists():
        return json.loads(ENVIRONMENT.read_text())
    image = subprocess.check_output(['docker', 'image', 'inspect', 'python:3.11-slim-bookworm', '--format', '{{.Id}}']).decode().strip()
    script = """import sys,subprocess,pathlib,json,platform,importlib.metadata
root=pathlib.Path.cwd(); venv=root/'.venv'
if not (venv/'pyvenv.cfg').exists(): subprocess.check_call([sys.executable,'-m','venv',str(venv)])
subprocess.check_call([str(venv/'bin/python'),'-m','pip','install','--disable-pip-version-check','--only-binary=:all:','-r',str(root/'scripts/requirements-server.txt')])
code='import sys,json,importlib.metadata; print(json.dumps(dict(python=sys.version,prefix=sys.prefix,base_prefix=sys.base_prefix,executable=sys.executable,versions={n:importlib.metadata.version(n) for n in ["numpy","scipy","scikit-learn","joblib","threadpoolctl"]})))'
env=json.loads(subprocess.check_output([str(venv/'bin/python'),'-c',code]))
assert env['prefix']!=env['base_prefix']
assert 'include-system-site-packages = false' in (venv/'pyvenv.cfg').read_text()
env.update(image_id=IMAGE,platform=platform.platform(),base_environment_modified=False,scope='project-private Docker + venv',no_result_download=True)
with (root/'runtime/environment.json').open('x') as stream: json.dump(env,stream,indent=2)
""".replace('IMAGE', repr(image))
    args = docker_args(image, install=True) + ['python', '-c', script]
    log = ROOT / 'runtime/environment-setup.log'
    with log.open('a') as stream:
        subprocess.check_call(args, stdout=stream, stderr=subprocess.STDOUT)
    return json.loads(ENVIRONMENT.read_text())


def stage(phase, out=None, folder=None):
    env = json.loads(ENVIRONMENT.read_text())
    args = docker_args(env['image_id'], writable_data=phase == 'validate')
    args += [str(VENV / 'bin/python'), 'scripts/server_pipeline_stage.py', phase]
    if out:
        args += ['--run-dir', str(out)]
    if folder:
        args += ['--folder', str(folder)]
    subprocess.check_call(args)
