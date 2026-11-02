"""Read-only Linux probe, Python 3.6 compatible. Never reads old experiments."""
import datetime
import json
import os
import platform
import shutil
import subprocess


def run(args):
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=12)
        return {'argv': args, 'returncode': p.returncode,
                'stdout': p.stdout[:20000], 'stderr': p.stderr[:4000]}
    except Exception as exc:
        return {'argv': args, 'error': type(exc).__name__ + ': ' + str(exc)}


tools = ['docker', 'tcpdump', 'strace', 'tracee', 'auditctl', 'nsenter', 'ip', 'git', 'curl']
result = {'timestamp_utc': datetime.datetime.utcnow().isoformat() + 'Z',
          'uid': os.getuid(), 'kernel': platform.release(), 'machine': platform.machine(),
          'python': platform.python_version(),
          'btf_vmlinux_exists': os.path.isfile('/sys/kernel/btf/vmlinux'),
          'bpf_fs_exists': os.path.isdir('/sys/fs/bpf'),
          'executables': {name: shutil.which(name) for name in tools},
          'checks': []}
commands = [
    ['cat', '/etc/os-release'],
    ['docker', 'version', '--format', '{{json .}}'],
    ['docker', 'info', '--format', '{{json .}}'],
    ['docker', 'image', 'ls', '--digests', '--format', '{{json .}}'],
    ['tcpdump', '--version'], ['strace', '-V'],
    ['df', '-h', '/root/wxq'],
    ['free', '-m'],
]
for command in commands:
    result['checks'].append(run(command))
print(json.dumps(result, ensure_ascii=False))
