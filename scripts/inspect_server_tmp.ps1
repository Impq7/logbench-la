param()
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot -Parent
$credentialRoot = 'D:/download/workbuddy/2026-10-07-17-18-52/llm-supply-chain-security/DataSet'
$taskPointer = [IntPtr]::Zero
$taskCode = @'
import datetime, hashlib, json, os, sys, uuid
from pathlib import Path
sys.path.insert(0, os.environ.pop('LOGBENCH_SSH_LIBRARY'))
import paramiko
probe = r'''
import datetime, hashlib, json, os, re, stat, subprocess
from pathlib import Path
def stamp(value):
    return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).isoformat()
root = Path('/root')
files = []
for path in sorted(root.iterdir()):
    if not (path.name.endswith('.tmp') or path.name in ('.python_history', '.bash_history')):
        continue
    info = path.lstat()
    item = {'path': str(path), 'size': info.st_size, 'uid': info.st_uid,
        'mode': oct(stat.S_IMODE(info.st_mode)), 'mtime_utc': stamp(info.st_mtime),
        'ctime_utc': stamp(info.st_ctime), 'regular_file': stat.S_ISREG(info.st_mode)}
    if item['regular_file']:
        content = path.read_bytes()
        item.update(sha256=hashlib.sha256(content).hexdigest(), line_count=len(content.splitlines()),
            empty=not content)
        # Report only safe structural indicators, never history text or secrets.
        if path.name.startswith('.python_history'):
            item['project_path_mentions'] = content.count(b'/root/wxq/agent_benchmark/logbench-la-clean')
            item['looks_like_json_records'] = content.lstrip().startswith(b'{')
    files.append(item)
processes = []
for entry in Path('/proc').iterdir():
    if not entry.name.isdigit():
        continue
    try:
        comm = (entry / 'comm').read_text().strip()
        if not any(term in comm.lower() for term in ('python', 'bash', 'zsh', 'ipython')):
            continue
        processes.append({'pid': int(entry.name), 'comm': comm,
            'exe': os.readlink(str(entry / 'exe')), 'cwd': os.readlink(str(entry / 'cwd'))})
    except (OSError, IOError):
        pass
sources = []
for name in ('/etc/profile', '/etc/bash.bashrc', '/root/.bashrc', '/root/.profile'):
    path = Path(name)
    if not path.is_file():
        continue
    data = path.read_bytes()
    lines = data.decode('utf-8', 'replace').splitlines()
    hits = [{'line': i+1, 'terms': [term for term in ('python_history', 'PYTHONSTARTUP', 'PYTHONINSPECT', 'readline', 'python', 'conda', 'PROMPT_COMMAND') if term in line]}
            for i, line in enumerate(lines) if any(term in line for term in ('python_history','PYTHONSTARTUP','PYTHONINSPECT','readline','python','conda','PROMPT_COMMAND'))]
    sources.append({'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'matching_line_terms': hits})
print(json.dumps({'kind': 'root_tmp_read_only_metadata_audit', 'utc': stamp(datetime.datetime.now().timestamp()),
    'files': files, 'processes': processes, 'shell_startup_metadata': sources,
    'mutations': 0, 'history_contents_exported': False}))
'''
client = paramiko.SSHClient()
client.load_host_keys(os.environ.pop('LOGBENCH_SSH_KNOWN_HOSTS'))
client.set_missing_host_key_policy(paramiko.RejectPolicy())
try:
    client.connect('10.22.81.253', port=60011, username='root', password=os.environ.pop('LOGBENCH_SSH_PASSWORD'),
        look_for_keys=False, allow_agent=False, timeout=15, banner_timeout=15, auth_timeout=15)
    # Non-interactive stdin script: no Python REPL or history hook.
    stdin, stdout, stderr = client.exec_command('python3 -', timeout=60)
    stdin.write(probe)
    stdin.flush()
    stdin.channel.shutdown_write()
    output = stdout.read().decode('utf-8', 'replace')
    error = stderr.read().decode('utf-8', 'replace')
    code = stdout.channel.recv_exit_status()
    if code:
        raise RuntimeError('Read-only probe failed: ' + error[:500])
    result = json.loads(output)
    root = Path(os.environ.pop('LOGBENCH_PROJECT_ROOT'))
    out = root / 'experiment' / ('server-root-tmp-audit-' + uuid.uuid4().hex[:12])
    out.mkdir()
    result['remote_probe_sha256'] = hashlib.sha256(probe.encode()).hexdigest()
    (out / 'metadata.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    (out / 'probe.py').write_text(probe, encoding='utf-8')
    print(json.dumps({'output': str(out), 'result': result}, ensure_ascii=False, indent=2))
finally:
    client.close()
'@
try {
    $taskSecure = ConvertTo-SecureString ((Get-Content -LiteralPath "$credentialRoot/.private/server253.dpapi" -Raw).Trim())
    $taskPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($taskSecure)
    $env:LOGBENCH_SSH_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($taskPointer)
    $env:LOGBENCH_SSH_KNOWN_HOSTS = "$credentialRoot/.private/server253_known_hosts"
    $env:LOGBENCH_SSH_LIBRARY = "$credentialRoot/runtime"
    $env:LOGBENCH_PROJECT_ROOT = $taskRoot
    $taskCode | & 'C:/Users/WXQ/.workbuddy/binaries/python/envs/default/Scripts/python.exe' -X utf8 -
    $taskExit = $LASTEXITCODE
} finally {
    if ($taskPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($taskPointer) }
    Remove-Item Env:LOGBENCH_SSH_PASSWORD,Env:LOGBENCH_SSH_KNOWN_HOSTS,Env:LOGBENCH_SSH_LIBRARY,Env:LOGBENCH_PROJECT_ROOT -ErrorAction SilentlyContinue
}
exit $taskExit
