"""Run inside the trusted local coordinator; prove real WSL/Docker eBPF first."""
import gzip
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

OUT = Path('/output')


def run(args, check=True):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
    if check and p.returncode:
        raise RuntimeError(p.stderr[-2000:])
    return p


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    identity = 'logbench-local-gate-' + uuid.uuid4().hex[:12]
    report = {'passed':False, 'kernel':os.uname().release, 'model_requests':0,
        'scope':'infrastructure diagnostic, never a model sample', 'sensors':[]}
    target = run(['docker','run','--rm','-d','--name',identity+'-target','--network','none','--cap-drop','ALL',
        '--security-opt','no-new-privileges','--read-only','--tmpfs','/tmp:rw,nosuid,noexec,size=32m',
        'logbench-native-dev:82f7911781dc78ba','python','-c','import time; time.sleep(180)']).stdout.strip()
    sensor = None
    try:
        pid = int(run(['docker','inspect',target,'--format','{{.State.Pid}}']).stdout)
        mnt = os.stat('/proc/{}/ns/mnt'.format(pid)).st_ino
        image = sys.argv[1] if len(sys.argv)>1 else 'aquasec/tracee:0.19.0'
        report['tracee_image']=image
        http_args = ['--server','http-address=:3366','--server','healthz','--server','metrics'] if ':0.24.' in image else ['--http-listen-addr',':3366','--healthz','--metrics']
        p = run(['docker','run','-d','--name',identity+'-sensor','--privileged','--pid','host','--cgroupns','host',
            '--network','none','-e','LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host',
            '-v','/etc/os-release:/etc/os-release-host:ro','-v','/var/run:/var/run:ro','-v','/boot:/boot:ro',
            '-v','/sys/fs/cgroup:/sys/fs/cgroup:ro','--entrypoint','/tracee/tracee',image,
            '--scope','mntns='+str(mnt),'--events','openat,read,write,close,socket,connect,accept,accept4',
            '--output','json']+http_args)
        sensor = p.stdout.strip()
        sensor_pid = int(run(['docker','inspect',sensor,'--format','{{.State.Pid}}']).stdout)
        ready = False
        for _ in range(50):
            p = run(['nsenter','-t',str(sensor_pid),'-n','curl','-fsS','--max-time','1','http://127.0.0.1:3366/healthz'],False)
            if p.returncode == 0:
                ready = True
                break
            if run(['docker','inspect',sensor,'--format','{{.State.Running}}'],False).stdout.strip() != 'true':
                break
            time.sleep(.3)
        if not ready:
            raise RuntimeError('Local Tracee did not become healthy')
        before = run(['nsenter','-t',str(sensor_pid),'-n','curl','-fsS','http://127.0.0.1:3366/metrics']).stdout
        script = "import pathlib,socket,threading; p=pathlib.Path('/tmp/sensor-probe'); p.write_text('probe'); p.read_text(); s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(); t=threading.Thread(target=lambda:s.accept()[0].close()); t.start(); c=socket.create_connection(s.getsockname()); c.close(); t.join(); s.close()"
        run(['docker','exec',target,'python','-c',script])
        time.sleep(1)
        after = run(['nsenter','-t',str(sensor_pid),'-n','curl','-fsS','http://127.0.0.1:3366/metrics']).stdout
        run(['docker','stop','-t','10',sensor],False)
        logs = run(['docker','logs',sensor],False)
        events = [json.loads(line) for line in logs.stdout.splitlines() if line.startswith('{')]
        from validate_sensor_contract import loss_values
        b,a=loss_values(before),loss_values(after)
        losses={k:a[k]-b[k] for k in b.keys() & a.keys()}
        names={e['eventName'] for e in events}
        report.update(events=len(events),event_names=sorted(names),losses=losses,
            correct_namespace=all(e['mountNamespace']==mnt for e in events))
        report['passed']=bool(events and report['correct_namespace'] and {'openat','read','write','connect'} <= names and
            names.intersection({'accept','accept4'}) and b and b.keys()==a.keys() and all(v==0 for v in losses.values()))
        with gzip.open(str(OUT/'endpoint.raw.jsonl.gz'),'wb') as stream:
            stream.write(logs.stdout.encode())
        (OUT/'metrics-before.txt').write_text(before)
        (OUT/'metrics-after.txt').write_text(after)
        (OUT/'tracee.log').write_text(logs.stderr)
    except Exception as exc:
        report['error']=type(exc).__name__+': '+str(exc)
        if sensor:
            logs=run(['docker','logs',sensor],False)
            (OUT/'tracee-failure.log').write_text(logs.stdout+'\n'+logs.stderr)
            report['sensor_error_excerpt']=logs.stderr[-2500:]
    finally:
        for cid in (sensor,target):
            if cid:
                run(['docker','rm','-f',cid],False)
        (OUT/'report.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report),flush=True)
    if not report['passed']:
        raise SystemExit(1)


if __name__=='__main__':
    main()
