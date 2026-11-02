"""Real eBPF + PCAP diagnostic in a fresh, offline container. Not benchmark data."""
import collections
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import struct
import subprocess
import threading
import time
import uuid

run_id = 'sensor-contract-' + uuid.uuid4().hex[:12]
gateway_config = globals().get('gateway_config')
native = bool(gateway_config and gateway_config.get('native_profile'))
if gateway_config:
    run_id = 'gateway-contract-' + uuid.uuid4().hex[:12]
    gateway_config['session_id'] = run_id
if native:
    run_id = 'native-session-' + uuid.uuid4().hex[:12]
    gateway_config['session_id'] = run_id
root = Path('/root/wxq/agent_benchmark/logbench-la-clean')
out = root / ('development-integrity' if native else 'diagnostics') / run_id
out.mkdir(parents=True, exist_ok=False)
report = {'run_id': run_id, 'output_dir': str(out), 'kind': 'infrastructure_diagnostic',
          'eligible_for_training': False, 'timestamp_utc': datetime.datetime.utcnow().isoformat() + 'Z',
          'checks': [], 'ready': False}
if gateway_config:
    report['gateway_key_name'] = gateway_config.get('key_name')
    report['gateway_base_url'] = gateway_config.get('gateway_base_url')
    report['model_requested'] = gateway_config.get('model_requested')
    report['api_transport'] = gateway_config.get('api_transport')
    report['phase'] = gateway_config.get('phase', 'development-only')
    report['max_output_tokens'] = gateway_config.get('max_output_tokens')
    report['condition'] = gateway_config.get('condition')
if native:
    report.update(kind='adapted_development_task', native_task_id=gateway_config['native_task_id'],
        source_task_lineage=gateway_config['source_task_lineage'], development_split=gateway_config['development_split'],
        development_revision=gateway_config['development_revision'], annotation_revision=gateway_config['annotation_revision'],
        eligible_for_formal_results=False, collection_revision=gateway_config['collection_revision'])
containers = []
capture = None
capture_log = None
tool_capture = None
tool_capture_log = None
arrival_stop = threading.Event()
arrival_threads = []
endpoint_follower = None
sensor = sensor_pid = None
clock_stop = threading.Event()
clock_thread = None


def clock_sample():
    before = time.monotonic()
    wall = time.time()
    after = time.monotonic()
    return {'timestamp': wall, 'monotonic': (before + after) / 2,
            'sampling_uncertainty_seconds': (after - before) / 2}


def record_clocks():
    with (out / 'clock_sync.jsonl').open('w') as stream:
        while True:
            stream.write(json.dumps(clock_sample()) + '\n')
            stream.flush()
            if clock_stop.wait(0.25):
                stream.write(json.dumps(clock_sample()) + '\n')
                break


def record_endpoint_arrivals(process):
    with (out / 'endpoint_live.jsonl').open('wb') as raw, (out / 'arrival_endpoint.jsonl').open('w') as index:
        for number, line in enumerate(iter(process.stdout.readline, b'')):
            arrived = time.time()
            raw.write(line)
            index.write(json.dumps({'record_index': number, 'arrival_time': arrived,
                'arrival_monotonic': time.monotonic(), 'session_id': run_id,
                'sha256': hashlib.sha256(line).hexdigest()}) + '\n')
            raw.flush()
            index.flush()


def record_packet_arrivals(name):
    path = out / (name + '.pcap')
    with (out / ('arrival_' + name + '.jsonl')).open('w') as index:
        while not path.exists():
            if arrival_stop.wait(0.01):
                return
        with path.open('rb') as stream:
            header = b''
            while len(header) < 24:
                header += stream.read(24 - len(header))
                if len(header) < 24 and arrival_stop.wait(0.01):
                    return
            endian = '<' if header[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
            resolution = 1e9 if header[:4] in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d') else 1e6
            number = 0
            while True:
                offset = stream.tell()
                packet_header = stream.read(16)
                if len(packet_header) < 16:
                    stream.seek(offset)
                    if arrival_stop.wait(0.01):
                        return
                    continue
                seconds, fraction, captured, original = struct.unpack(endian + 'IIII', packet_header)
                packet = stream.read(captured)
                if len(packet) != captured:
                    stream.seek(offset)
                    if arrival_stop.wait(0.01):
                        return
                    continue
                index.write(json.dumps({'record_index': number, 'offset': offset, 'arrival_time': time.time(),
                    'arrival_monotonic': time.monotonic(), 'session_id': run_id,
                    'timestamp': seconds + fraction / resolution,
                    'sha256': hashlib.sha256(packet_header + packet).hexdigest()}) + '\n')
                number += 1
                index.flush()


def run_native_worker(target):
    """Continuously retain the visible prefix, even if the worker or API fails."""
    artifact = None
    with (out / 'worker.stderr.log').open('w') as errors, (out / 'trajectory.jsonl').open('w') as trace, \
            (out / 'requests.jsonl').open('w') as requests, (out / 'lifecycle.jsonl').open('w') as lifecycle:
        process = subprocess.Popen(['docker', 'exec', '-i', target, 'python', '-u', '/probe.py'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors, universal_newlines=True)
        def expire():
            report['worker_timed_out'] = True
            process.kill()
        watchdog = threading.Timer(780, expire)
        watchdog.daemon = True
        watchdog.start()
        try:
            process.stdin.write(json.dumps(gateway_config) + '\n')
            process.stdin.close()
            gateway_config.pop('api_key', None)
            for line in process.stdout:
                frame = json.loads(line)
                kind, row = frame['kind'], frame['record']
                if kind in ('trajectory', 'request_start', 'request_end', 'lifecycle'):
                    row.update(arrival_timestamp=time.time(), arrival_monotonic=time.monotonic())
                    row['arrival_time'] = row['arrival_timestamp']
                    if kind == 'trajectory':
                        destination = trace
                    elif kind == 'lifecycle':
                        destination = lifecycle
                    else:
                        row['record_type'] = kind
                        destination = requests
                    destination.write(json.dumps(row, ensure_ascii=False) + '\n')
                    destination.flush()
                elif kind == 'tool_schemas':
                    (out / 'tool_schemas.json').write_text(json.dumps(row, indent=2))
                elif kind == 'artifact':
                    if artifact is not None:
                        raise ValueError('Duplicate final worker artifact')
                    artifact = row
                else:
                    raise ValueError('Unknown worker stream record')
            report['worker_exit_code'] = process.wait()
        finally:
            watchdog.cancel()
            if process.poll() is None:
                process.kill()
                process.wait()
    if artifact is None or report['worker_exit_code']:
        raise RuntimeError('Worker did not finish; streamed prefix retained')
    (out / 'labels.json').write_text(json.dumps(artifact.pop('evaluation'), indent=2))
    (out / 'gateway_artifact.json').write_text(json.dumps(artifact, indent=2))
    report['gateway'] = {k: artifact[k] for k in ('termination', 'error', 'requests')}


def finish_capture():
    """Drain all sensors on success and failure; never discard a failed run's prefix."""
    for process, name in ((capture, 'network'), (tool_capture, 'network_tools')):
        if process is not None:
            report[name + '_alive_before_stop'] = process.poll() is None
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
            process.wait(timeout=10)
            report[name + '_exit_code'] = process.returncode
    report['capture_ended_at'] = time.time()
    if sensor_pid is not None:
        code, metrics = endpoint(sensor_pid, 'metrics')
        (out / 'tracee_metrics_after.txt').write_text(metrics)
        report['metrics_after_ok'] = code == 0
    if sensor is not None:
        run(['docker', 'stop', '-t', '10', sensor], required=False)
        if endpoint_follower is not None:
            endpoint_follower.wait(timeout=10)
        p = subprocess.run(['docker', 'logs', sensor], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (out / 'endpoint.jsonl').write_bytes(p.stdout)
        (out / 'tracee.log').write_bytes(p.stderr)
    arrival_stop.set()
    for thread in arrival_threads:
        thread.join(timeout=10)
    if native and (out / 'endpoint.jsonl').exists():
        report['endpoint_live_matches_final'] = (out / 'endpoint_live.jsonl').read_bytes() == (out / 'endpoint.jsonl').read_bytes()
    clock_stop.set()
    if clock_thread is not None:
        clock_thread.join(timeout=2)
    report['sensors_drained'] = True


def run(args, timeout=30, required=True):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True, timeout=timeout)
    report['checks'].append({'argv': args, 'returncode': p.returncode,
                            'stdout': p.stdout, 'stderr': p.stderr})
    if required and p.returncode:
        raise RuntimeError('Command failed: ' + ' '.join(args[:4]))
    return p.stdout.strip()


def endpoint(pid, path):
    p = subprocess.run(['nsenter', '-t', str(pid), '-n', 'curl', '-fsS', '--max-time', '2',
                        'http://127.0.0.1:3366/' + path], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, universal_newlines=True)
    return p.returncode, p.stdout


worker = '''import http.server,json,pathlib,socket,subprocess,threading,time,urllib.request
events=[]
def mark(kind,**kw):
    events.append(dict(kind=kind,timestamp=time.time(),monotonic=time.monotonic(),**kw))
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body=self.rfile.read(int(self.headers['Content-Length']))
        mark('service_received',body=body.decode(),peer=self.client_address)
        self.send_response(200);self.end_headers();self.wfile.write(b'accepted')
    def log_message(self,*args): pass
server=http.server.HTTPServer(('127.0.0.1',0),Handler)
threading.Thread(target=server.serve_forever,daemon=True).start()
mark('start')
p=pathlib.Path('/tmp/logbench-sensor-contract.txt')
p.write_text('17 25')
mark('file_write',path=str(p))
data=p.read_text()
mark('file_read',path=str(p),value=data)
child=subprocess.run(['/bin/echo','logbench-child'],capture_output=True,text=True)
mark('child_exit',returncode=child.returncode)
value=sum(map(int,data.split()))
url='http://127.0.0.1:%d/result'%server.server_port
request=urllib.request.Request(url,data=json.dumps({'sum':value}).encode(),method='POST')
with urllib.request.urlopen(request,timeout=5) as response:
    mark('http_result',status=response.status,result=response.read().decode(),port=server.server_port)
p.unlink()
mark('file_delete',path=str(p))
server.shutdown()
mark('end')
print(json.dumps(events))
'''
worker = globals().get('worker_source', worker)
(out / 'worker.py').write_text(worker)
try:
    target_image = gateway_config['runtime_image'] if native else 'python:3.11-slim-bookworm'
    for img in ['aquasec/tracee:0.19.0', target_image]:
        run(['docker', 'image', 'inspect', img, '--format', '{{.Id}} {{json .RepoDigests}}'])
    target = run(['docker', 'run', '--pull', 'never', '-d', '--name', run_id,
                  '--network', 'bridge' if gateway_config else 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                  '--memory', '768m' if native else '256m', '--pids-limit', '64',
                  '-v', str(out / 'worker.py') + ':/probe.py:ro',
                  target_image, 'python', '-c', 'import time; time.sleep(900)' if native else 'import time; time.sleep(300)'])
    containers.append(target)
    target_pid = int(run(['docker', 'inspect', target, '--format', '{{.State.Pid}}']))
    report.update(target_container_id=target, target_host_pid=target_pid)
    if gateway_config:
        # Long TLS requests were repeatedly unacknowledged at the default bridge MTU.
        # Change only this new container's network namespace, never the host network.
        run(['nsenter', '-t', str(target_pid), '-n', 'ip', 'link', 'set', 'dev', 'eth0', 'mtu', '1280'])
        report['container_network_mtu'] = 1280
        report['container_network_link'] = run(['nsenter', '-t', str(target_pid), '-n', 'ip', '-j', 'link', 'show', 'dev', 'eth0'])
    mount_namespace = os.stat('/proc/{}/ns/mnt'.format(target_pid)).st_ino
    report['target_mount_namespace'] = mount_namespace
    events = 'sched_process_fork,sched_process_exec,sched_process_exit,openat,read,write,close,unlink,unlinkat,socket,connect,accept,accept4,bind,listen'
    if native:
        events += ',security_file_open,dup,dup2,dup3,fcntl,rename,renameat,renameat2,getsockname,getpeername,sendto,recvfrom,sendmsg,recvmsg,shutdown'
    report['endpoint_events_requested'] = events.split(',')
    sensor = run(['docker', 'run', '--pull', 'never', '-d', '--name', run_id + '-tracee',
                  '--pid', 'host', '--cgroupns', 'host', '--privileged', '--network', 'none',
                  '--entrypoint', '/tracee/tracee', '-e', 'LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host',
                  '-v', '/etc/os-release:/etc/os-release-host:ro',
                  '-v', '/var/run:/var/run:ro', '-v', '/boot:/boot:ro',
                  '-v', '/sys/fs/cgroup:/sys/fs/cgroup:ro',
                  'aquasec/tracee:0.19.0', '--scope', 'mntns=' + str(mount_namespace),
                  '--events', events, '--output', 'json',
                  '--http-listen-addr', ':3366', '--healthz', '--metrics'])
    containers.append(sensor)
    sensor_pid = int(run(['docker', 'inspect', sensor, '--format', '{{.State.Pid}}']))
    if native:
        endpoint_follower = subprocess.Popen(['docker', 'logs', '-f', sensor], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        thread = threading.Thread(target=record_endpoint_arrivals, args=(endpoint_follower,))
        thread.daemon = True
        thread.start()
        arrival_threads.append(thread)
    healthy = False
    for _ in range(40):
        code, response = endpoint(sensor_pid, 'healthz')
        if code == 0:
            healthy = True
            break
        state = run(['docker', 'inspect', sensor, '--format', '{{.State.Running}}'], required=False)
        if state != 'true':
            break
        time.sleep(0.5)
    report['tracee_ready'] = healthy
    if not healthy:
        raise RuntimeError('Tracee did not become healthy')
    code, metrics = endpoint(sensor_pid, 'metrics')
    (out / 'tracee_metrics_before.txt').write_text(metrics)
    report['metrics_before_ok'] = code == 0
    capture_log = (out / 'tcpdump.log').open('w')
    capture_args = ['nsenter', '-t', str(target_pid), '-n',
                    'tcpdump', '-i', 'eth0' if gateway_config else 'lo', '-n', '-U', '-s', '0']
    if not gateway_config:
        capture_args += ['-Q', 'in']
    capture_args += ['-w', str(out / 'network.pcap')]
    capture = subprocess.Popen(capture_args,
                               stdout=subprocess.DEVNULL, stderr=capture_log)
    if gateway_config:
        tool_capture_log = (out / 'tcpdump_tools.log').open('w')
        tool_capture = subprocess.Popen(['nsenter', '-t', str(target_pid), '-n', 'tcpdump',
            '-i', 'lo', '-Q', 'in', '-n', '-U', '-s', '0', '-w', str(out / 'network_tools.pcap')],
            stdout=subprocess.DEVNULL, stderr=tool_capture_log)
    for _ in range(30):
        if ('listening on' in (out / 'tcpdump.log').read_text() and
            (not gateway_config or 'listening on' in (out / 'tcpdump_tools.log').read_text())):
            break
        if capture.poll() is not None or (tool_capture and tool_capture.poll() is not None):
            raise RuntimeError('tcpdump exited during startup')
        time.sleep(0.1)
    else:
        raise RuntimeError('tcpdump readiness missing')
    report['capture_ready_at'] = time.time()
    report['network_capture_direction'] = {'eth0': 'inout', 'lo': 'in'}
    if native:
        report['clock_origin'] = clock_sample()
        gateway_config['clock_origin'] = report['clock_origin']
        clock_thread = threading.Thread(target=record_clocks)
        clock_thread.daemon = True
        clock_thread.start()
        for name in ('network', 'network_tools'):
            thread = threading.Thread(target=record_packet_arrivals, args=(name,))
            thread.daemon = True
            thread.start()
            arrival_threads.append(thread)
    report['task_started_at'] = time.time()
    if native:
        run_native_worker(target)
    elif gateway_config:
        p = subprocess.run(['docker', 'exec', '-i', target, 'python', '/probe.py'],
                           input=json.dumps(gateway_config) + '\n', stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, universal_newlines=True, timeout=780 if native else 290)
        gateway_config.pop('api_key', None)
        report['worker_exit_code'] = p.returncode
        (out / 'worker.stderr.log').write_text(p.stderr)
        if p.returncode:
            raise RuntimeError('Gateway worker failed; see worker.stderr.log')
        worker_out = p.stdout
        artifact = json.loads(worker_out)
        (out / 'trajectory.jsonl').write_text('\n'.join(json.dumps(row) for row in artifact.pop('trajectory')) + '\n')
        (out / 'labels.json').write_text(json.dumps(artifact.pop('evaluation'), indent=2))
        (out / 'gateway_artifact.json').write_text(json.dumps(artifact, indent=2))
        report['gateway'] = {k: artifact[k] for k in ('termination', 'error', 'requests')}
    else:
        worker_out = run(['docker', 'exec', target, 'python', '/probe.py'])
    report['task_ended_at'] = time.time()
    if not gateway_config:
        (out / 'actions.json').write_text(worker_out)
    time.sleep(2)
    finish_capture()
    rows = []
    malformed = 0
    for line in (out / 'endpoint.jsonl').read_text(errors='replace').splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            malformed += 1
    counts = collections.Counter(row.get('eventName') for row in rows)
    report['endpoint_event_counts'] = dict(counts)
    report['endpoint_malformed_lines'] = malformed
    observed = sorted(set(row.get('container', {}).get('id', row.get('containerId', '')) for row in rows))
    report['observed_container_ids'] = observed
    drops = re.search(r'(\d+) packets dropped by kernel', (out / 'tcpdump.log').read_text())
    report['network_dropped'] = int(drops.group(1)) if drops else None
    if gateway_config:
        drops_tools = re.search(r'(\d+) packets dropped by kernel', (out / 'tcpdump_tools.log').read_text())
        report['network_tools_dropped'] = int(drops_tools.group(1)) if drops_tools else None
    loss_metrics = [line for line in (out / 'tracee_metrics_after.txt').read_text().splitlines()
                    if not line.startswith('#') and ('lost' in line.lower() or 'drop' in line.lower())]
    report['endpoint_loss_metrics'] = loss_metrics
    report['ready'] = bool(counts.get('sched_process_exec') and counts.get('openat')
                           and counts.get('connect') and report['network_dropped'] == 0
                           and len(loss_metrics) > 0
                           and all(float(line.rsplit(None, 1)[1]) == 0 for line in loss_metrics)
                           and malformed == 0)
    if gateway_config:
        report['ready'] = report['ready'] and report['network_tools_dropped'] == 0 and report['gateway']['termination'] == 'completed'
except Exception as exc:
    report['error'] = type(exc).__name__ + ': ' + str(exc)
finally:
    if not report.get('sensors_drained'):
        report.setdefault('task_ended_at', time.time())
        try:
            finish_capture()
        except Exception as exc:
            report['drain_error'] = type(exc).__name__ + ': ' + str(exc)
    clock_stop.set()
    arrival_stop.set()
    if endpoint_follower is not None and endpoint_follower.poll() is None:
        endpoint_follower.terminate()
        endpoint_follower.wait(timeout=10)
    for thread in arrival_threads:
        thread.join(timeout=10)
    if capture is not None and capture.poll() is None:
        capture.send_signal(signal.SIGINT)
        capture.wait(timeout=10)
    if capture_log is not None:
        capture_log.close()
    if tool_capture is not None and tool_capture.poll() is None:
        tool_capture.send_signal(signal.SIGINT)
        tool_capture.wait(timeout=10)
    if tool_capture_log is not None:
        tool_capture_log.close()
    for cid in reversed(containers):
        p = subprocess.run(['docker', 'logs', cid], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (out / (cid[:12] + '.stdout.log')).write_bytes(p.stdout)
        (out / (cid[:12] + '.stderr.log')).write_bytes(p.stderr)
        run(['docker', 'rm', '-f', cid], required=False)
    report['sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in out.iterdir() if p.is_file()}
    (out / 'report.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report))
