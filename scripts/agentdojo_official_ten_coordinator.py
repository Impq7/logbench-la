"""官方 AgentDojo 引擎的 T/E/N 三模态采集 coordinator（Linux 容器内运行）。

复用官方 benchmark 引擎跑 T（OutputLogger 落盘）+ 真实外泄 N（网卡 pcap +
SNI/握手/流量解析），并补官方给不了的 E 模态：Tracee 端侧 syscall 事件。

本脚本运行在受信 coordinator 容器（--privileged --pid host + docker.sock）：
  - 通过 /proc/<agent_pid>/ns/mnt 取 agent 挂载命名空间 inode，启动 Tracee
    sensor（--scope mntns=...）只采集 agent 容器的端侧事件；
  - 时钟对齐复用 scripts/clock_alignment.py（Tracee boot_time -> monotonic，
    pcap realtime -> monotonic），CLOCK_BOOTTIME 采样写入 clock_sync.jsonl；
  - 事件经 docker logs -f 流式落盘 + arrival 索引，metrics before/after 门禁
    「丢失=0」，流式与最终 docker logs 逐字节比对。

拓扑（与 agentdojo_official_net.py 一致）：
  业务网 logbench-official-net：exfil_receiver(TLS443) + dns_server(UDP53)；
  agent 双网（eth0 业务网抓包 + bridge NAT 出 LLM 网关）。

密钥只经 stdin 进进程内存，不落盘、不进 argv。
"""
import collections
import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

ROOT = Path("/src")            # 项目根（只读挂载）
OUT = Path("/output")          # run_dir（读写挂载）

AGENT_IMAGE = "logbench-official-agent:r1"           # 含 tcpdump
FIXTURE_IMAGE = "logbench-native-dev:82f7911781dc78ba"
CONTAINER_PY = "/opt/agentdojo/.venv/bin/python"
NET = None  # assigned per session

# Tracee 0.24.1 事件集：与 server_split_collect.launch_sensor 一致，追加 tracee_info 供时钟校准
TRACEE_EVENTS = ("sched_process_fork,sched_process_exec,sched_process_exit,"
                 "openat,read,write,close,unlink,unlinkat,socket,connect,accept,accept4,"
                 "bind,listen,sendto,recvfrom,tracee_info")


def run(args, required=True, timeout=40):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True, timeout=timeout)
    report["checks"].append({"argv": args, "returncode": p.returncode,
                             "stdout": p.stdout, "stderr": p.stderr})
    if required and p.returncode:
        raise RuntimeError("Host command failed: " + " ".join(args[:4]))
    return p.stdout.strip()


def clock_sample():
    a = time.monotonic()
    wall = time.time()
    boot = time.clock_gettime(time.CLOCK_BOOTTIME)
    b = time.monotonic()
    return {"timestamp": wall, "monotonic": (a + b) / 2,
            "boottime": boot, "sampling_uncertainty_seconds": (b - a) / 2}


def loss_values(text):
    values = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        name, value = line.rsplit(None, 1)
        if "lost" in name.lower() or "drop" in name.lower():
            values[name] = float(value)
    return values


def endpoint_http(pid, path):
    p = subprocess.run(["nsenter", "-t", str(pid), "-n", "curl", "-fsS", "--max-time", "2",
                        "http://127.0.0.1:3366/" + path],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    return p.returncode, p.stdout


def record_endpoint_arrivals(role, follower):
    raw_path = OUT / f"endpoint_{role}.jsonl"
    idx_path = OUT / f"arrival_endpoint_{role}.jsonl"
    with raw_path.open("wb") as raw, idx_path.open("w") as index:
        for number, line in enumerate(iter(follower.stdout.readline, b"")):
            index.write(json.dumps({"record_index": number, "arrival_time": time.time(),
                                    "arrival_monotonic": time.monotonic(), "session_id": report["run_id"],
                                    "sha256": hashlib.sha256(line).hexdigest()}) + "\n")
            raw.write(line)
            raw.flush()
            index.flush()


def record_clocks(stop):
    with (OUT / "clock_sync.jsonl").open("w") as stream:
        while True:
            stream.write(json.dumps(clock_sample()) + "\n")
            stream.flush()
            if stop.wait(0.05):
                stream.write(json.dumps(clock_sample()) + "\n")
                break


def launch_sensor(role, mntns, tracee_image):
    http_args = ["--server", "http-address=:3366", "--server", "healthz", "--server", "metrics"]
    name = report["run_id"] + "-" + role + "-tracee"
    containers.append(name)
    sensor_id = run(["docker", "run", "--pull", "never", "-d", "--name", name,
                     "--pid", "host", "--cgroupns", "host", "--privileged", "--network", "none",
                     "--memory", "1g", "--memory-swap", "1g", "--entrypoint", "/tracee/tracee",
                     "-e", "LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host",
                     "-v", "/etc/os-release:/etc/os-release-host:ro", "-v", "/var/run:/var/run:ro",
                     "-v", "/boot:/boot:ro", "-v", "/sys/fs/cgroup:/sys/fs/cgroup:ro",
                     tracee_image, "--scope", "mntns=" + str(mntns),
                     "--events", TRACEE_EVENTS, "--output", "json"] + http_args)
    pid = int(run(["docker", "inspect", sensor_id, "--format", "{{.State.Pid}}"]))
    follower = subprocess.Popen(["docker", "logs", "-f", sensor_id],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    threads.append(threading.Thread(target=record_endpoint_arrivals, args=(role, follower),
                                    daemon=True))
    threads[-1].start()
    for _ in range(40):
        code, _ = endpoint_http(pid, "healthz")
        if code == 0:
            break
        if run(["docker", "inspect", sensor_id, "--format", "{{.State.Running}}"],
               required=False) != "true":
            raise RuntimeError("Tracee stopped: " + role)
        time.sleep(0.5)
    else:
        raise RuntimeError("Tracee health timeout: " + role)
    code, metrics = endpoint_http(pid, "metrics")
    if code:
        raise RuntimeError("Tracee metrics unavailable")
    (OUT / f"tracee_{role}_before.txt").write_text(metrics)
    return {"id": sensor_id, "pid": pid, "follower": follower, 'reader':threads[-1]}


def drain_sensor(role, sensor):
    code, metrics = endpoint_http(sensor["pid"], "metrics")
    (OUT / f"tracee_{role}_after.txt").write_text(metrics)
    run(["docker", "stop", "-t", "10", sensor["id"]])
    sensor["follower"].wait(timeout=15)
    sensor['reader'].join(timeout=5)
    p = subprocess.run(["docker", "logs", sensor["id"]],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (OUT / f"tracee_{role}.log").write_bytes(p.stderr)
    live = (OUT / f"endpoint_{role}.jsonl").read_bytes()
    before = loss_values((OUT / f"tracee_{role}_before.txt").read_text())
    after = loss_values((OUT / f"tracee_{role}_after.txt").read_text())
    loss_zero = bool(before) and before.keys() == after.keys() and all(v == 0 for v in after.values())
    return {"live_matches_final": live == p.stdout, "metrics_after_ok": code == 0,
            "loss_zero": loss_zero, "loss_before": before, "loss_after": after}


def collect_agent_output(proc, sensor, token):
    """Release the existing stdin pipe only after N has stopped and E is drained."""
    pending = json.dumps({'kind': 'exfil_audit_pending', 'token': token})
    sensor_drain = None
    with (OUT / 'console.log').open('a') as console:
        for line in proc.stdout:
            console.write(line)
            console.flush()
            sys.stdout.write(line)
            sys.stdout.flush()
            try:
                message = json.loads(line)
            except ValueError:
                message = {}
            if isinstance(message, dict) and message.get('token') == token:
                if message.get('kind') in ('task_started', 'task_ended'):
                    prefix = message['kind']
                    report[prefix + '_at'] = message['timestamp']
                    report[prefix + '_monotonic'] = message['monotonic']
            if line.strip() == pending:
                sensor_drain = drain_sensor('agent', sensor)
                report['sensors_drained'] = True
                report['capture_ended_at'] = time.time()
                proc.stdin.write(json.dumps({'command': 'flush_exfil_audit', 'token': token}) + '\n')
                proc.stdin.flush()
                proc.stdin.close()
    report['agent_exit_code'] = proc.wait()
    if sensor_drain is None:
        proc.stdin.close()
        raise RuntimeError('Agent exited without the exfil audit handoff')
    if not (OUT / 'exfil_sender.jsonl').is_file():
        raise RuntimeError('Missing sender audit after sensor stop')
    return sensor_drain


def save_receiver_audit(receiver_id):
    """Preserve existing receiver stderr before removal; never a model input."""
    p = subprocess.run(['docker', 'logs', receiver_id], capture_output=True)
    (OUT / 'exfil_receiver.jsonl').write_bytes(p.stderr)
    return p.returncode == 0


def align_session():
    from clock_alignment import ClockAlignment, tracee_boot_time, REVISION
    clocks = [json.loads(line) for line in (OUT / "clock_sync.jsonl").read_text().splitlines() if line]
    alignment = ClockAlignment(clocks)
    raw = [json.loads(line) for line in (OUT / "endpoint_agent.jsonl").read_text().splitlines() if line]
    boot_ns = tracee_boot_time(raw)
    counts = collections.Counter(e.get("eventName") for e in raw)
    events = [e for e in raw if e.get("eventName") != "tracee_info"]
    span = None
    if events:
        mono = [alignment.endpoint(e["timestamp"], boot_ns) for e in events]
        span = {"first_monotonic": min(mono), "last_monotonic": max(mono),
                "count": len(events),
                "clock_uncertainty_seconds": alignment.boot_uncertainty}
    return {"revision": REVISION, "boot_ns": boot_ns, "event_counts": dict(counts),
            "alignment": alignment.report(), "span": span}


def main():
    global report, containers, threads, NET
    cfg = json.loads(sys.stdin.readline())
    api_key = cfg.pop("api_key", None)
    if not api_key and not cfg.get('diagnostic'):
        raise SystemExit("missing api_key on stdin")
    # 兄弟容器 --mount source 由 docker 守护进程在主机侧解析，用主机真实路径
    host_root = cfg["host_root"]
    host_out = cfg["host_out"]
    host_runtime = cfg['host_runtime']

    report = {"run_id": "official-ten-" + uuid.uuid4().hex[:12],
              "kind": "agentdojo_official_TEN", "ready": False, "checks": [],
              "roles": {}, "errors": [], "clock_policy": cfg.get("clock_policy"),
              "sensors_drained": False}
    report.update(diagnostic=cfg.get('diagnostic',False), execution_scope=cfg['execution_scope'],
                  source_hashes=cfg['source_hashes'], image_ids=cfg['image_ids'])
    containers, threads = [], []
    NET = report['run_id'] + '-business'

    (OUT / "capture").mkdir(exist_ok=True, parents=True)

    receiver_id = dns_id = agent_id = sensor = None
    clock_stop = threading.Event()
    clock_thread = None
    try:
        run(['docker','network','create','--internal',NET])
        report['business_network'] = {'name':NET, 'internal':True}
        # 1) TLS receiver（被动 sink）
        receiver_id = "official-ten-recv-" + uuid.uuid4().hex[:8]
        containers.append(receiver_id)
        subprocess.run(["docker", "run", "-d", "--rm", "--name", receiver_id, "--network", NET,
                        "--mount", f"type=bind,source={host_runtime},target=/src,readonly",
                        "--entrypoint", CONTAINER_PY, FIXTURE_IMAGE, "/src/scripts/exfil_receiver.py"],
                       check=True, stdout=subprocess.DEVNULL)
        receiver_ip = run(["docker", "inspect", "-f",
                           "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", receiver_id])
        time.sleep(1.0)

        # 2) DNS responder
        dns_id = "official-ten-dns-" + uuid.uuid4().hex[:8]
        containers.append(dns_id)
        with (OUT / "dns.stderr.log").open("w") as dlog:
            dns_proc = subprocess.Popen(
                ["docker", "run", "--rm", "-i", "--name", dns_id, "--network", NET,
                 "--mount", f"type=bind,source={host_runtime},target=/src,readonly",
                 "--entrypoint", CONTAINER_PY, FIXTURE_IMAGE, "/src/scripts/dns_server.py"],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=dlog, text=True)
            dns_proc.stdin.write(json.dumps({"receiver_ip": receiver_ip}) + "\n")
            dns_proc.stdin.close()
        time.sleep(1.5)
        dns_ip = run(["docker", "inspect", "-f",
                      "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", dns_id])

        # 3) agent：create + 接 bridge（NAT 出口），start 后取 host_pid/mntns
        agent_id = "official-ten-agent-" + uuid.uuid4().hex[:8]
        containers.append(agent_id)
        agent_cfg = {
            "api_key": api_key,
            "base_url": cfg["base_url"],
            "model_id": cfg["model_id"],
            "reasoning_effort": cfg.get('reasoning_effort'),
            "suite": cfg["suite"],
            "benchmark_version": cfg["benchmark_version"],
            "user_tasks": cfg.get("user_tasks", ["user_task_0"]),
            "injection_tasks": cfg.get("injection_tasks", ["injection_task_4"]),
            "attack": cfg.get("attack", "asb_concat"),
            "logdir": "/runs",
            "project_root": "/src",
            "force_rerun": True,
            "exfil": True,
            "exfil_audit_token": report['run_id'],
            "diagnostic": cfg.get('diagnostic',False),
            "execution_scope": cfg['execution_scope'],
            "capture": {"iface": "any", "output": "/capture/network.pcap"},
        }
        (OUT / "00_plan.json").write_text(
            json.dumps({k: v for k, v in agent_cfg.items() if k != "api_key"},
                       indent=2, ensure_ascii=False))
        subprocess.run(["docker", "create", "-i", "--name", agent_id, "--network", NET, "--dns", dns_ip,
                        "--security-opt", "no-new-privileges",
                        "--tmpfs", "/tmp:rw,size=128m",
                        "--mount", f"type=bind,source={host_runtime},target=/src,readonly",
                        "--mount", f"type=bind,source={host_out},target=/runs",
                        "--mount", f"type=bind,source={host_out}/capture,target=/capture",
                        "--entrypoint", CONTAINER_PY, AGENT_IMAGE,
                        "/src/scripts/agentdojo_official_run.py"], check=True,
                       stdout=subprocess.DEVNULL)
        run(["docker", "network", "connect", "bridge", agent_id])

        proc = subprocess.Popen(["docker", "start", "-i", "-a", agent_id],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, encoding="utf-8")
        # 取 agent host_pid + mount namespace inode
        agent_pid = None
        for _ in range(100):
            pid = run(["docker", "inspect", agent_id, "--format", "{{.State.Pid}}"],
                      required=False)
            if pid and pid != "0":
                agent_pid = int(pid)
                break
            time.sleep(0.1)
        if agent_pid is None:
            raise RuntimeError("agent PID not available")
        mntns = os.stat(f"/proc/{agent_pid}/ns/mnt").st_ino
        report["roles"]["agent"] = {"container_id": agent_id, "host_pid": agent_pid,
                                    "mount_namespace": mntns}

        # Prepare candidate positions with the official cache before starting E/N.
        proc.stdin.write(json.dumps(agent_cfg) + '\n')
        proc.stdin.flush()
        api_key = agent_cfg = None
        prepared = json.dumps({'kind':'task_prepared','token':report['run_id']})
        with (OUT/'console.log').open('w') as console:
            for line in proc.stdout:
                console.write(line)
                if line.strip() == prepared:
                    break
            else:
                raise RuntimeError('Agent preparation failed before capture')

        # 4) Tracee E sensor 挂 agent mntns
        sensor = launch_sensor("agent", mntns, cfg["tracee_image"])
        report["roles"]["agent"]["sensor_container_id"] = sensor["id"]
        report["tracee_ready"] = True
        report["clock_origin"] = clock_sample()

        # 5) 时钟循环（BOOTTIME 采样）
        clock_thread = threading.Thread(target=record_clocks, args=(clock_stop,), daemon=True)
        clock_thread.start()
        report["capture_ready_at"] = time.time()

        # 6) 触发官方 benchmark（写入 agent stdin）
        proc.stdin.write(json.dumps({'command':'start_capture','token':report['run_id']}) + "\n")
        proc.stdin.flush()  # keep open for the post-sensor audit release
        # 7) Agent stops tcpdump, coordinator drains Tracee, then audit flush is released.
        sensor_drain = collect_agent_output(proc, sensor, report['run_id'])
        clock_stop.set()
        for t in threads:
            t.join(timeout=10)
        if clock_thread is not None:
            clock_thread.join(timeout=2)
        report["endpoint"] = sensor_drain

        # 8) 时钟对齐 + E 汇总
        try:
            report["emodality"] = align_session()
        except Exception as exc:  # noqa: BLE001
            report["errors"].append("alignment_failed: " + type(exc).__name__ + ": " + str(exc))

        # N 产物信息
        pcap = OUT / "capture" / "network.pcap"
        report["network"] = {"receiver_ip": receiver_ip, "dns_ip": dns_ip,
                             "pcap": str(pcap),
                             "pcap_bytes": pcap.stat().st_size if pcap.exists() else 0}

        # 门禁判定
        report["ready"] = bool(
            report["agent_exit_code"] == 0
            and sensor_drain["loss_zero"]
            and sensor_drain["live_matches_final"]
            and report.get("emodality", {}).get("span", {}).get("count", 0) > 0
            and report["network"]["pcap_bytes"] > 0
        )
        if not report["ready"]:
            report["errors"].append("ten_gate_failed")
    except Exception as exc:  # noqa: BLE001
        report["errors"].append(type(exc).__name__ + ": " + str(exc))
        if sensor is not None:
            try:
                drain_sensor("agent", sensor)
            except Exception as dexc:  # noqa: BLE001
                report["drain_error"] = type(dexc).__name__ + ": " + str(dexc)
    finally:
        clock_stop.set()
        if clock_thread is not None:
            clock_thread.join(timeout=2)
        if receiver_id:
            try:
                report['receiver_audit_saved'] = save_receiver_audit(receiver_id)
            except OSError as exc:
                report['receiver_audit_saved'] = False
                report['errors'].append('receiver_audit: ' + type(exc).__name__)
            if not report['receiver_audit_saved']:
                report['ready'] = False
        report['cleanup'] = []
        for cid in reversed(containers):
            removal = subprocess.run(['docker','rm','-f',cid],capture_output=True)
            remaining = subprocess.run(['docker','inspect',cid],capture_output=True).returncode == 0
            report['cleanup'].append({'id':cid,'remove_code':removal.returncode,'absent':not remaining})
        removal = subprocess.run(['docker','network','rm',NET],capture_output=True)
        remaining = subprocess.run(['docker','network','inspect',NET],capture_output=True).returncode == 0
        report['cleanup'].append({'id':NET,'remove_code':removal.returncode,'absent':not remaining})
        report['cleanup_ok'] = all(r['absent'] for r in report['cleanup'])
        report['ready'] = report['ready'] and report['cleanup_ok']
        (OUT / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
        from validate_official_session import validate_run
        try:
            report['validation'] = validate_run(OUT, allow_diagnostic=True)
        except Exception as exc:
            report['ready'] = False
            report['errors'].append('validation: ' + type(exc).__name__ + ': ' + str(exc))
        (OUT / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
        print(json.dumps({"kind": "done", "ready": report["ready"],
                          "run_id": report["run_id"]}, ensure_ascii=False), flush=True)
    if not report["ready"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
