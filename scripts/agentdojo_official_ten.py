"""主机侧 T/E/N 采集启动器（Windows）：DPAPI 密钥经 env 传入，Docker 拉起受信
coordinator 容器，密钥只经 stdin 进 coordinator 进程内存，不落盘。

coordinator 容器需 --privileged --pid host + docker.sock，用于：
  - /proc/<agent_pid>/ns/mnt 取挂载命名空间，启动 Tracee sensor（E 模态）；
  - CLOCK_BOOTTIME 采样做 E/N 时钟对齐；
  - nsenter/curl 访问 Tracee metrics。

拓扑与官方引擎调用同 agentdojo_official_net.py。
"""
import argparse
import json
import os
import subprocess
import sys
import uuid
import shutil
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COORDINATOR_IMAGE = "logbench-local-coordinator:r1"
BASE_URL = "https://124.223.37.235:6969/v1"
MODEL_ID = "cn:deepseek-v4.1-flash"
TRACEE_IMAGE = "aquasec/tracee:0.24.1"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--attack", default="asb_concat")
    parser.add_argument("--suite", default="slack")
    parser.add_argument("--benchmark-version", default="v1")
    parser.add_argument("--user-tasks", default="user_task_0")
    parser.add_argument("--injection-tasks", default="injection_task_4")
    parser.add_argument('--model-id', default=MODEL_ID)
    parser.add_argument('--reasoning-effort', choices=['low','medium','high'], default=None)
    parser.add_argument('--diagnostic', action='store_true', help='No-model sensor probe, excluded from dataset')
    args = parser.parse_args()

    out = args.run_dir.resolve()
    if out.parent != ROOT / "experiment" or not out.name.startswith("agentdojo-official-"):
        raise ValueError("run-dir 必须位于 experiment/ 且以 agentdojo-official- 开头")

    key = os.environ.pop("LOGBENCH_GATEWAY_KEY", None)
    if not key and not args.diagnostic:
        raise SystemExit("LOGBENCH_GATEWAY_KEY 未设置（先经 .ps1 DPAPI 解密）")

    out.mkdir(parents=True, exist_ok=False)
    (out / "capture").mkdir(exist_ok=True)

    cfg = {
        "api_key": key,
        "base_url": BASE_URL,
        "model_id": args.model_id,
        "reasoning_effort": args.reasoning_effort,
        "attack": args.attack,
        "suite": args.suite,
        "benchmark_version": args.benchmark_version,
        "user_tasks": args.user_tasks.split(",") if args.user_tasks else [],
        "injection_tasks": args.injection_tasks.split(",") if args.injection_tasks else [],
        "diagnostic": args.diagnostic,
        "execution_scope": "single_official_task",
        "tracee_image": TRACEE_IMAGE,
        "clock_policy": "tracee-boot-monotonic-r1",
        # coordinator 内启动兄弟容器时，--mount source 由 docker 守护进程在主机侧
        # 解析，必须传主机真实路径（不是 coordinator 内部的 /src、/output）。
        "host_root": ROOT.as_posix(),
        "host_out": out.as_posix(),
    }

    # Agent/fixtures see only these runtime sources, never the project datasets,
    # credentials, audit history or detector artefacts.
    runtime_files = ['scripts/agentdojo_official_run.py', 'scripts/exfil_receiver.py', 'scripts/dns_server.py',
        'logbench/__init__.py', 'logbench/agentdojo_asb/__init__.py', 'logbench/agentdojo_asb/attacks.py',
        'logbench/agentdojo_asb/wrap.py', 'logbench/agentdojo_asb/exfil.py']
    for relative in runtime_files:
        target = out / 'runtime_src' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    cfg['host_runtime'] = (out / 'runtime_src').as_posix()
    cfg['source_hashes'] = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in runtime_files}
    cfg['image_ids'] = {name: subprocess.check_output(['docker','image','inspect',name,'--format','{{.Id}}'],text=True).strip()
        for name in ('logbench-official-agent:r1', 'logbench-native-dev:82f7911781dc78ba', TRACEE_IMAGE)}

    command = ["docker", "run", "--rm", "-i", "--name", "official-ten-" + uuid.uuid4().hex[:12],
               "--privileged", "--pid", "host", "--network", "host",
               "-v", "/var/run/docker.sock:/var/run/docker.sock",
               "--mount", f"type=bind,source={ROOT.as_posix()},target=/src,readonly",
               "--mount", f"type=bind,source={out.as_posix()},target=/output",
               COORDINATOR_IMAGE, "python", "scripts/agentdojo_official_ten_coordinator.py"]

    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=None, text=True, encoding="utf-8")
    process.stdin.write(json.dumps(cfg) + "\n")
    process.stdin.close()
    key = None
    cfg = None
    for line in process.stdout:
        print(line, end="", flush=True)
    code = process.wait()
    if code:
        raise SystemExit(code)


if __name__ == "__main__":
    main()
