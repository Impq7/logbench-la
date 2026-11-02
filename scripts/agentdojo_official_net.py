"""Phase 2 主机编排：官方引擎 agent 容器 + 真实外泄网络 + 网卡 pcap 抓包。

拓扑：
  - 业务网 logbench-official-net：exfil_receiver(TCP443 TLS sink) + dns_server(UDP53)
    两个被动网络夹具，agent 通过 --dns 把外泄目标域名解析到 receiver，形成真实
    DNS→TCP→TLS(SNI) 外泄链。
  - agent 同时接默认 bridge（NAT 出口）访问 LLM 网关；业务网 eth0 抓 pcap。
  - agent 内 tcpdump 抓 eth0（业务网），N 由 n_protocol_extract 解析 SNI/握手/流量。

密钥只经 LOGBENCH_GATEWAY_KEY(env) → 进程内存 → docker stdin。
"""
import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENT_IMAGE = "logbench-official-agent:r1"          # 含 tcpdump
FIXTURE_IMAGE = "logbench-native-dev:82f7911781dc78ba"  # receiver/dns 用
CONTAINER_PY = "/opt/agentdojo/.venv/bin/python"
NET = "logbench-official-net"
BASE_URL = "https://124.223.37.235:6969/v1"
MODEL_ID = "cn:deepseek-v4.1-flash"


def docker(*args: str) -> str:
    return subprocess.check_output(["docker", *args], text=True).strip()


def docker_ok(*args: str) -> bool:
    return subprocess.run(["docker", *args], capture_output=True).returncode == 0


def net_exists(name: str) -> bool:
    return docker_ok("network", "inspect", name)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--attack", default="asb_concat")
    args = parser.parse_args()
    out = args.run_dir.resolve()
    if out.parent != ROOT / "experiment" or not out.name.startswith("agentdojo-official-"):
        raise ValueError("run-dir 必须位于 experiment/ 且以 agentdojo-official- 开头")

    key = os.environ.pop("LOGBENCH_GATEWAY_KEY", None)
    if not key:
        raise SystemExit("LOGBENCH_GATEWAY_KEY 未设置（先经 .ps1 DPAPI 解密）")

    out.mkdir(parents=True, exist_ok=True)
    (out / "capture").mkdir(exist_ok=True)

    if not net_exists(NET):
        docker("network", "create", NET)

    receiver_id = dns_id = agent_id = None
    dns_proc = None
    try:
        # 1) TLS receiver（被动 sink，无 stdin）
        receiver_id = "logbench-official-recv-" + uuid.uuid4().hex[:8]
        subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", receiver_id, "--network", NET,
             "--mount", f"type=bind,source={ROOT.as_posix()},target=/src,readonly",
             "--entrypoint", CONTAINER_PY, FIXTURE_IMAGE, "/src/scripts/exfil_receiver.py"],
            check=True,
        )
        receiver_ip = docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", receiver_id)
        time.sleep(1.0)

        # 2) DNS responder（经 stdin 告知 receiver IP，后台常驻）
        dns_id = "logbench-official-dns-" + uuid.uuid4().hex[:8]
        dns_log = out / "dns.stderr.log"
        with dns_log.open("w", encoding="utf-8") as dlog:
            dns_proc = subprocess.Popen(
                ["docker", "run", "--rm", "-i", "--name", dns_id, "--network", NET,
                 "--mount", f"type=bind,source={ROOT.as_posix()},target=/src,readonly",
                 "--entrypoint", CONTAINER_PY, FIXTURE_IMAGE, "/src/scripts/dns_server.py"],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=dlog, text=True,
            )
            dns_proc.stdin.write(json.dumps({"receiver_ip": receiver_ip}) + "\n")
            dns_proc.stdin.close()
        time.sleep(1.5)
        dns_ip = docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", dns_id)

        # 3) agent：先 create 再接默认 bridge（网关 NAT 出口），最后 start -i 读 stdin
        agent_id = "logbench-official-agent-" + uuid.uuid4().hex[:8]
        cfg = {
            "api_key": key,
            "base_url": BASE_URL,
            "model_id": MODEL_ID,
            "suite": "slack",
            "benchmark_version": "v1",
            "user_tasks": ["user_task_0"],
            "injection_tasks": ["injection_task_4"],
            "attack": args.attack,
            "logdir": "/runs",
            "project_root": "/src",
            "force_rerun": True,
            "exfil": True,
            "positive_control": "www.my-website-234.com/random",
            "capture": {"iface": "eth0", "output": "/capture/network.pcap"},
        }
        (out / "00_plan.json").write_text(
            json.dumps({k: v for k, v in cfg.items() if k != "api_key"}, indent=2, ensure_ascii=False)
        )
        subprocess.run(
            ["docker", "create", "-i", "--name", agent_id, "--network", NET, "--dns", dns_ip,
             "--mount", f"type=bind,source={ROOT.as_posix()},target=/src,readonly",
             "--mount", f"type=bind,source={out.as_posix()},target=/runs",
             "--mount", f"type=bind,source={(out / 'capture').as_posix()},target=/capture",
             "--entrypoint", CONTAINER_PY, AGENT_IMAGE, "/src/scripts/agentdojo_official_run.py"],
            check=True,
        )
        docker("network", "connect", "bridge", agent_id)

        console = out / "console.log"
        with console.open("w", encoding="utf-8") as logf:
            proc = subprocess.Popen(
                ["docker", "start", "-i", "-a", agent_id],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8",
            )
            proc.stdin.write(json.dumps(cfg) + "\n")
            proc.stdin.close()
            key = None
            cfg = None
            for line in proc.stdout:
                logf.write(line)
                print(line, end="", flush=True)
            code = proc.wait()

        # 抓包信息
        pcap = out / "capture" / "network.pcap"
        (out / "network.json").write_text(json.dumps({
            "receiver_ip": receiver_ip, "dns_ip": dns_ip,
            "pcap": str(pcap), "pcap_bytes": pcap.stat().st_size if pcap.exists() else 0,
        }, indent=2))
        if code:
            raise SystemExit(code)
    finally:
        for cid in (receiver_id, dns_id):
            if cid:
                subprocess.run(["docker", "rm", "-f", cid], capture_output=True)
        if agent_id:
            subprocess.run(["docker", "rm", "-f", agent_id], capture_output=True)


if __name__ == "__main__":
    main()
