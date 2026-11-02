"""主机侧编排：解密后的密钥经 env → docker stdin 传给官方引擎容器。

密钥只经 LOGBENCH_GATEWAY_KEY(env) → 进程内存 → docker stdin，不落盘、不进 argv。
容器内跑官方 AgentDojo benchmark（OPENAI_COMPATIBLE 网关 + ASB 攻击），T 由官方
OutputLogger 落 /runs，回传 run-dir 供审计。
"""
import argparse
import json
import os
import subprocess
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "logbench-native-dev:82f7911781dc78ba"
CONTAINER_PY = "/opt/agentdojo/.venv/bin/python"

# 冻结开发网关与模型（与 configs/split50-development.json 一致，不回退）
BASE_URL = "https://124.223.37.235:6969/v1"
MODEL_ID = "cn:deepseek-v4.1-flash"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--attack", default="asb_concat")
    parser.add_argument("--suite", default="slack")
    parser.add_argument("--benchmark-version", default="v1")
    parser.add_argument("--user-tasks", default="user_task_0")
    parser.add_argument("--injection-tasks", default="injection_task_4")
    args = parser.parse_args()

    out = args.run_dir.resolve()
    if out.parent != ROOT / "experiment" or not out.name.startswith("agentdojo-official-"):
        raise ValueError("run-dir 必须位于 experiment/ 且以 agentdojo-official- 开头")

    key = os.environ.pop("LOGBENCH_GATEWAY_KEY", None)
    if not key:
        raise SystemExit("LOGBENCH_GATEWAY_KEY 未设置（先经 .ps1 DPAPI 解密）")

    cfg = {
        "api_key": key,
        "base_url": BASE_URL,
        "model_id": MODEL_ID,
        "suite": args.suite,
        "benchmark_version": args.benchmark_version,
        "user_tasks": [args.user_tasks],
        "injection_tasks": [args.injection_tasks],
        "attack": args.attack,
        "logdir": "/runs",
        "project_root": "/src",
        "force_rerun": True,
    }
    out.mkdir(parents=True, exist_ok=True)
    # 配置快照不含密钥
    (out / "00_plan.json").write_text(
        json.dumps({k: v for k, v in cfg.items() if k != "api_key"}, indent=2, ensure_ascii=False)
    )

    cmd = [
        "docker", "run", "--rm", "-i",
        "--name", "logbench-official-" + uuid.uuid4().hex[:8],
        "--mount", f"type=bind,source={ROOT.as_posix()},target=/src,readonly",
        "--mount", f"type=bind,source={out.as_posix()},target=/runs",
        "--entrypoint", CONTAINER_PY, IMAGE, "/src/scripts/agentdojo_official_run.py",
    ]
    log_path = out / "console.log"
    with log_path.open("w", encoding="utf-8") as logf:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, encoding="utf-8")
        proc.stdin.write(json.dumps(cfg) + "\n")
        proc.stdin.close()
        key = None
        cfg = None
        for line in proc.stdout:
            logf.write(line)
            print(line, end="", flush=True)
        code = proc.wait()
    if code:
        raise SystemExit(code)


if __name__ == "__main__":
    main()
