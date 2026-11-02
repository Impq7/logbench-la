"""One official AgentDojo task per capture; no suite-wide utility preflight."""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import shutil


def control(kind, cfg, **values):
    print(json.dumps(dict(kind=kind, token=cfg.get('exfil_audit_token'), **values)), flush=True)


def finish_capture(tcpdump_proc, cfg):
    if tcpdump_proc is not None:
        tcpdump_proc.terminate()
        try:
            tcpdump_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            tcpdump_proc.kill()
            tcpdump_proc.wait(timeout=5)
        tcpdump_proc.log_thread.join(timeout=2)
    token = cfg.get('exfil_audit_token')
    if token:
        control('exfil_audit_pending', cfg)
        if json.loads(sys.stdin.readline() or '{}') != {'command':'flush_exfil_audit','token':token}:
            raise RuntimeError('Exfil audit not released after sensor stop')
    from logbench.agentdojo_asb.exfil import write_exfil_audit
    write_exfil_audit(Path(cfg['logdir']) / 'exfil_sender.jsonl')
    if tcpdump_proc is not None:
        shutil.copyfile('/tmp/logbench-network.pcap', cfg['capture']['output'])
        (Path(cfg['logdir']) / 'tcpdump.log').write_text(''.join(tcpdump_proc.log_lines))


def use_hunyuan_text_messages(llm):
    """Hunyuan gateway accepts strings, not OpenAI text-block arrays."""
    create = llm.client.chat.completions.create
    def request(**kwargs):
        messages = []
        for original in kwargs['messages']:
            message = dict(original)
            content = message.get('content')
            if isinstance(content, list):
                message['content'] = ''.join(part['text'] for part in content)
            elif content is None:
                message['content'] = ''
            messages.append(message)
        return create(**dict(kwargs, messages=messages))
    llm.client.chat.completions.create = request


def prepare_task(cfg):
    """Reuse official pipeline, candidate cache, logger and single-task runner."""
    import logbench.agentdojo_asb  # register existing strategies
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import run_task_with_injection_tasks, run_task_without_injection_tasks
    from agentdojo.logging import OutputLogger
    from agentdojo.models import ModelsEnum
    from agentdojo.task_suite.load_suites import get_suite
    from logbench.agentdojo_asb.wrap import wrap_external_tools

    if len(cfg['user_tasks']) != 1 or cfg.get('positive_control'):
        raise ValueError('Collection requires one user task and no positive control')
    suite = get_suite(cfg['benchmark_version'], cfg['suite'])
    task = suite.get_user_task_by_id(cfg['user_tasks'][0])
    pipeline = AgentPipeline.from_config(PipelineConfig(llm=ModelsEnum.OPENAI_COMPATIBLE,
        model_id=cfg['model_id'], defense=None, system_message_name=None, system_message=None))
    if cfg.get('reasoning_effort') is not None or cfg['model_id'] == 'hunyuan-chat':
        # The tools loop reuses this same official OpenAILLM instance.
        from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
        llm = next(element for element in pipeline.elements if isinstance(element, OpenAILLM))
        llm.reasoning_effort = cfg.get('reasoning_effort')
        if cfg['model_id'] == 'hunyuan-chat':
            use_hunyuan_text_messages(llm)
    attacker = None
    if cfg.get('attack') not in (None, '', 'none'):
        if len(cfg['injection_tasks']) != 1:
            raise ValueError('Collection requires one injection task')
        attacker = load_attack(cfg['attack'], suite, pipeline)
        # Official ground-truth candidate discovery is cached, before sensors and
        # before tool wrapping: no fixture traffic and no second model task.
        attacker.attack(task, suite.get_injection_task_by_id(cfg['injection_tasks'][0]))
    wrap_external_tools(suite.tools)

    def execute():
        with OutputLogger(str(cfg['logdir'])):
            if attacker is None:
                return run_task_without_injection_tasks(suite, pipeline, task, Path(cfg['logdir']), True, cfg['benchmark_version'])
            return run_task_with_injection_tasks(suite, pipeline, task, attacker, Path(cfg['logdir']), True,
                                                 cfg['injection_tasks'], cfg['benchmark_version'])
    return execute


def sensor_probe():
    """No-model diagnostic; never publishable as a dataset task."""
    from logbench.agentdojo_asb.exfil import fire_exfil
    probe = Path('/tmp/logbench-sensor-probe')
    probe.write_text('synthetic diagnostic')
    probe.read_bytes()
    fire_exfil('post_webpage', {'url':'diagnostic.logbench.test', 'content':'synthetic diagnostic'})


def main():
    cfg = json.loads(sys.stdin.readline())
    key = cfg.pop('api_key', None)
    sys.path.insert(0, cfg.get('project_root', '/src'))
    if cfg.get('diagnostic'):
        execute = sensor_probe
    else:
        if not key:
            raise ValueError('Missing gateway credential')
        os.environ['OPENAI_COMPATIBLE_BASE_URL'] = cfg['base_url']
        os.environ['OPENAI_COMPATIBLE_API_KEY'] = key
        execute = prepare_task(cfg)
    key = None
    token = cfg.get('exfil_audit_token')
    if token:
        control('task_prepared', cfg)
        if json.loads(sys.stdin.readline() or '{}') != {'command':'start_capture','token':token}:
            raise RuntimeError('Sensors did not release the task')
    capture = cfg['capture']
    proc = subprocess.Popen(['tcpdump','--immediate-mode','-B','8192','-i',capture['iface'],
                             '-w','/tmp/logbench-network.pcap','-U'],
                            stderr=subprocess.PIPE,text=True)
    proc.log_lines = []
    ready = threading.Event()
    def collect_log():
        for line in proc.stderr:
            proc.log_lines.append(line)
            if 'listening on' in line:
                ready.set()
    proc.log_thread = threading.Thread(target=collect_log, daemon=True)
    proc.log_thread.start()
    try:
        if not ready.wait(5) or proc.poll() is not None:
            raise RuntimeError('tcpdump not ready')
        control('task_started',cfg,timestamp=time.time(),monotonic=time.monotonic())
        try:
            execute()
        finally:
            control('task_ended',cfg,timestamp=time.time(),monotonic=time.monotonic())
    finally:
        finish_capture(proc,cfg)


if __name__ == '__main__':
    main()
