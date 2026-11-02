"""Convert AgentDojo official-engine trajectory JSON to clean Harbor ATIF traces.

Purpose
-------
AgentDojo's ``OutputLogger`` trajectory carries the full evaluation metadata
(``security``, ``utility``, ``attack_type``, ``injection_task_id``,
``injections``, ``suite_name``, ``pipeline_name``, ``benchmark_version``,
``evaluation_timestamp``, ``duration``, ``error``) alongside the interaction
history. Feeding that file directly to an attack detector leaks the answer:
a model can trivially read ``security``/``attack_type`` instead of learning
attack signals from the interaction itself.

This module strips every label/shortcut field and emits a clean Harbor ATIF
(Agent Trajectory Interchange Format, RFC 0001) trace built **only** from the
agent interaction:

* ``system`` messages are dropped (they encode benchmark setup and can carry
  task/injection hints).
* ``user`` messages map to ``source: "user"`` steps.
* ``assistant`` messages map to ``source: "agent"`` steps; their ``tool_calls``
  are expanded into ``tool_calls[]`` with the original ``arguments`` preserved.
* ``tool`` messages (tool returns) are folded into the originating agent step's
  ``observation.results[]``, paired back to the originating call via
  ``source_call_id`` (Harbor ATIF has no ``tool`` source).

The output is a minimal, schema-conformant ATIF document:

.. code-block:: json

    {
      "schema_version": "ATIF-v1.7",
      "agent": {"name": "agentdojo", "version": "1"},
      "steps": [
        {"step_id": 1, "source": "user", "message": "..."},
        {"step_id": 2, "source": "agent", "message": "...",
         "tool_calls": [{"tool_call_id": "call_1", "function_name": "f", "arguments": {...}}],
         "observation": {"results": [{"source_call_id": "call_1", "content": "..."}]}}
      ]
    }

No field in the output derives from ``attack_type``/``security``/``utility``/
``injection_task_id`` or any other evaluation key, so the model sees only
interaction features.

Batch usage
-----------
    python scripts/agentdojo_to_atif.py <trajectory.json> [out_dir]

or point at a directory tree of ``*openai-compatible*/*.json`` files; every
trajectory is converted independently, one ATIF ``.json`` per input.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

SCHEMA_VERSION = "ATIF-v1.7"

# Every top-level AgentDojo trajectory key that is NOT interaction history.
# These are dropped outright so the detector cannot read the answer.
_EVAL_KEYS = {
    "security", "utility", "attack_type", "injection_task_id", "injections",
    "suite_name", "pipeline_name", "benchmark_version", "evaluation_timestamp",
    "duration", "error", "agentdojo_package_version", "user_task_id",
}

# Message keys we keep for an assistant/user message. Whitelist projection:
# anything else on the message (e.g. a stray evaluation field) is dropped.
_KEEP_MESSAGE_KEYS = {"role", "content", "tool_calls", "tool_call_id", "tool_call"}


def _text(content):
    """Flatten OpenAI-style content blocks to a single string.

    ``content`` may be a plain string or a list of ``{"type": "text", ...}``
    blocks. Non-text blocks (e.g. future image blocks) are skipped; only the
    textual interaction is projected into ``message``.
    """
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("content") or "")
        return "".join(parts)
    return str(content)


def _clean_arguments(args):
    """Keep the original tool arguments verbatim; drop any placeholder marker."""
    if args is None:
        return {}
    if not isinstance(args, dict):
        return {"value": args}
    # AgentDojo injects ``placeholder_args`` (may be None or a masked copy) next
    # to the real ``args``. We keep only the real ``args``; ``placeholder_args``
    # is benchmark bookkeeping, not interaction.
    return {k: v for k, v in args.items() if k != "placeholder_args"}


def convert(trajectory):
    """Convert one AgentDojo trajectory dict into a clean ATIF trace dict."""
    messages = trajectory.get("messages", [])
    steps = []
    calls, returned = {}, set()
    step_id = 0

    for msg in messages:
        if not isinstance(msg, dict):
            continue
        role = msg.get("role")

        # Drop the benchmark system prompt: it encodes task/injection setup.
        if role == "system":
            continue

        # Project only interaction-relevant keys (whitelist), never the raw msg.
        projected = {k: msg[k] for k in _KEEP_MESSAGE_KEYS if k in msg}

        if role == "user":
            step_id += 1
            steps.append({
                "step_id": step_id,
                "source": "user",
                "message": _text(projected.get("content")),
            })

        elif role == "assistant":
            step_id += 1
            step = {
                "step_id": step_id,
                "source": "agent",
                "message": _text(projected.get("content")),
            }
            tool_calls = projected.get("tool_calls")
            if isinstance(tool_calls, list) and tool_calls:
                normalized = []
                for call in tool_calls:
                    if not isinstance(call, dict):
                        continue
                    call_id = call.get('id') or call.get('tool_call_id')
                    if not call_id or call_id in calls:
                        raise ValueError('Missing/duplicate tool call ID')
                    calls[call_id] = step
                    normalized.append({
                        "tool_call_id": call.get("id") or call.get("tool_call_id") or "",
                        "function_name": call.get("function") or call.get("function_name") or call.get("name") or "",
                        "arguments": _clean_arguments(call.get("args") or call.get("arguments")),
                    })
                if normalized:
                    step["tool_calls"] = normalized
            steps.append(step)

        elif role == "tool":
            # Match the originating call even when another agent step intervenes.
            call_id = projected.get("tool_call_id") or projected.get("tool_call")
            content = _text(projected.get("content"))
            target = calls.get(call_id)
            if target is None or call_id in returned:
                raise ValueError('Orphan/duplicate tool result: ' + str(call_id))
            returned.add(call_id)
            observation = target.setdefault("observation", {})
            results = observation.setdefault("results", [])
            results.append({
                "source_call_id": call_id,
                "content": content,
            })

    # The official loop can stop after producing its final, unexecuted calls.
    pending = set(calls) - returned
    final_calls = {c['tool_call_id'] for c in steps[-1].get('tool_calls', [])} if steps else set()
    if pending and (messages[-1].get('role') != 'assistant' or pending != final_calls):
        raise ValueError('Incomplete tool call/result pairs')
    trace = {
        "schema_version": SCHEMA_VERSION,
        "agent": {"name": "agentdojo", "version": "1"},
        "steps": steps,
    }
    validate_atif(trace)
    return trace


def validate_atif(trace):
    """Validate our text-only ATIF-v1.7 export, without a new runtime dependency.

    This deliberately supports only the fields this exporter produces, not all
    optional/multimodal Harbor extensions. Tool arguments remain opaque user data.
    """
    if set(trace) != {'schema_version', 'agent', 'steps'} or trace['schema_version'] != SCHEMA_VERSION:
        raise ValueError('Expected complete ATIF-v1.7 document')
    if trace['agent'] != {'name': 'agentdojo', 'version': '1'} or not trace['steps']:
        raise ValueError('Missing ATIF agent/steps')
    seen, results = set(), set()
    for i, step in enumerate(trace['steps'], 1):
        if step.get('step_id') != i or step.get('source') not in ('user', 'agent') or not isinstance(step.get('message'), str):
            raise ValueError('Invalid ATIF step')
        if set(step) - {'step_id','source','message','tool_calls','observation'}:
            raise ValueError('Unexpected ATIF step fields')
        local = set()
        for call in step.get('tool_calls', []):
            cid = call.get('tool_call_id')
            if not cid or cid in seen or not call.get('function_name') or not isinstance(call.get('arguments'), dict):
                raise ValueError('Invalid ATIF tool call')
            seen.add(cid)
            local.add(cid)
        for result in step.get('observation', {}).get('results', []):
            cid = result.get('source_call_id')
            if cid not in local or cid in results or not isinstance(result.get('content'), str):
                raise ValueError('Invalid ATIF observation link')
            results.add(cid)
    pending = seen - results
    final_calls = {c['tool_call_id'] for c in trace['steps'][-1].get('tool_calls', [])}
    if pending and (pending != final_calls or trace['steps'][-1].get('observation')):
        raise ValueError('Incomplete ATIF observations')


def _is_eval_free(trace):
    """Assert no evaluation/label field leaked into the output."""
    banned = {"security", "utility", "attack_type", "injection_task_id",
              "injections", "suite", "pipeline", "benchmark", "y_attempt",
              "y_harm", "evaluation", "oracle"}
    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k.lower() in banned or any(b in k.lower() for b in banned):
                    raise ValueError("label field leaked: " + k)
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)
    walk(trace)


def convert_file(path, out_dir):
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    trace = convert(data)
    validate_atif(trace)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    # Neutral output name: the input filename often encodes attack/task labels
    # (e.g. ``injection_task_4.json``, ``asb_concat/...``). We name the output by
    # a content hash so the detector cannot infer the label from the file name.
    stem = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    out = out_dir / (stem + ".atif.json")
    out.write_text(json.dumps(trace, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"input": str(path), "output": str(out), "steps": len(trace["steps"])}


def iter_trajectories(paths):
    """Expand CLI args into a flat list of trajectory JSON files.

    A directory argument is walked for any ``*openai-compatible*/*.json`` file,
    so a whole experiment tree can be converted in one call.
    """
    for arg in paths:
        p = Path(arg)
        if p.is_dir():
            yield from sorted(p.rglob("*.json"))
        else:
            yield p


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("inputs", nargs="+", help="Trajectory JSON file(s) or directory tree(s).")
    parser.add_argument("-o", "--out-dir", default="DataSet/atif",
        help="Output directory for ATIF traces (default: DataSet/atif).")
    args = parser.parse_args(argv)

    results = []
    for path in iter_trajectories(args.inputs):
        try:
            results.append(convert_file(path, args.out_dir))
        except Exception as exc:  # noqa: BLE001 - report and continue batch
            print("FAILED %s: %s" % (path, exc), file=sys.stderr)

    print(json.dumps({"converted": len(results), "results": results},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
