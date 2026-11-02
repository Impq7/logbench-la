"""Generate a reproducible random sampling plan for the official-engine Slack collection.

80 sessions, drawn randomly over slack's 17 user tasks x 5 attack markers
(none = benign, plus the 4 ASB strategies). Benign and injected are balanced
40/40 so the LateFusion baseline can fit a decision boundary across train/val/test;
within those classes the user_task and injection_task are drawn at random. Fixed
seed keeps the plan reproducible.
"""
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SEED = 7
TOTAL = 80
BENIGN = 40
INJECTED = 40

USER_TASKS = ['user_task_%d' % i for i in range(17)]  # slack v1: user_task_0..16
INJECTION_TASKS = ['injection_task_%d' % i for i in range(1, 6)]  # injection_task_1..5
STRATEGIES = ['asb_concat', 'asb_escape', 'asb_context_ignore', 'asb_fake_completion']


def main(out_path=None):
    rng = random.Random(SEED)
    samples = []

    # 40 benign: attack = none, random user_task, no injection_task.
    for _ in range(BENIGN):
        samples.append({
            'user_task': rng.choice(USER_TASKS),
            'attack': 'none',
            'injection_task': None,
        })

    # 40 injected: 10 per ASB strategy, random user_task + random injection_task.
    for strategy in STRATEGIES:
        for _ in range(INJECTED // len(STRATEGIES)):
            samples.append({
                'user_task': rng.choice(USER_TASKS),
                'attack': strategy,
                'injection_task': rng.choice(INJECTION_TASKS),
            })

    rng.shuffle(samples)
    for i, s in enumerate(samples, 1):
        s['seq'] = i
        s['run_dir'] = 'agentdojo-official-ten-s%02d' % i

    plan = {
        'seed': SEED,
        'total': len(samples),
        'benign': BENIGN,
        'injected': INJECTED,
        'scenario': 'slack',
        'samples': samples,
    }
    out = Path(out_path) if out_path else ROOT / 'experiment' / 'agentdojo-official-slack-80' / 'plan.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding='utf-8')
    # summary
    from collections import Counter
    print('total:', len(samples))
    print('attack dist:', dict(Counter(s['attack'] for s in samples)))
    print('user_task dist:', dict(sorted(Counter(s['user_task'] for s in samples).items())))
    print('plan ->', out)
    return out


if __name__ == '__main__':
    main()
