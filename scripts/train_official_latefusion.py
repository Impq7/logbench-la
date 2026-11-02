"""Official-engine LateFusion baseline: adapt the local LateFusion pipeline to
AgentDojo official-engine sessions.

The local baseline (``train_batch_latefusion.py``) reads hunyuan-chat-style
sessions whose report carries ``collection_validation.json`` + ``condition`` +
``development_split``. Official-engine sessions (``kind == agentdojo_official_TEN``)
have none of those: their QA lives in the coordinator's ``report.json``
(``ready``, ``network.pcap_bytes``, ``emodality.span``), their benign/injected
distinction lives in ``report.attack`` (``none`` vs an ASB strategy), and their
split boundary is the ``source_task_lineage``.

This module reuses ``train_batch_latefusion``'s train/verify/architecture config
verbatim, and only swaps in an official-engine ``load_official_samples`` loader.
Nothing else is reimplemented.

Usage:
    python scripts/train_official_latefusion.py --scenario slack \
        --split-map '{"asb-slack-user_task_0": "train", ...}'

The lineage -> split map is REQUIRED: official-engine runs do not record a
collected ``development_split``, so the split must be declared explicitly (by
user-task lineage). Every lineage present in the dataset must be mapped, and each
split must contain both benign and injected sessions.
"""
import argparse
import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from session_storage import SessionStore, verify_official_packed  # noqa: E402
import train_batch_latefusion as tbf  # noqa: E402

require = tbf.require


def load_official_samples(batch, scenarios, split_map=None):
    """Rebuild the cohort from official-engine sessions.

    ``split_map`` is a lineage -> split dict (required, see module docstring).
    """
    override = tbf.normalize_split_map(split_map)
    if override is None or override['kind'] != 'lineage':
        raise ValueError('Official-engine training requires a lineage -> split map '
                         '(no collected development_split exists).')
    samples, labels, evidence = [], {}, []
    for scenario in scenarios:
        base = ROOT / 'DataSet' / batch / scenario / 'sessions'
        require(base.is_dir(), 'No sessions at ' + str(base))
        for folder in sorted(p for p in base.iterdir() if p.is_dir()):
            verify_official_packed(folder)
            store = SessionStore(folder)
            report = store.json('report.json')
            lab = store.json('labels.json')
            require(report.get('kind') == 'agentdojo_official_TEN',
                    'Not an official-engine session: ' + folder.name)
            # Require the independent single-task QA preserved by the packer.
            # Transport evidence never replaces the official harm oracle.
            require(report.get('ready'), 'Coordinator gate failed: ' + folder.name)
            require((report.get('validation') or {}).get('revision') == 'official-single-task-r2'
                    and report['validation'].get('passed') is True, 'Current independent QA required')
            endpoint = report.get('endpoint') or {}
            require(endpoint.get('loss_zero') is True,
                    'Tracee loss unknown/nonzero: ' + folder.name)
            loss_after = endpoint.get('loss_after') or {}
            require(all(v == 0 for v in loss_after.values()) if loss_after else False,
                    'Tracee lost events unknown/nonzero: ' + folder.name)
            network = report.get('network') or {}
            require(network.get('pcap_bytes', 0) > 0, 'No pcap: ' + folder.name)
            require((report.get('emodality') or {}).get('span', {}).get('count', 0) > 0,
                    'No E events: ' + folder.name)
            # benign/injected from labels (y_attempt), cross-checked against report.attack.
            attack = report.get('attack')
            is_benign = attack in (None, 'none', '')
            require(lab['y_attempt'] == (0 if is_benign else 1),
                    'y_attempt/attack mismatch: ' + folder.name)
            lineage = report['source_task_lineage']
            require(lineage in override['mapping'],
                    'Lineage missing from split map: ' + lineage)
            split = override['mapping'][lineage]
            require(split in ('train', 'validation', 'test'), 'Bad split: ' + repr(split))
            sample = {'session_id': folder.name, 'group': lineage, 'split': split,
                      'scenario': scenario.capitalize(), 'backbone': report['model_requested'],
                      'canonical': '01_contract/' + folder.name,
                      'dataset_relative': folder.relative_to(ROOT).as_posix(),
                      'collected_split': split}
            record = {'session_id': folder.name, 'split': split,
                      'condition': 'injected' if lab['y_attempt'] else 'benign',
                      'y_attempt': lab['y_attempt'], 'y_harm': lab['y_harm'],
                      'exposed_injection': lab.get('exposed_injection'),
                      'task_success': lab.get('task_success'),
                      'attack': report.get('attack')}
            samples.append(sample)
            labels[folder.name] = lab
            evidence.append(record)
    require(samples, 'No sessions loaded')
    by_split = collections.defaultdict(set)
    for e in evidence:
        by_split[e['split']].add(e['y_attempt'])
    for sp in ('train', 'validation', 'test'):
        require(by_split.get(sp) == {0, 1},
                'Split ' + sp + ' lacks both classes: ' + repr(by_split.get(sp)))
    # Lineage must not cross splits.
    lineage_split = {}
    for s in samples:
        if s['group'] in lineage_split and lineage_split[s['group']] != s['split']:
            raise ValueError('Lineage crosses splits: ' + s['group'])
        lineage_split[s['group']] = s['split']
    return samples, labels, evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--batch', default='agentdojo-official-ten-r1')
    parser.add_argument('--scenario', required=True,
                        help='Comma-separated scenarios to mix.')
    parser.add_argument('--tag', default=None)
    parser.add_argument('--phase', choices=['train', 'verify'], default='train')
    parser.add_argument('--split-map', required=True,
                        help='REQUIRED: JSON (or path) of source-task lineage -> split, '
                             'e.g. \'{"asb-slack-user_task_0":"train","asb-slack-user_task_1":"test"}\'.')
    parser.add_argument('--t-view', choices=['raw', 'behavior'], default='raw')
    args = parser.parse_args()

    scenarios = [s.strip() for s in args.scenario.split(',') if s.strip()]
    require(scenarios, 'Empty scenario list')
    label = scenarios[0] if len(scenarios) == 1 else 'mixed-' + '-'.join(scenarios)
    if args.tag:
        label = label + '-' + args.tag
    split_map = tbf.parse_split_map(args.split_map)

    out = ROOT / 'experiment' / (args.batch + '-' + label + '-latefusion')
    if args.phase == 'train':
        result = tbf.train(args.batch, scenarios, label, split_map, args.t_view,
                           sample_loader=load_official_samples)
        print(json.dumps({'output': str(out), 'passed': result['passed'],
                          'sessions': result['sessions'],
                          'level2_TEN_test': result['level2_TEN_test']},
                         ensure_ascii=False), flush=True)
    else:
        samples, _, _ = load_official_samples(args.batch, scenarios, split_map)
        result = tbf.verify(out, samples, args.batch, scenarios, label)
        print(json.dumps(result, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
