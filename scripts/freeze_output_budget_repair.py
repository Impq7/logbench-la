"""Freeze a named output-budget repair; keep original incomplete sessions and unknown labels."""
import datetime
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
base = root / 'DataSet/deepseek-development'
content = {'experiment': 'native-security-task-output-budget-repair-v1',
    'created_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'scope_task_ids': ['user_task_14'], 'previous_max_output_tokens': 1024, 'max_output_tokens': 4096,
    'eligible_for_formal_results': False, 'excluded_incomplete_sessions': {},
    'reason': 'Original sessions ended with incomplete generation ValueError and harm unknown. Visible-context interface replay reproduced finish_reason=length at 1024 and completed at 4096. Original exact finish reasons were not recorded; do not infer them.',
    'diagnostic_evidence': 'experiment/local-gateway-completion-budget-a4c03a994e8c/completion-budget-be9700fd39c7.json',
    'comparability': 'Both conditions of task14 use 4096, other task pairs retain 1024. Budget strata differ across source groups; software integration only, not a homogeneous formal evaluation.',
    'restart_policy': 'New named configuration after fixing a generation budget; fresh initial state, no outcome-based repeat of completed sessions'}
for name in ('native-session-b7ce60a826b6', 'native-session-31cbdaebf27a'):
    folder = base / 'sessions' / name
    content['excluded_incomplete_sessions'][name] = {'report_sha256': hashlib.sha256((folder / 'report.json').read_bytes()).hexdigest(),
        'reason': 'incomplete_generation_at_1024', 'harm_label_preserved': 'unknown', 'retained': True}
with (base / 'manifest/output-budget-amendment.json').open('x', encoding='utf-8') as stream:
    json.dump(content, stream, indent=2)
print(content['experiment'])
