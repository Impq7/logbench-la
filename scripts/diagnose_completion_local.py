"""Local infrastructure-only interface check when the SSH route is unavailable."""
import json
import os
from pathlib import Path
import runpy
import uuid

root = Path(__file__).resolve().parents[1]
config = json.loads((root / 'configs/pilot.json').read_text())
config['api_key'] = os.environ.pop('LOGBENCH_DIAGNOSTIC_KEY')
out = root / 'experiment' / ('local-gateway-completion-budget-' + uuid.uuid4().hex[:12])
runpy.run_path(str(root / 'scripts/server_completion_budget.py'), init_globals={
    'gateway_config': config, 'budget_source_root': str(root / 'DataSet/deepseek-development/sessions'),
    'budget_output_root': str(out)})
