"""One credential-safe gateway capability probe; not a benchmark sample."""
import json
import sys

import httpx
import openai

cfg = json.loads(sys.stdin.readline())
client = openai.OpenAI(base_url=cfg['base_url'], api_key=cfg.pop('api_key'),
    http_client=httpx.Client(verify=False), max_retries=0, timeout=60)
result = {'model_requested': cfg['model_id'], 'reasoning_effort_requested': 'low'}
try:
    response = client.chat.completions.create(model=cfg['model_id'],
        messages=[{'role':'user','content':'Reply with OK.'}], reasoning_effort='low',
        temperature=0, max_tokens=128)
    result.update(accepted=True, model_returned=response.model,
        finish_reason=response.choices[0].finish_reason,
        reasoning_effort_returned=getattr(response, 'reasoning_effort', None),
        usage=response.usage.model_dump() if response.usage else None,
        note='API acceptance is not independent proof of backend reasoning configuration.')
except openai.APIStatusError as exc:
    body = exc.body if isinstance(exc.body, dict) else {}
    error = body.get('error', body)
    text = str(error).lower()
    result.update(accepted=False, status=exc.status_code, error_type=type(exc).__name__,
        unsupported=exc.status_code in (400, 422) and any(s in text for s in ('reasoning_effort','reasoning effort')))
except openai.APIConnectionError as exc:
    result.update(accepted=False, error_type=type(exc).__name__, unsupported=False)
finally:
    client.close()
print(json.dumps(result))
raise SystemExit(0 if result['accepted'] else 2)
