"""Responses SSE transport; only completed responses may drive tools."""
import json
import re
import urllib.error
import urllib.request


def safe_gateway_metadata(value, api_key):
    """Only explicitly selected response fields reach disk; never export reasoning/headers."""
    encoded = json.dumps(value).replace(api_key, '[REDACTED]') if api_key else json.dumps(value)
    return json.loads(re.sub(r'(?i)bearer\s+[^\s\"\\]+', 'Bearer [REDACTED]', encoded))


def response_connection(response):
    # CPython urllib's HTTPResponse exposes its live socket before response.read().
    # Missing metadata stays unknown, rather than being guessed from an IP/time match.
    try:
        sock = response.fp.raw._sock
        local, remote = sock.getsockname(), sock.getpeername()
        return {'local_ip': local[0], 'local_port': local[1],
                'remote_ip': remote[0], 'remote_port': remote[1], 'protocol': 6}
    except (AttributeError, OSError):
        return None


def completed_sse(stream):
    completed = None
    data_lines = []
    for raw in stream:
        line = raw.decode('utf-8').rstrip('\r\n')
        if line.startswith('data:'):
            data_lines.append(line[5:].lstrip())
        elif not line and data_lines:
            data = '\n'.join(data_lines)
            data_lines = []
            if data == '[DONE]':
                break
            event = json.loads(data)
            if event.get('type') in ('response.failed', 'response.incomplete', 'error'):
                raise ValueError('Gateway returned failed or incomplete SSE response')
            if event.get('type') == 'response.completed':
                completed = event['response']
                break
    if completed is None or completed.get('status') != 'completed':
        raise ValueError('Missing response.completed event')
    return completed


def responses_request(api_key, history, tools, config=None):
    config = config or {}
    native_tools = [dict(type='function', **tool['function']) for tool in tools]
    body = json.dumps({'model': config.get('model_requested', 'gpt-5.5'), 'input': history, 'tools': native_tools,
                       'stream': True, 'store': False, 'max_output_tokens': config.get('max_output_tokens', 1024)}).encode()
    request = urllib.request.Request(config.get('gateway_base_url', 'https://43.160.241.16/v1').rstrip('/') + '/responses', data=body,
        headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + api_key})
    try:
        with urllib.request.urlopen(request, timeout=config.get('request_timeout_seconds', 45)) as stream:
            result = completed_sse(stream)
            status = stream.status
    except urllib.error.HTTPError as exc:
        try:
            error = json.loads(exc.read(16384)).get('error', {})
            if not isinstance(error, dict):
                error = {'message': str(error)}
            detail = {k: str(error[k])[:1500] for k in ('code', 'type', 'param', 'message') if k in error}
            detail = {k: re.sub(r'(?i)bearer\s+[^\s\"\']+', 'Bearer [REDACTED]',
                                 v.replace(api_key, '[REDACTED]')) for k, v in detail.items()}
            exc.gateway_error = detail
        except (ValueError, AttributeError):
            exc.gateway_error = {'body': 'unavailable_or_non_json'}
        raise
    calls, texts = [], []
    for item in result['output']:
        if item['type'] == 'function_call':
            calls.append({'id': item['call_id'], 'type': 'function',
                          'function': {'name': item['name'], 'arguments': item['arguments']}})
        elif item['type'] == 'message':
            texts.extend(part['text'] for part in item.get('content', []) if part['type'] == 'output_text')
    # Any opaque reasoning continuation is replayed in memory only, never exported as T.
    history.extend(result['output'])
    visible = {'role': 'assistant', 'content': '\n'.join(texts) or None, 'tool_calls': calls}
    return result, status, visible


def chat_completions_request(api_key, history, tools, config):
    body = json.dumps({'model': config['model_requested'], 'messages': history,
                       'tools': tools, 'tool_choice': 'auto', 'stream': False,
                       'max_tokens': config.get('max_output_tokens', 1024)}).encode()
    request = urllib.request.Request(config['gateway_base_url'].rstrip('/') + '/chat/completions',
        data=body, headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + api_key})
    try:
        with urllib.request.urlopen(request, timeout=config.get('request_timeout_seconds', 60)) as response:
            connection = response_connection(response)
            result = json.loads(response.read())
            status = response.status
    except urllib.error.HTTPError as exc:
        try:
            error = json.loads(exc.read(16384)).get('error', {})
            if not isinstance(error, dict):
                error = {'message': str(error)}
            exc.gateway_error = safe_gateway_metadata({k: str(error[k])[:1500]
                                 for k in ('code', 'type', 'param', 'message') if k in error}, api_key)
        except (ValueError, AttributeError):
            exc.gateway_error = {'body': 'unavailable_or_non_json'}
        raise
    choice = (result.get('choices') or [{}])[0]
    metadata = safe_gateway_metadata({'response_id': result.get('id'), 'returned_model': result.get('model'),
        'status': status, 'usage': result.get('usage'), 'finish_reason': choice.get('finish_reason'),
        'connection': connection}, api_key)
    raw = choice.get('message') or {}
    if choice.get('finish_reason') not in ('stop', 'tool_calls', 'function_call'):
        error = ValueError('Incomplete Chat Completions response')
        error.response_metadata = metadata
        # Visible fragments are evidence, but must never execute incomplete tool calls.
        error.visible_response = safe_gateway_metadata({k: raw[k] for k in ('role', 'content', 'tool_calls') if k in raw}, api_key)
        raise error
    result['collection_metadata'] = metadata
    # Preserve provider-required continuation in memory; export only visible fields.
    runtime = {k: raw[k] for k in ('role', 'content', 'tool_calls', 'reasoning_content') if k in raw}
    history.append(runtime)
    visible = {k: raw[k] for k in ('role', 'content', 'tool_calls') if k in raw}
    return result, status, visible
