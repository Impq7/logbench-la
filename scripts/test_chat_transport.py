import io
import json
import unittest
import urllib.error
from unittest.mock import patch

from gateway_protocol import chat_completions_request


class ChatTransportTests(unittest.TestCase):
    config = {'gateway_base_url': 'https://example.invalid/v1', 'model_requested': 'test-model'}

    def response(self, reason, message):
        stream = io.BytesIO(json.dumps({'choices': [{'finish_reason': reason, 'message': message}]}).encode())
        stream.status = 200
        return stream

    def test_reasoning_retained_only_in_memory_continuation(self):
        history = []
        with patch('gateway_protocol.urllib.request.urlopen', return_value=self.response('stop',
                {'role': 'assistant', 'content': 'visible', 'reasoning_content': 'private continuation'})):
            _, _, visible = chat_completions_request('test-key-only', history, [], self.config)
        self.assertNotIn('reasoning_content', visible)
        self.assertEqual(history[0]['reasoning_content'], 'private continuation')

    def test_truncated_response_cannot_drive_tools(self):
        history = []
        with patch('gateway_protocol.urllib.request.urlopen', return_value=self.response('length',
                {'role': 'assistant', 'tool_calls': [{'id': 'incomplete'}]})):
            with self.assertRaisesRegex(ValueError, 'Incomplete'):
                chat_completions_request('test-key-only', history, [], self.config)
        self.assertEqual(history, [])

    def test_gateway_error_does_not_export_key(self):
        error = urllib.error.HTTPError('https://example.invalid/v1', 400, 'bad request', {},
            io.BytesIO(json.dumps({'error': {'message': 'credential test-key-only refused'}}).encode()))
        with patch('gateway_protocol.urllib.request.urlopen', side_effect=error):
            with self.assertRaises(urllib.error.HTTPError) as caught:
                chat_completions_request('test-key-only', [], [], self.config)
        self.assertNotIn('test-key-only', json.dumps(caught.exception.gateway_error))

    def test_truncation_retains_safe_visible_metadata(self):
        with patch('gateway_protocol.urllib.request.urlopen', return_value=self.response('length',
                {'role':'assistant','content':'visible partial','reasoning_content':'hidden'})):
            with self.assertRaises(ValueError) as caught:
                chat_completions_request('test-key-only',[],[],self.config)
        exc=caught.exception
        self.assertEqual(exc.response_metadata['finish_reason'],'length')
        self.assertEqual(exc.response_metadata['status'],200)
        self.assertEqual(exc.visible_response['content'],'visible partial')
        self.assertNotIn('reasoning_content',exc.visible_response)


if __name__ == '__main__':
    unittest.main()
