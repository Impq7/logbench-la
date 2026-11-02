import io
import json
import unittest

from gateway_protocol import completed_sse
from validate_sensor_contract import loss_values


class Contracts(unittest.TestCase):
    def test_completed_stream_stops_without_waiting_for_disconnect(self):
        event = {'type': 'response.completed', 'response': {'status': 'completed', 'output': []}}
        def stream():
            yield ('data: ' + json.dumps(event) + '\n').encode()
            yield b'\n'
            raise AssertionError('Must not wait for socket close after completion')
        self.assertEqual(completed_sse(stream())['status'], 'completed')

    def test_truncated_stream_is_not_success(self):
        with self.assertRaises(ValueError):
            completed_sse(io.BytesIO(b'data: {"type":"response.created"}\n\n'))

    def test_error_stream_is_not_success(self):
        with self.assertRaises(ValueError):
            completed_sse(io.BytesIO(b'data: {"type":"response.failed"}\n\n'))

    def test_done_without_completed_is_not_success(self):
        with self.assertRaises(ValueError):
            completed_sse(io.BytesIO(b'data: [DONE]\n\n'))

    def test_unknown_loss_remains_unknown(self):
        self.assertEqual(loss_values('# HELP tracee_ebpf_lostevents_total missing\n'), {})
        self.assertEqual(loss_values('tracee_ebpf_lostevents_total 3\n'),
                         {'tracee_ebpf_lostevents_total': 3.0})


if __name__ == '__main__':
    unittest.main()
