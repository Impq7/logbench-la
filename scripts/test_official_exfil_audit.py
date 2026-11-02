"""Focused tests; synthetic tools only, no model calls or dataset access."""
import importlib.util
import io
import json
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


exfil = load('tested_exfil', 'logbench/agentdojo_asb/exfil.py')
enrich = load('tested_enrich', 'logbench/agentdojo_asb/enrich.py')
runner = load('tested_runner', 'scripts/agentdojo_official_run.py')
coordinator = load('tested_coordinator', 'scripts/agentdojo_official_ten_coordinator.py')
receiver = load('tested_receiver', 'scripts/exfil_receiver.py')
from session_storage import load_model_inputs, pack_official_session, verify_official_packed


class SenderTests(unittest.TestCase):
    def setUp(self):
        exfil._AUDIT_RECORDS.clear()

    def test_success_records_no_body_and_does_no_file_io(self):
        tls = Mock()
        tls.recv.side_effect = [b'HTTP/1.1 200 OK\r\n\r\nOK', b'']
        context = Mock()
        context.wrap_socket.return_value.__enter__ = Mock(return_value=tls)
        context.wrap_socket.return_value.__exit__ = Mock(return_value=False)
        infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))]
        with patch.object(exfil.socket, 'getaddrinfo', return_value=infos), \
             patch.object(exfil.socket, 'create_connection'), \
             patch.object(exfil.ssl, 'create_default_context', return_value=context), \
             patch('builtins.open', side_effect=AssertionError('task-time write')), \
             patch.object(Path, 'open', side_effect=AssertionError('task-time write')):
            self.assertIsNone(exfil.fire_exfil('post_webpage', {'url':'test.invalid/path', 'content':'SECRET_BODY'}))
        row, = exfil._AUDIT_RECORDS
        self.assertTrue(row['connected'] and row['tls_established'] and row['send_completed'] and row['success'])
        self.assertEqual(row['stage'], 'complete')
        self.assertNotIn('SECRET_BODY', json.dumps(row))
        self.assertNotIn('arguments', row)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'exfil_sender.jsonl'
            exfil.write_exfil_audit(path)
            self.assertEqual(json.loads(path.read_text()), row)
            self.assertEqual(exfil._AUDIT_RECORDS, [])

    def test_connection_failure_keeps_original_tool_return(self):
        with patch.dict(sys.modules, {
            'agentdojo.functions_runtime':SimpleNamespace(Function=object),
            'logbench.agentdojo_asb.exfil':exfil,
        }):
            wrapper = load('tested_wrapper', 'logbench/agentdojo_asb/wrap.py')
        visible = {'ok':True}
        state = []
        def original(**kwargs):
            state.append(kwargs['content'])
            return visible
        tool = SimpleNamespace(name='post_webpage', dependencies={}, run=original)
        wrapper._wrap(tool)
        with patch.object(exfil.socket, 'getaddrinfo', return_value=[(0,0,0,'',('127.0.0.1',443))]), \
             patch.object(exfil.socket, 'create_connection', side_effect=ConnectionRefusedError('PRIVATE_ERROR')):
            self.assertIs(tool.run(url='test.invalid', content='body'), visible)
        self.assertEqual(state, ['body'])
        row, = exfil._AUDIT_RECORDS
        self.assertEqual((row['stage'], row['error_type']), ('connect','ConnectionRefusedError'))
        self.assertFalse(row['connected'] or row['success'])
        self.assertNotIn('PRIVATE_ERROR', json.dumps(row))

    def test_dns_failure_records_one_attempt_without_retry(self):
        with patch.object(exfil.socket, 'getaddrinfo', side_effect=socket.gaierror()) as dns, \
             patch.object(exfil.socket, 'create_connection') as connect:
            exfil.fire_exfil('post_webpage', {'url':'test.invalid'})
        dns.assert_called_once()
        connect.assert_not_called()
        self.assertEqual(exfil._AUDIT_RECORDS[0]['stage'], 'dns')


class ReceiverTests(unittest.TestCase):
    def test_complete_and_truncated_requests(self):
        head = b'POST /exfil HTTP/1.1\r\nContent-Length: 4\r\n\r\n'
        for body, complete in [(b'data',True), (b'da',False)]:
            with self.subTest(complete=complete):
                conn = Mock()
                conn.recv.side_effect = [head,body,b'']
                self.assertEqual(receiver.read_request(conn), (len(head)+len(body),complete))

    def test_timeout_does_not_claim_delivery(self):
        data = b'POST /exfil HTTP/1.1\r\nContent-Length: 4\r\n\r\nda'
        conn = Mock()
        conn.recv.side_effect = [data, socket.timeout()]
        self.assertEqual(receiver.read_request(conn), (len(data),False))

    @unittest.skipUnless(sys.platform == 'linux' and shutil.which('openssl'),
                         'TLS integration runs in the project Linux image with openssl')
    def test_real_tls_sender_and_receiver_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            with socket.socket() as probe:
                probe.bind(('127.0.0.1',0))
                port = probe.getsockname()[1]
            code = ('import sys;sys.path.insert(0,sys.argv[1]);import exfil_receiver as r;'
                    'r.HOST="127.0.0.1";r.PORT=int(sys.argv[2]);r.CERT_DIR=sys.argv[3];r.main()')
            proc = subprocess.Popen([sys.executable,'-B','-u','-c',code,str(ROOT/'scripts'),str(port),tmp],
                                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                ready = proc.stdout.readline()
                if not ready:
                    self.fail('Receiver startup failed: ' + proc.stderr.read())
                self.assertEqual(json.loads(ready)['kind'], 'receiver_ready')
                exfil._AUDIT_RECORDS.clear()
                with patch.object(exfil, 'RECEIVER_PORT',port):
                    exfil.fire_exfil('post_webpage', {'url':'localhost/path','content':'synthetic-body'})
                row, = exfil._AUDIT_RECORDS
                self.assertTrue(row['send_completed'] and row['success'])
                delivered = json.loads(proc.stderr.readline())
                self.assertTrue(delivered['complete'])
                self.assertNotIn('synthetic-body', json.dumps(delivered))
                # A second real TLS connection ends the request body early.
                context = ssl._create_unverified_context()
                with socket.create_connection(('127.0.0.1',port)) as raw:
                    with context.wrap_socket(raw,server_hostname='localhost') as tls:
                        tls.sendall(b'POST /exfil HTTP/1.1\r\nContent-Length: 9\r\n\r\nshort')
                truncated = json.loads(proc.stderr.readline())
                self.assertFalse(truncated['complete'])
            finally:
                proc.terminate()
                proc.communicate(timeout=5)


class HandoffTests(unittest.TestCase):
    def test_capture_stops_before_audit_write(self):
        order = []
        capture = Mock()
        capture.log_lines = []
        capture.terminate.side_effect = lambda: order.append('stop_N')
        capture.wait.side_effect = lambda **kw: order.append('N_stopped')
        command = io.StringIO(json.dumps({'command':'flush_exfil_audit','token':'test'}))
        class ReleaseInput:
            def readline(self):
                order.append('E_stopped_release')
                return command.readline()
        with patch.object(runner.sys,'stdin',ReleaseInput()), patch.object(runner.sys,'stdout',io.StringIO()), \
             patch.dict(sys.modules, {'logbench.agentdojo_asb.exfil':SimpleNamespace(
                 write_exfil_audit=lambda path: order.append('write_audit'))}):
                with patch.object(Path,'write_text'), patch.object(runner.shutil,'copyfile'):
                    runner.finish_capture(capture,{'logdir':'.','exfil_audit_token':'test','capture':{'output':'unused'}})
        self.assertEqual(order,['stop_N','N_stopped','E_stopped_release','write_audit'])

    def test_no_release_means_no_audit_write(self):
        write = Mock()
        with patch.object(runner.sys,'stdin',io.StringIO('')), patch.object(runner.sys,'stdout',io.StringIO()), \
             patch.dict(sys.modules, {'logbench.agentdojo_asb.exfil':SimpleNamespace(write_exfil_audit=write)}):
            with self.assertRaisesRegex(RuntimeError,'not released'):
                runner.finish_capture(None,{'logdir':'.','exfil_audit_token':'test'})
        write.assert_not_called()

    def test_real_pipe_handshake_writes_only_after_drain(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.Popen([sys.executable,'-B',str(Path(__file__).resolve()),'--handoff-child',tmp],
                                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                    text=True,encoding='utf-8')
            def drain(role,sensor):
                self.assertFalse((Path(tmp)/'exfil_sender.jsonl').exists())
                return {'loss_zero':True}
            try:
                with patch.object(coordinator,'OUT',Path(tmp)), patch.object(coordinator,'report',{},create=True), \
                     patch.object(coordinator,'drain_sensor',side_effect=drain) as stopped, \
                     patch.object(coordinator.sys,'stdout',io.StringIO()):
                    result=coordinator.collect_agent_output(proc,{'id':'synthetic'},'test')
                    self.assertTrue(result['loss_zero'])
                    self.assertEqual(coordinator.report['agent_exit_code'],0)
                    stopped.assert_called_once()
                row=json.loads((Path(tmp)/'exfil_sender.jsonl').read_text())
                self.assertEqual(row['error_type'],'gaierror')
            finally:
                if proc.poll() is None:
                    proc.kill()
                if proc.stdin.closed:
                    proc.stdin = None
                proc.communicate(timeout=5)

    def test_receiver_log_export(self):
        raw=b'{"event":"exfil_received","complete":false}\n'
        with tempfile.TemporaryDirectory() as tmp, patch.object(coordinator,'OUT',Path(tmp)), \
             patch.object(coordinator.subprocess,'run',return_value=SimpleNamespace(returncode=0,stderr=raw)):
            self.assertTrue(coordinator.save_receiver_audit('fixture-id'))
            self.assertEqual((Path(tmp)/'exfil_receiver.jsonl').read_bytes(),raw)


class LabelAndBoundaryTests(unittest.TestCase):
    def test_planned_labels_and_unknown_harm(self):
        cases=[('asb_concat',None,True,True,1), ('asb_concat',None,False,False,0),
               ('asb_concat','API error',False,True,None),('asb_concat',None,None,True,None),
               ('none',None,True,True,0),('none','API error',False,True,None)]
        for attack,error,utility,security,expected in cases:
            with self.subTest(attack=attack,error=error,utility=utility,security=security):
                result=enrich.trajectory_labels({'attack_type':attack,'error':error,'utility':utility,
                    'security':security},{'attack':attack,'lineage':'fixture'},'fixture')
                self.assertEqual(result['y_attempt'],int(attack!='none'))
                self.assertEqual(result['y_harm'],expected)
                self.assertIsNone(result['exposed_injection'])

    def test_packing_retains_raw_audits_but_excludes_model_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            run=root/'run'
            trajectory=run/'openai-compatible/slack/user_task_0/asb_concat/injection_task_0.json'
            trajectory.parent.mkdir(parents=True)
            original={'suite_name':'slack','benchmark_version':'v1','user_task_id':'user_task_0',
                      'injection_task_id':'injection_task_0','attack_type':'asb_concat','error':'API error','security':True,'utility':False,
                      'injections':{'vector':'AUDIT_ONLY_SENTINEL'},
                      'messages':[{'role':'user','content':'ordinary synthetic task'}]}
            original_bytes=json.dumps(original).encode()
            trajectory.write_bytes(original_bytes)
            (run/'report.json').write_text(json.dumps({'run_id':'synthetic-session','ready':False,
                'task_started_at':100,'task_ended_at':101,'task_started_monotonic':10,
                'task_ended_monotonic':11,'clock_origin':{'monotonic':9}}))
            (run/'00_plan.json').write_text(json.dumps({'attack':'asb_concat','user_tasks':['user_task_0'],
                'injection_tasks':['injection_task_0'],'suite':'slack','benchmark_version':'v1'}))
            for name in ['exfil_sender.jsonl','exfil_receiver.jsonl']:
                (run/name).write_text('{"audit":"AUDIT_ONLY_SENTINEL"}\n')
            (run/'capture').mkdir()
            # Empty fixture PCAP is used only to test the storage boundary, never accepted as a sample.
            (run/'capture/network.pcap').write_bytes(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
            meta={'attack':'asb_concat','lineage':'fixture','scenario':'Slack','backbone':'synthetic'}
            stage=root/'session'
            with patch.object(enrich,'enrich_endpoint',return_value=[]), patch.object(enrich,'validate_run',
                    return_value={'coverage_T':'OK','coverage_E':'OK','coverage_N':'valid_empty'}):
                _,_,_,labels=enrich.build_flat_session(run,stage,meta)
            pack_official_session(stage,meta)
            self.assertTrue(verify_official_packed(stage)['passed'])
            self.assertEqual((stage/'raw'/trajectory.relative_to(run)).read_bytes(),original_bytes)
            self.assertTrue((stage/'raw/exfil_sender.jsonl').is_file())
            self.assertTrue((stage/'raw/exfil_receiver.jsonl').is_file())
            inputs=load_model_inputs(stage)
            self.assertNotIn('AUDIT_ONLY_SENTINEL',json.dumps(inputs))
            self.assertIsNone(labels['y_harm'])
            self.assertIsNone(labels['exposed_injection'])
            self.assertEqual(labels['y_attempt'],1)
            self.assertEqual({k:labels[k] for k in ('user_task_id','injection_task_id','attack_type')},
                {'user_task_id':'user_task_0','injection_task_id':'injection_task_0','attack_type':'asb_concat'})


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--handoff-child':
        with patch.object(exfil.socket,'getaddrinfo',side_effect=socket.gaierror()):
            exfil.fire_exfil('post_webpage',{'url':'test.invalid'})
        with patch.dict(sys.modules,{'logbench.agentdojo_asb.exfil':exfil}):
            runner.finish_capture(None,{'logdir':sys.argv[2],'exfil_audit_token':'test'})
    else:
        unittest.main(verbosity=2)
