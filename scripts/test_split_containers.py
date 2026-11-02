"""Topology, business/admin boundary, truncation and two-role E association tests."""
import copy
import gzip
import io
import json
import math
from pathlib import Path
from types import SimpleNamespace
import tempfile
import sys
import unittest
from unittest.mock import patch

from split_agent_worker import run as run_agent, tool_call
from validate_split_session import check_topology, annotate_endpoint
from development_features import extract
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from logbench.represent import project_e


def topology():
    return {'roles':{
        'agent':{'container_id':'a','mount_namespace':10,'network_namespace':20,'networks':{'session':'10.3.0.2','bridge':'10.2.0.2'},
                 'privileged':False,'cap_drop':['ALL'],'port_bindings':{},'security_opt':['no-new-privileges']},
        'backend':{'container_id':'b','mount_namespace':11,'network_namespace':21,'networks':{'session':'10.3.0.3'},
                   'privileged':False,'cap_drop':['ALL'],'port_bindings':{},'security_opt':['no-new-privileges']}},
        'business_network':{'Internal':True,'Containers':{'a':{},'b':{}}},'business_network_name':'session',
        'backend_ip':'10.3.0.3','agent_business_ip':'10.3.0.2','agent_business_interface':'eth1','agent_api_interface':'eth0'}


class SplitTests(unittest.TestCase):
    def test_endpoint_representation_preserves_backend_process_role(self):
        row={'relative_timestamp':1,'arrival_relative_timestamp':2,'processName':'python','eventName':'read',
             'returnValue':1,'container_role':'backend'}
        p=project_e(row)
        self.assertEqual(p['role'],'backend')
        self.assertEqual(p['process'],'python')
        self.assertEqual(p['process_class'],'python_runtime')

    def test_legacy_collection_entry_stops_before_any_subprocess(self):
        from collect_native_development import main
        with patch('subprocess.run') as external:
            with self.assertRaisesRegex(RuntimeError,'Loopback collection retired'):
                main()
        external.assert_not_called()

    def test_features_keep_two_container_processes_and_do_not_sum_verification_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)
            def write(name,values):
                mapping={'trajectory.jsonl':'T.trajectory.jsonl.gz','endpoint.events.jsonl':'E.endpoint.events.jsonl.gz','network.events.jsonl':'N.network.events.jsonl.gz'}
                target=folder/'01_model_inputs'/mapping[name]
                target.parent.mkdir(exist_ok=True)
                with gzip.open(target,'wt',encoding='utf-8') as stream:
                    stream.write(''.join(json.dumps(v)+'\n' for v in values))
            write('trajectory.jsonl',[{'role':'user','timestamp':1},{'role':'assistant','timestamp':3,'content':'ok'}])
            write('endpoint.events.jsonl',[{'timestamp':2e9,'eventName':'read','processEntityId':7,
                'stable_process_id':role+':7','observation_role':'task'} for role in ('agent','backend')])
            packets=[{'timestamp':2,'length':60,'capture':capture,'primary_N':True,'interface':interface}
                for capture,interface in [('network_api','eth0'),('network_tools','eth1')]]
            packets.append(dict(packets[-1],length=9999,capture='network_backend',primary_N=False))
            write('network.events.jsonl',packets)
            result=extract(folder)
            self.assertAlmostEqual(result['E_process_count'],math.log1p(2))
            self.assertAlmostEqual(result['N_network_tools_packets'],math.log1p(1))
            self.assertAlmostEqual(result['N_network_tools_bytes'],math.log1p(60))

    def test_separate_containers_namespaces_and_private_peers(self):
        self.assertEqual(check_topology(topology()),[])
        for field in ('container_id','mount_namespace','network_namespace'):
            value=topology()
            value['roles']['backend'][field]=value['roles']['agent'][field]
            self.assertIn('shared_'+field,check_topology(value))

    def test_backend_egress_and_unexpected_peer_rejected(self):
        value=topology()
        value['roles']['backend']['networks']['bridge']='10.2.0.3'
        self.assertIn('unexpected_app_network_membership',check_topology(value))
        value=topology()
        value['business_network']['Containers']['other']={}
        self.assertIn('unexpected_peer_in_session_network',check_topology(value))

    def test_loopback_and_shared_interface_rejected(self):
        value=topology()
        value['backend_ip']='127.0.0.1'
        self.assertIn('backend_not_distinct_routed_peer',check_topology(value))
        value=topology()
        value['agent_business_interface']='eth0'
        self.assertIn('tool_and_API_interfaces_not_distinct',check_topology(value))
        with self.assertRaisesRegex(ValueError,'distinct container'):
            tool_call({'backend_ip':'127.0.0.1','backend_port':8080},'read_file',{},'call')

    def test_no_admin_or_truth_keys_allowed_in_business_response(self):
        class FakeConnection:
            def __init__(self,*args,**kwargs):
                self.sock=SimpleNamespace(getsockname=lambda:('10.3.0.2',1234),getpeername=lambda:('10.3.0.3',8080))
            def connect(self): pass
            def request(self,*args,**kwargs): pass
            def close(self): pass
            def getresponse(self):
                return SimpleNamespace(status=200,read=lambda:json.dumps({'content':'ok','error':None,'evaluation':{'y_harm':1}}).encode())
        with patch('split_agent_worker.http.client.HTTPConnection',FakeConnection):
            with self.assertRaisesRegex(ValueError,'truth/metadata'):
                tool_call({'backend_ip':'10.3.0.3','backend_port':8080},'read_file',{},'call')

    def config(self):
        return {'session_id':'session','clock_origin':{'monotonic':0},'tools':[],'prompt':'visible request',
            'model_requested':'fixture','max_output_tokens':4096,'api_key':'synthetic-unit-key'}

    def test_truncated_response_keeps_visible_fragment_and_executes_no_tools(self):
        def transport(*args):
            exc=ValueError('Incomplete response')
            exc.response_metadata={'status':200,'finish_reason':'length'}
            exc.visible_response={'content':'partial','tool_calls':[{'id':'not-executable'}]}
            raise exc
        output=io.StringIO()
        with patch('sys.stdout',output),patch('split_agent_worker.tool_call') as mock:
            run_agent(self.config(),transport=transport)
        mock.assert_not_called()
        frames=[json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(frames[-1]['record']['termination'],'error')
        self.assertEqual(frames[-1]['record']['requests'][0]['finish_reason'],'length')
        self.assertTrue(any(f['kind']=='trajectory' and f['record'].get('status')=='incomplete_not_executed' for f in frames))
        self.assertNotIn('synthetic-unit-key',output.getvalue())

    def test_agent_uses_remote_tool_client_and_exports_no_state(self):
        def transport(key,history,tools,config):
            calls=[] if len(history)>2 else [{'id':'c1','function':{'name':'get_balance','arguments':'{}'}}]
            history.append({'role':'assistant','content':'visible'})
            return {'collection_metadata':{'status':200,'finish_reason':'tool_calls' if calls else 'stop'}},200,{'content':'visible','tool_calls':calls}
        output=io.StringIO()
        with patch('sys.stdout',output),patch('split_agent_worker.tool_call',return_value=({'content':'10','error':None},{'protocol':6})) as mock:
            run_agent(self.config(),transport=transport)
        mock.assert_called_once()
        frames=[json.loads(line) for line in output.getvalue().splitlines()]
        final=frames[-1]['record']
        self.assertEqual(final['termination'],'completed')
        self.assertFalse({'evaluation','pre_state','post_state','oracle','receipts'}.intersection(final))
        self.assertFalse(final['state_or_oracle_in_agent'])

    def test_same_pid_in_different_containers_has_distinct_stable_identity(self):
        report={'run_id':'s','clock_origin':{'timestamp':1,'monotonic':1},'roles':{'backend':{'service_pid':7}}}
        raw=[{'timestamp':2000000000,'processEntityId':9,'parentEntityId':0,'eventName':'read','processId':7,
              'returnValue':1,'args':[{'name':'fd','value':3}]}]
        arrivals=[{'arrival_time':2,'arrival_monotonic':2}]
        start,end={'worker_pid':7,'timestamp':1},{'timestamp':3}
        a=annotate_endpoint(raw,arrivals,'agent',report,[],start,end)[0]
        b=annotate_endpoint(raw,arrivals,'backend',report,[],start,end)[0]
        self.assertNotEqual(a['stable_process_id'],b['stable_process_id'])
        self.assertEqual(b['container_role'],'backend')

    def test_stdout_telemetry_is_excluded_but_backend_write_retained(self):
        report={'run_id':'s','clock_origin':{'timestamp':1,'monotonic':1},'roles':{'backend':{'service_pid':7}}}
        raw=[{'timestamp':2000000000,'processEntityId':9,'parentEntityId':0,'eventName':'write','processId':7,
              'returnValue':1,'args':[{'name':'fd','value':fd}]} for fd in (1,5)]
        output=annotate_endpoint(raw,[{'arrival_time':2,'arrival_monotonic':2}]*2,'backend',report,[],{'worker_pid':7,'timestamp':1},{'timestamp':3})
        self.assertEqual([r['observation_role'] for r in output],['collector_io','task'])


if __name__=='__main__':
    unittest.main()
