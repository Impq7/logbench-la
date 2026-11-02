"""Current single-session contract tests. All inputs are synthetic fixtures."""
import gzip
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'scripts'))
from test_official_exfil_audit import enrich, runner
from agentdojo_to_atif import convert, validate_atif
from validate_official_session import trajectory_for_plan, validate_run
from session_storage import load_model_inputs, verify_official_packed


def fixture(root):
    run = root/'run'
    path = run/'openai-compatible/slack/user_task_0/asb_concat/injection_task_4.json'
    path.parent.mkdir(parents=True)
    plan = {'suite':'slack','benchmark_version':'v1','user_tasks':['user_task_0'],
            'injection_tasks':['injection_task_4'],'attack':'asb_concat','model_id':'synthetic'}
    trace = {'suite_name':'slack','benchmark_version':'v1','user_task_id':'user_task_0',
             'injection_task_id':'injection_task_4','attack_type':'asb_concat','error':None,
             'utility':True,'security':False,'messages':[{'role':'user','content':'synthetic task'}]}
    path.write_text(json.dumps(trace))
    (run/'00_plan.json').write_text(json.dumps(plan))
    (run/'report.json').write_text(json.dumps({'run_id':'synthetic-session','ready':True,
        'task_started_at':100,'task_ended_at':101,'task_started_monotonic':10,
        'task_ended_monotonic':11,'clock_origin':{'monotonic':9}}))
    (run/'capture').mkdir()
    (run/'capture/network.pcap').write_bytes(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
    return run, path, plan


class AtifTests(unittest.TestCase):
    def test_result_attaches_to_its_call_not_latest_step(self):
        trace = convert({'messages':[
            {'role':'assistant','content':'','tool_calls':[{'id':'a','function':'f','args':{}}]},
            {'role':'assistant','content':'','tool_calls':[{'id':'b','function':'f','args':{}}]},
            {'role':'tool','tool_call_id':'a','content':'A'},
            {'role':'tool','tool_call_id':'b','content':'B'}]})
        validate_atif(trace)
        self.assertEqual(trace['steps'][0]['observation']['results'][0]['content'],'A')
        self.assertEqual(trace['steps'][1]['observation']['results'][0]['content'],'B')

    def test_orphan_missing_and_duplicate_calls_fail(self):
        call={'role':'assistant','content':'','tool_calls':[{'id':'a','function':'f','args':{}}]}
        for messages in [[{'role':'tool','tool_call_id':'a','content':'x'}],
                         [call,{'role':'assistant','content':'done'}],[call,call]]:
            with self.subTest(messages=messages), self.assertRaises(ValueError):
                convert({'messages':messages})

    def test_official_loop_tail_keeps_unexecuted_calls_without_fake_results(self):
        trace=convert({'messages':[{'role':'assistant','content':'','tool_calls':[
            {'id':'pending','function':'f','args':{}}]}]})
        validate_atif(trace)
        self.assertEqual(trace['steps'][0]['tool_calls'][0]['tool_call_id'],'pending')
        self.assertNotIn('observation',trace['steps'][0])


class PublicationTests(unittest.TestCase):
    def test_append_plan_preserves_original_freeze(self):
        with tempfile.TemporaryDirectory() as tmp:
            dataset=Path(tmp)/'dataset'
            original={'run_dirs':['original-run']}
            enrich.write_frozen(dataset, original)
            frozen=(dataset/'manifest/frozen.json').read_bytes()
            extra={'plan':{'extension_id':'extra'},'run_dirs':['new-run']}
            enrich.write_frozen(dataset, extra)
            enrich.write_frozen(dataset, extra)
            self.assertEqual((dataset/'manifest/frozen.json').read_bytes(),frozen)
            self.assertEqual(len(enrich.frozen_cohorts(dataset)),2)
            with self.assertRaises(ValueError):
                enrich.write_frozen(dataset,dict(extra,run_dirs=['different-run']))
            with self.assertRaises(ValueError):
                enrich.write_frozen(dataset,{'plan':{'extension_id':'duplicate'},'run_dirs':['original-run']})
            enrich.write_frozen(dataset,dict(original,source_hashes={'scripts/agentdojo_to_atif.py':'packing-fix'}))
            self.assertEqual((dataset/'manifest/frozen.json').read_bytes(),frozen)
            self.assertEqual(len(list((dataset/'manifest/packing-revisions').glob('*.json'))),1)
            with self.assertRaises(ValueError):
                enrich.write_frozen(dataset,dict(original,source_hashes={'scripts/agentdojo_official_run.py':'changed-runtime'}))

    def test_multiple_or_mismatched_trajectories_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            run,path,plan=fixture(Path(tmp))
            trajectory_for_plan(run,plan)
            bad=dict(plan,user_tasks=['user_task_1'])
            with self.assertRaises(ValueError): trajectory_for_plan(run,bad)
            path.with_name('another.json').write_bytes(path.read_bytes())
            with self.assertRaises(ValueError): trajectory_for_plan(run,plan)

    def test_no_qa_no_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            run,_,_=fixture(Path(tmp))
            with self.assertRaises(ValueError): validate_run(run)

    def test_atomic_publication_full_atif_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            run,path,_=fixture(root)
            original=path.read_bytes()
            dataset=root/'dataset'
            plan={'run_dirs':[str(run.resolve())],'seed':7}
            enrich.write_frozen(dataset,plan)
            with self.assertRaises(ValueError): enrich.write_frozen(dataset,dict(plan,seed=8))
            meta=enrich.build_meta(run,'synthetic','slack')
            quality={'revision':'official-single-task-r2','passed':True,
                     'coverage_T':'OK','coverage_E':'OK','coverage_N':'valid_empty'}
            with patch.object(enrich,'validate_run',return_value=quality), patch.object(enrich,'enrich_endpoint',return_value=[]):
                enrich.pack_into_dataset(run,dataset,meta)
            dest=dataset/'sessions/synthetic-session'
            self.assertTrue(verify_official_packed(dest)['passed'])
            with open(dest/'model_inputs/T.atif.json','rt') as stream:
                atif=json.load(stream)
            self.assertTrue((dest/'model_inputs/T.trajectory.jsonl').is_file())
            self.assertTrue((dest/'model_inputs/N.network.events.jsonl').is_file())
            self.assertFalse((dest/'model_inputs/T.trajectory.jsonl.gz').exists())
            self.assertFalse((dest/'model_inputs/N.network.events.jsonl.gz').exists())
            self.assertEqual(load_model_inputs(dest)['T'],atif['steps'])
            self.assertEqual(path.read_bytes(),original)
            self.assertEqual(json.loads((dataset/'manifest/selection_summary.json').read_text())['published'],1)
            with self.assertRaises(FileExistsError): enrich.pack_into_dataset(run,dataset,meta)
            self.assertEqual(path.read_bytes(),original)

    def test_failed_pack_keeps_original_raw(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            run,path,_=fixture(root)
            dataset=root/'dataset'
            enrich.write_frozen(dataset,{'run_dirs':[str(run.resolve())]})
            meta=enrich.build_meta(run,'synthetic','slack')
            with patch.object(enrich,'validate_run',side_effect=ValueError('sensor failure')):
                with self.assertRaises(ValueError): enrich.pack_into_dataset(run,dataset,meta)
            self.assertTrue(path.exists())
            self.assertFalse((dataset/'sessions/synthetic-session').exists())


class OfficialExecutionTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform=='linux','OpenAI SDK available in official image')
    def test_hunyuan_wire_omits_reasoning_parameters(self):
        import httpx
        import openai
        from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
        from agentdojo.functions_runtime import FunctionsRuntime
        requests=[]
        def handle(request):
            requests.append(json.loads(request.content))
            return httpx.Response(200,json={'id':'fixture','created':0,'model':'hunyuan-chat',
                'object':'chat.completion','choices':[{'index':0,'finish_reason':'stop',
                'message':{'role':'assistant','content':'OK'}}]})
        client=openai.OpenAI(base_url='https://fixture.invalid/v1',api_key='synthetic',
            http_client=httpx.Client(transport=httpx.MockTransport(handle)),max_retries=0)
        try:
            llm=OpenAILLM(client,'hunyuan-chat')
            runner.use_hunyuan_text_messages(llm)
            llm.query('fixture',FunctionsRuntime([]),messages=[
                {'role':'system','content':[{'type':'text','content':'fixture system'}]},
                {'role':'user','content':[{'type':'text','content':'OK'}]}])
        finally:
            client.close()
        self.assertFalse({'reasoning_effort','thinking','enable_thinking'} & requests[0].keys())
        self.assertTrue(all(isinstance(m['content'],str) for m in requests[0]['messages']))

    def test_hunyuan_only_changes_wire_content_without_mutating_history(self):
        messages=[{'role':'developer','content':[{'type':'text','text':'system'}]},
            {'role':'assistant','content':None,'tool_calls':[{'id':'call-a','type':'function',
                'function':{'name':'echo','arguments':'{}'}}]},
            {'role':'tool','tool_call_id':'call-a','content':[{'type':'text','text':'OK'}]}]
        original=json.loads(json.dumps(messages))
        create=Mock(return_value='completion')
        llm=SimpleNamespace(client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create))))
        runner.use_hunyuan_text_messages(llm)
        result=llm.client.chat.completions.create(model='hunyuan-chat',messages=messages,tool_choice='auto')
        self.assertEqual(result,'completion')
        sent=create.call_args.kwargs
        self.assertEqual([m['content'] for m in sent['messages']],['system','','OK'])
        self.assertEqual(sent['messages'][1]['tool_calls'],original[1]['tool_calls'])
        self.assertEqual(sent['messages'][2]['tool_call_id'],'call-a')
        self.assertEqual(messages,original)

    @unittest.skipUnless(sys.platform=='linux','Official engine available in project image')
    def test_low_reasoning_reaches_official_request(self):
        from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
        from agentdojo.functions_runtime import FunctionsRuntime
        from openai.types.chat import ChatCompletion
        client=Mock()
        client.chat.completions.create.return_value=ChatCompletion.model_validate({
            'id':'synthetic','created':0,'model':'synthetic','object':'chat.completion',
            'choices':[{'index':0,'finish_reason':'stop','message':{'role':'assistant','content':'OK'}}]})
        llm=OpenAILLM(client,'synthetic')
        with tempfile.TemporaryDirectory() as tmp, patch('agentdojo.agent_pipeline.agent_pipeline.get_llm',return_value=llm):
            runner.prepare_task({'suite':'slack','benchmark_version':'v1','user_tasks':['user_task_0'],
                'attack':'none','model_id':'synthetic','logdir':tmp,'reasoning_effort':'low'})
            llm.query('synthetic',FunctionsRuntime([]),messages=[{'role':'user','content':[{'type':'text','content':'OK'}]}])
        self.assertEqual(client.chat.completions.create.call_args.kwargs['reasoning_effort'],'low')

    @unittest.skipUnless(sys.platform=='linux','Official engine available in project image')
    def test_reuses_official_single_task_without_utility_model_run(self):
        from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
        from agentdojo.task_suite.load_suites import get_suite
        suite=get_suite('v1','slack')
        pipeline=SimpleNamespace(name='openai-compatible')
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(AgentPipeline,'from_config',return_value=pipeline), \
             patch('agentdojo.benchmark.run_task_with_injection_tasks',return_value=({},{})) as task, \
             patch('agentdojo.benchmark.benchmark_suite_with_injections',side_effect=AssertionError('suite preflight forbidden')):
            execute=runner.prepare_task({'suite':'slack','benchmark_version':'v1','user_tasks':['user_task_0'],
                'injection_tasks':['injection_task_4'],'attack':'asb_concat','model_id':'synthetic','logdir':tmp})
            task.assert_not_called()
            execute()
            task.assert_called_once()
            self.assertEqual(task.call_args.args[6],['injection_task_4'])


class RepresentationTests(unittest.TestCase):
    @unittest.skipIf(sys.platform=='linux','Detector runtime is the existing Windows project runtime')
    def test_timing_only_interface_and_tcp_directions(self):
        from logbench import runtime
        from logbench.represent import materialize, flow_direction
        from logbench.artifacts import save, seal, rows
        initiators={}
        packet={'timestamp':100.5,'length':60,'network_protocol':'TCP','protocol':6,
                'src':'1.1.1.1','dst':'2.2.2.2','src_port':50000,'dst_port':443,'tcp_flags':2}
        reverse=dict(packet,src=packet['dst'],dst=packet['src'],src_port=443,dst_port=50000,tcp_flags=18)
        self.assertEqual(flow_direction(packet,initiators),'c2s')
        self.assertEqual(flow_direction(reverse,initiators),'s2c')
        self.assertEqual(flow_direction(dict(packet,tcp_flags=16),initiators),'c2s')
        self.assertEqual(flow_direction(reverse,{}),'unknown')
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)
            source=out/'01_contract/synthetic'
            model=source/'model_inputs'
            model.mkdir(parents=True)
            values={'T.trajectory.jsonl.gz':[{'step_id':1,'source':'user','message':'fixture'}],
                'E.endpoint.events.jsonl.gz':[{'observation_role':'task','relative_timestamp':1.5,
                    'arrival_relative_timestamp':1.5,'eventName':'openat'}],
                'N.network.events.jsonl.gz':[packet,reverse]}
            for name,records in values.items():
                with gzip.open(model/name,'wt') as stream:
                    for row in records: stream.write(json.dumps(row)+'\n')
            save(source/'timing.json',{'task_started_at':100,'task_ended_at':101,
                'task_started_relative':1,'task_ended_relative':2})
            seal(out/'01_contract')
            materialize(out,[{'canonical':'01_contract/synthetic','session_id':'synthetic'}])
            self.assertEqual([r['flow_direction'] for r in rows(out/'03_represent/synthetic/N.jsonl')],['c2s','s2c'])
            self.assertFalse((source/'labels').exists())


if __name__=='__main__':
    unittest.main(verbosity=2)
