import csv
import ipaddress
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from collection_session import check_trajectory, normalize, file_open_links
from packet_metadata import decode_packet, dns_questions, pcap_packets
from development_features import compute


class PacketTests(unittest.TestCase):
    def test_ipv6_mdns_kept_with_question(self):
        dns=struct.pack('!6H',0,0,1,0,0,0)+b'\x04host\x05local\x00'+struct.pack('!HH',28,1)
        udp=struct.pack('!4H',5353,5353,8+len(dns),0)+dns
        ip=struct.pack('!IHBB',6<<28,len(udp),17,255)+ipaddress.ip_address('fe80::1').packed+ipaddress.ip_address('ff02::fb').packed+udp
        row=decode_packet(b'\x00'*12+b'\x86\xdd'+ip,1)
        self.assertEqual(row['dns_query'],['host.local'])
        self.assertEqual(row['ip_version'],6)
        self.assertEqual(row['dst_port'],5353)
        self.assertNotIn('payload',row)

    def test_arp_and_unknown_are_retained(self):
        self.assertEqual(decode_packet(b'\x00'*12+b'\x08\x06'+b'\x00'*28,1)['network_protocol'],'ARP')
        self.assertEqual(decode_packet(b'\x00'*12+b'\x88\xb5',1)['parse_status'],'unsupported_ethertype')

    def test_dns_pointer_cycle_rejected(self):
        with self.assertRaises(ValueError):
            dns_questions(struct.pack('!6H',0,0,1,0,0,0)+b'\xc0\x0c\x00\x01\x00\x01')

    def test_truncated_pcap_fails_instead_of_becoming_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'n.pcap'
            path.write_bytes(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)+struct.pack('<IIII',1,0,20,20)+b'broken')
            with self.assertRaisesRegex(ValueError,'Truncated packet data'):
                pcap_packets(path)


class CollectionTests(unittest.TestCase):
    def test_file_identity_uses_lsm_after_syscall_entry(self):
        def event(name,ts,result,**args):
            return {'eventName':name,'timestamp':ts,'returnValue':result,'hostThreadId':5,
                    'args':[{'name':k,'value':v} for k,v in args.items()]}
        events=[event('openat',10,7,pathname='relative.txt'),
                event('security_file_open',11,0,pathname='/work/relative.txt',syscall_pathname='relative.txt',dev=2,inode=40,ctime=9),
                event('openat',20,-2,pathname='missing.txt')]
        result=file_open_links(events)
        self.assertEqual(result[0]['file_path'],'/work/relative.txt')
        self.assertEqual(result[0]['file_object_id'],'2:40:9')
        self.assertNotIn(2,result)

    def trace(self):
        return [
            {'event_id':'a','role':'assistant','tool_calls':[{'id':'c1'},{'id':'c2'}],'relative_timestamp':1,'arrival_monotonic':1},
            {'event_id':'b','role':'tool_call','call_id':'c1','parent_call_id':None,'parent_event_id':'a','tool_arguments':{},'relative_timestamp':2,'arrival_monotonic':2},
            {'event_id':'c','role':'tool','call_id':'c1','relative_timestamp':3,'arrival_monotonic':3},
            {'event_id':'d','role':'tool_call','call_id':'c2','parent_call_id':None,'parent_event_id':'a','tool_arguments':{},'relative_timestamp':4,'arrival_monotonic':4},
            {'event_id':'e','role':'tool','call_id':'c2','relative_timestamp':5,'arrival_monotonic':5}]

    def test_multiple_calls_share_assistant_parent(self):
        self.assertEqual(check_trajectory(self.trace()),[])
        trace=self.trace()
        trace[3]['parent_call_id']='c1'
        self.assertIn('invalid_tool_parent',check_trajectory(trace))

    def test_missing_tool_return_blocks_gate(self):
        self.assertIn('missing_tool_result',check_trajectory(self.trace()[:-1]))

    def test_interrupted_worker_retains_prefix_and_unknown_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)
            report={'run_id':'test','source_task_lineage':'group','model_requested':'model','condition':'benign'}
            (folder/'report.json').write_text(json.dumps(report))
            prefix=json.dumps({'role':'user','content':'a visible prefix'})+'\n'
            (folder/'trajectory.jsonl').write_text(prefix)
            result=normalize(folder,{})
            self.assertFalse(result['passed'])
            self.assertEqual(result['coverage']['T']['coverage_flag'],'partial_loss')
            self.assertEqual(result['coverage']['E']['coverage_flag'],'collector_failure')
            self.assertEqual((folder/'trajectory.jsonl').read_text(),prefix)
            with (folder/'labels.csv').open(encoding='utf-8-sig') as stream:
                label=next(csv.DictReader(stream))
            self.assertEqual(label['y_harm'],'NaN')
            self.assertEqual(label['y_attempt'],'NaN')

    def test_telemetry_write_excluded_but_task_write_preserved(self):
        t=[{'role':'user','timestamp':1},{'role':'assistant','timestamp':3,'content':'ok'}]
        e=[{'timestamp':2e9,'eventName':'write','processEntityId':1,'observation_role':'task'},
           {'timestamp':2e9,'eventName':'write','processEntityId':1,'observation_role':'collector_io'}]
        n=[{'timestamp':2,'length':60,'network_protocol':'ARP'}]
        features=compute(t,e,n,n)
        import math
        self.assertEqual(features['E_event_write'],math.log1p(1))
        self.assertEqual(features['N_network_five_tuple_count'],0)


class WorkerStreamTests(unittest.TestCase):
    def run_worker(self, truncated=False):
        import hashlib, io, sys, threading
        from types import SimpleNamespace
        class Service:
            def __init__(self,*args):
                self.pre=self.env=SimpleNamespace(model_dump=lambda:{'file':'test-payload'})
                self.task=SimpleNamespace(PROMPT='visible task')
                self.server=SimpleNamespace(server_port=1234)
                self.receipts=[]
                self.state_snapshots={}
            def schemas(self): return []
            def start(self): pass
            def stop(self): pass
            def oracle(self,output,completed): return {'y_harm':0 if completed else None}
        def request(*args):
            if truncated:
                exc=ValueError('Incomplete response')
                exc.response_metadata={'status':200,'finish_reason':'length'}
                exc.visible_response={'content':'visible partial','tool_calls':[]}
                raise exc
            return {'collection_metadata':{'status':200,'finish_reason':'stop'},'reasoning_content':'hidden'},200,{'content':'done'}
        config={'session_id':'session','native_task_id':'task','native_vector':'vector','condition':'injected',
                'clock_origin':{'monotonic':0},'model_requested':'fixture','max_output_tokens':4096,
                'annotation_revision':'confirmed-payload-r1','development_revision':'test',
                'gateway_base_url':'https://example.invalid/v1','source_task_lineage':'group'}
        source=Path(__file__).with_name('native_probe_worker.py').read_text(encoding='utf-8')
        output=io.StringIO()
        namespace={'BankingService':Service,'chat_completions_request':request,'threading':threading,
                   'hashlib':hashlib,'PAYLOAD':'test-payload','COMMIT':'fixture'}
        with patch.object(sys,'stdin',io.StringIO(json.dumps(config)+'\n')),patch.object(sys,'stdout',output),patch.object(Path,'read_bytes',return_value=b'fixture'):
            exec(compile(source,'native_probe_worker.py','exec'),namespace)
        self.assertNotIn('hidden',output.getvalue())
        return [json.loads(line) for line in output.getvalue().splitlines()]

    def test_visible_prefix_and_unread_injection_attempt(self):
        frames=self.run_worker()
        self.assertEqual([f['record']['role'] for f in frames if f['kind']=='trajectory'],['system','user','assistant'])
        labels=frames[-1]['record']['evaluation']
        self.assertEqual(labels['y_attempt'],1)
        self.assertFalse(labels['exposed_injection'])
        self.assertEqual(frames[-1]['record']['termination'],'completed')

    def test_failed_response_retains_fragment_and_unknown_harm(self):
        frames=self.run_worker(truncated=True)
        partial=[f['record'] for f in frames if f['kind']=='trajectory'][-1]
        self.assertEqual(partial['content'],'visible partial')
        self.assertEqual(partial['status'],'incomplete_not_executed')
        self.assertIsNone(frames[-1]['record']['evaluation']['y_harm'])
        self.assertEqual(frames[-1]['record']['requests'][0]['finish_reason'],'length')


if __name__=='__main__':
    unittest.main()
