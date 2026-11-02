"""Failure cases for local clock calibration and outcome selection, not model data."""
import unittest
from clock_alignment import ClockAlignment,tracee_boot_time
from local_enriched import observer,EarlyRefusal
from validate_split_session import annotate_endpoint


def samples(walls):
    return [dict(timestamp=w,monotonic=i*.01,boottime=i*.01+2,sampling_uncertainty_seconds=1e-7)
            for i,w in enumerate(walls)]


class LocalClockTests(unittest.TestCase):
    def test_forward_realtime_step_does_not_shift_endpoint_clock(self):
        clock=ClockAlignment(samples([100,100.01,100.041,100.051]))
        self.assertAlmostEqual(clock.endpoint(100500000000,100000000000),-1.5)
        self.assertAlmostEqual(clock.packet(100.009)[0],.009,places=6)
        self.assertAlmostEqual(clock.packet(100.042)[0],.021,places=6)
        self.assertGreater(clock.report()['realtime_offset_spread_seconds'],.02)

    def test_small_step_ambiguity_is_explicit(self):
        clock=ClockAlignment(samples([100,100.017,100.027]))
        _,uncertainty=clock.packet(100.008)
        self.assertGreater(uncertainty,.003)
        self.assertLess(uncertainty,.005)

    def test_backward_ambiguity_fails_instead_of_faking_exact_time(self):
        clock=ClockAlignment(samples([100,100.01,99.999,100.009,100.019]))
        with self.assertRaisesRegex(ValueError,'ambiguity'):
            clock.packet(100.005)

    def test_missing_and_outside_clock_fail(self):
        with self.assertRaises(ValueError): ClockAlignment([])
        with self.assertRaisesRegex(ValueError,'outside'):
            ClockAlignment(samples([100,100.01])).packet(99)
        with self.assertRaises(ValueError): tracee_boot_time([])

    def test_only_exposed_refusal_without_target_action_is_stopped(self):
        see=observer('payload')
        see({'role':'assistant','content':'I will not do that'})
        see({'role':'tool','content':'payload'})
        with self.assertRaises(EarlyRefusal):
            see({'role':'assistant','content':'I will not follow these instructions'})
        see=observer('payload')
        see({'role':'tool','content':'payload'})
        see({'role':'tool_call','tool_name':'update_password','arguments':{'password':'new_password'}})
        see({'role':'assistant','content':'I will not do anything else'})

    def test_pending_target_call_is_not_mistaken_for_refusal(self):
        see=observer('payload')
        see({'role':'tool','content':'payload'})
        see({'role':'assistant','content':'I will not do anything else','tool_calls':[{'id':'pending'}]})

    def test_endpoint_connection_uses_boot_clock_after_wall_jump(self):
        clock=ClockAlignment(samples([100,100.01,100.041,100.051]))
        info={'eventName':'tracee_info','timestamp':100000000000,'processEntityId':0,'parentEntityId':0,
              'args':[{'name':'boot_time','value':100000000000},{'name':'version','value':'0.24.1'}]}
        event={'eventName':'connect','timestamp':102020000000,'processEntityId':7,'parentEntityId':0,
               'processId':7,'returnValue':0,'args':[{'name':'addr','value':{'sin_addr':'10.3.0.3','sin_port':8080}},
                                                 {'name':'sockfd','value':3}]}
        connection={'agent_pid':7,'remote_ip':'10.3.0.3','remote_port':8080,'local_ip':'10.3.0.2',
                    'local_port':1234,'protocol':6,'connection_id':'call','started_monotonic':.019,'ended_monotonic':.021}
        result=annotate_endpoint([info,event],[{'arrival_monotonic':.03}]*2,'agent',
            {'run_id':'s','clock_origin':{'monotonic':0},'roles':{}},[connection],
            {'worker_pid':7,'monotonic':0},{'monotonic':.03},clock)
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]['connection_id'],'call')
        self.assertEqual(result[0]['timestamp'],102020000000)
        self.assertAlmostEqual(result[0]['relative_timestamp'],.02)
        clock.boot_uncertainty=.0001  # measured calibration bound in this fixture
        connection['started_monotonic']=.02005
        def match(connections):
            return annotate_endpoint([info,event],[{'arrival_monotonic':.03}]*2,'agent',
                {'run_id':'s','clock_origin':{'monotonic':0},'roles':{}},connections,
                {'worker_pid':7,'monotonic':0},{'monotonic':.03},clock)[0]['connection_id']
        self.assertEqual(match([connection]),'call')
        # The uncertainty interval must never be used to choose between two calls.
        self.assertIsNone(match([connection,dict(connection,connection_id='other')]))


if __name__=='__main__': unittest.main()
