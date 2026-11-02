"""Boundary tests for the smoke pipeline, not synthetic performance evidence."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / '.runtime/detectors'))
sys.path.insert(0, str(ROOT / 'scripts'))
import numpy as np
from logbench.artifacts import save, save_rows, seal, verify
from logbench.cohort import assert_group_split
from logbench.evaluate import metrics
from logbench.fusion import candidates, combine, threshold, fit
from logbench.represent import project_t, project_e, project_n, windows
from logbench.registry import registry
from packet_metadata import pcap_packets


class Boundaries(unittest.TestCase):
    def test_fit_succeeds_without_any_test_features_or_labels(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            cfg = json.loads((ROOT / 'configs/architecture-smoke.json').read_text())
            cfg['levels'] = [2]
            save(out / '00_plan/architecture-smoke.json', cfg)
            samples = [{'session_id': f'{split}-{i}', 'group': f'{split}-group', 'split': split}
                       for split in ('train', 'validation', 'test') for i in (0, 1)]
            save(out / '02_cohort/samples.json', samples)
            for split in ('train', 'validation'):
                save_rows(out / '02_cohort' / (split + '-labels.jsonl'),
                          [{'session_id': f'{split}-{i}', 'y_attempt': i} for i in (0, 1)])
                for i in (0, 1):
                    sid = f'{split}-{i}'
                    save_rows(out / '03_represent' / sid / 'T.jsonl',
                        [dict(time=1, arrival=1, role='tool', tool='read', content='alpha' if i else 'beta', arguments={})])
                    save_rows(out / '03_represent' / sid / 'E.jsonl',
                        [dict(time=1, arrival=1, event='read' if i else 'write', process='python',
                              process_class='python_runtime', role='agent', direction='read', path='/work/a',
                              path_class='workspace_temporary', result='success', sock_remote=None, sock_known=False)])
                    save_rows(out / '03_represent' / sid / 'N.jsonl',
                        [dict(time=1, arrival=1, protocol='TCP', flow_direction='client_to_service', length=80+i,
                              ip_version=4, dns_questions=0)])
            seal(out / '02_cohort')
            seal(out / '03_represent')
            # Test sessions are listed, but their feature and label files do not exist.
            fit(out, samples)
            self.assertTrue((out / '04_fit/selection.json').exists())
            self.assertFalse((out / '02_cohort/test-labels.jsonl').exists())

    def test_lineage_derivative_cannot_cross_splits(self):
        with self.assertRaisesRegex(ValueError, 'crosses splits'):
            assert_group_split([{'group': 'same', 'split': 'train'}, {'group': 'same', 'split': 'test'}])

    def test_artifacts_cannot_be_overwritten_and_tampering_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            save(path / 'evidence.json', {'value': 1})
            seal(path)
            with self.assertRaises(FileExistsError):
                save(path / 'evidence.json', {'value': 2})
            (path / 'evidence.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                verify(path)

    def test_truth_rejected_ids_never_projected(self):
        # ATIF step: a user step must not leak any label/session field.
        step = dict(step_id=1, source='user', message='visible', session_id='secret-id')
        self.assertNotIn('secret-id', json.dumps(project_t(step)))
        with self.assertRaises(ValueError):
            project_t(dict(step, y_attempt=1))

    def test_empty_modality_fails_and_windows_cover_tail(self):
        with self.assertRaises(ValueError):
            windows([])
        chunks = windows(list(range(70)))
        self.assertEqual([len(w) for w in chunks], [64, 38])
        self.assertEqual(set().union(*map(set, chunks)), set(range(70)))

    def test_raw_identity_and_destination_excluded(self):
        event = dict(relative_timestamp=1, arrival_relative_timestamp=2, processName='python', eventName='read',
                     returnValue=1, file_path='/work/a', processEntityId='sensitive-id', containerId='cid')
        self.assertNotIn('sensitive-id', json.dumps(project_e(event)))
        packet = dict(timestamp=1.5, direction='unattributed', length=90,
                      application_role='unattributed', src='10.1.1.1', session_id='secret')
        self.assertNotIn('10.1.1.1', json.dumps(project_n(packet)))

    def test_n_attribution_never_projected(self):
        packet = dict(timestamp=1.5, network_protocol='TCP',
                      length=90, src='10.1.1.1', dst='93.184.216.34', src_port=54321, dst_port=443,
                      tcp_flags=0x02, session_id='secret-session', container_role='agent',
                      application_role='tool_http', tool_call_id='tc-1', connection_id='conn-1',
                      direction='unattributed', capture='network', interface='eth0', primary_N=True)
        out = json.dumps(project_n(packet))
        for forbidden in ('secret-session', 'agent', 'tool_http', 'tc-1', 'conn-1',
                          'unattributed', '10.1.1.1'):
            self.assertNotIn(forbidden, out)
        # flow_direction is re-derived from packet fields (SYN => client->server), not the attribution column
        self.assertEqual(project_n(packet)['flow_direction'], 'c2s')
        # pure network fields are preserved
        self.assertEqual(project_n(packet)['dst_port'], 443)
        self.assertEqual(project_n(packet)['tcp_flags'], 0x02)
        # time is the raw pcap epoch timestamp, not a task-relative value
        self.assertEqual(project_n(packet)['time'], 1.5)

    def test_pure_pcap_parser_emits_no_attribution_or_hashes(self):
        # Minimal valid pcap: one Ethernet ARP frame.
        header = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        frame = b'\xff' * 6 + b'\x00\x11\x22\x33\x44\x55' + struct.pack('>H', 0x0806)
        ts_sec, ts_usec = 1600000000, 500000
        record = struct.pack('<IIII', ts_sec, ts_usec, len(frame), len(frame)) + frame
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'net.pcap'
            path.write_bytes(header + record)
            packets = pcap_packets(path)
        self.assertEqual(len(packets), 1)
        pkt = packets[0]
        # pure standard-traffic fields present
        self.assertEqual(pkt['network_protocol'], 'ARP')
        self.assertIsInstance(pkt['timestamp'], float)
        self.assertIn('record_index', pkt)
        self.assertIn('length', pkt)
        # no agent attribution, no per-packet hashes, no clock alignment
        for forbidden in ('session_id', 'container_role', 'application_role', 'connection_id',
                          'tool_call_id', 'capture', 'interface', 'primary_N', 'direction',
                          'flow_id', 'five_tuple', 'frame_sha256', 'record_sha256',
                          'relative_timestamp', 'aligned_monotonic', 'clock_uncertainty_seconds'):
            self.assertNotIn(forbidden, pkt)

    def test_search_budget_and_weight_simplex(self):
        for mask in ('T', 'TE', 'TEN'):
            grid = candidates(mask)
            self.assertLessEqual(len(grid), 24)
            for candidate in grid:
                if candidate['weights']:
                    self.assertAlmostEqual(sum(candidate['weights']), 1)
                    self.assertTrue(all(v >= 0 for v in candidate['weights']))

    def test_threshold_higher_score_means_anomaly(self):
        choice, _ = threshold(np.array([0, 1]), np.array([0., 2.]))
        self.assertEqual(choice['threshold'], 2)
        self.assertEqual(choice['FPR'], 0)
        self.assertEqual(choice['F1'], 1)

    def test_no_harm_support_is_undefined_not_zero(self):
        records = [dict(group='g', y_attempt=0, y_harm=None, alert_F1=0, score=0., probability=.1, alert_low_FPR=0)]
        result = metrics(records)
        self.assertIsNone(result['harm_conditioned_recall'])
        self.assertIsNone(result['precision'])
        self.assertIsNone(result['MCC'])
        self.assertEqual(result['unknown_harm_support'], 1)

    def test_registry_does_not_claim_unrun_methods(self):
        records = registry()
        self.assertEqual(len({r['method'] for r in records}), 23)
        self.assertEqual(sum(r['architecture_compatible'] for r in records), 119)
        self.assertTrue(all(r['runtime_support'] == 'unsupported' for r in records if r['method'] != 'LateFusion'))


if __name__ == '__main__':
    unittest.main()
