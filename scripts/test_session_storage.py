import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from session_storage import (pack_official_session, verify_official_packed,
                             SessionStore, load_model_inputs, rebuild_catalog,
                             OFFICIAL_REVISION)


class OfficialStorageTests(unittest.TestCase):
    """Tests for the official-engine three-directory layout (raw/model_inputs/labels)."""

    def fixture(self, folder, sid='official-x'):
        folder.mkdir(parents=True)
        # derived flat files (what enrich.build_flat_session writes)
        (folder / 'trajectory.jsonl').write_text('{"step_id":1,"source":"user","message":"hi"}\n')
        (folder / 'endpoint.events.jsonl').write_text('{"eventName":"read"}\n')
        (folder / 'network.events.jsonl').write_text('{"length":60}\n')
        (folder / 'report.json').write_text(json.dumps({
            'run_id': sid, 'ready': True, 'endpoint': {'loss_zero': True},
            'network': {'pcap_bytes': 100}, 'emodality': {'span': {'count': 1}}}))
        (folder / 'labels.json').write_text(json.dumps({'session_id': sid, 'y_attempt': 1, 'y_harm': 0}))
        (folder / 'session_manifest.csv').write_text('session_id,scenario\n%s,Slack\n' % sid)
        (folder / 'labels.csv').write_text('session_id,y_attempt,y_harm\n%s,1,0\n' % sid)
        # raw/ native run_dir (byte-identical retention)
        raw = folder / 'raw'
        raw.mkdir()
        (raw / '00_plan.json').write_text('{"attack":"asb_concat"}')
        (raw / 'report.json').write_text(json.dumps({'run_id': sid}))
        (raw / 'capture').mkdir()
        (raw / 'capture' / 'network.pcap').write_bytes(b'pcap-bytes')
        (raw / 'console.log').write_text('log line\n')
        return sid

    def _meta(self, sid):
        return {'run_id': sid, 'lineage': 'asb-slack-user_task_0', 'scenario': 'Slack', 'backbone': 'deepseek'}

    def test_pack_produces_three_directories_and_verifies(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d) / 's'
            sid = self.fixture(folder)
            res = pack_official_session(folder, self._meta(sid))
            self.assertTrue(res['passed'])
            self.assertEqual({p.name for p in folder.iterdir()}, {'raw', 'model_inputs', 'labels'})
            self.assertEqual(verify_official_packed(folder)['passed'], True)

    def test_load_model_inputs_reads_three_modalities_only(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d) / 's'
            sid = self.fixture(folder)
            pack_official_session(folder, self._meta(sid))
            values = load_model_inputs(folder)
            self.assertEqual(set(values), {'T', 'E', 'N'})
            # a stray extra file in model_inputs is rejected
            (folder / 'model_inputs' / 'labels.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'Unexpected or missing'):
                load_model_inputs(folder)

    def test_session_store_reads_labels_and_rejects_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d) / 's'
            sid = self.fixture(folder)
            pack_official_session(folder, self._meta(sid))
            store = SessionStore(folder)
            self.assertEqual(store.json('labels.json')['y_attempt'], 1)
            self.assertEqual(store.json('report.json')['run_id'], sid)
            with self.assertRaisesRegex(ValueError, 'Unknown label file'):
                store.json('nope.json')

    def test_model_loader_never_uses_audit_store(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d) / 's'
            sid = self.fixture(folder)
            pack_official_session(folder, self._meta(sid))
            with patch('session_storage.SessionStore', side_effect=AssertionError('QA access forbidden')):
                values = load_model_inputs(folder)
            self.assertEqual(set(values), {'T', 'E', 'N'})

    def test_corrupt_file_rejected_by_verification(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d) / 's'
            sid = self.fixture(folder)
            pack_official_session(folder, self._meta(sid))
            (folder / 'model_inputs' / 'T.trajectory.jsonl.gz').write_bytes(b'corrupt')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                verify_official_packed(folder)

    def test_catalog_aggregates_sessions(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for sid in ('s1', 's2'):
                folder = root / 'sessions' / sid
                self.fixture(folder, sid=sid)
                pack_official_session(folder, self._meta(sid))
            result = rebuild_catalog(root)
            self.assertEqual(result, {'sessions': 2, 'labels': 2})
            with (root / 'manifest' / 'labels.csv').open(encoding='utf-8-sig') as stream:
                labels = list(csv.DictReader(stream))
            self.assertEqual(sorted(r['session_id'] for r in labels), ['s1', 's2'])


if __name__ == '__main__':
    unittest.main()
