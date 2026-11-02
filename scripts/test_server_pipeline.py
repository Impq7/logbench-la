"""Server-native cleanup counterexamples; run only in the project server venv."""
import json
from pathlib import Path
import tempfile
import unittest
from server_pipeline import cleanup_barriers


class BarrierSafetyTests(unittest.TestCase):
    def test_unknown_marker_is_retained(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            directory = base / '.staging/barrier-012345abcdef'
            directory.mkdir(parents=True)
            path = directory / 'unrecognized.ready'
            path.write_text(json.dumps({'run_id':'session'}))
            with self.assertRaises(ValueError):
                cleanup_barriers(base, {'slot-000':'session'})
            self.assertTrue(path.exists())

    def test_known_finished_marker_can_be_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            directory = base / '.staging/barrier-012345abcdef'
            directory.mkdir(parents=True)
            (directory / 'slot-000.ready').write_text(json.dumps({'run_id':'session'}))
            self.assertEqual(len(cleanup_barriers(base, {'slot-000':'session'})), 1)
            self.assertFalse(directory.exists())

    def test_symlink_directory_is_never_followed(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            (base / '.staging').mkdir()
            other = base / 'other'
            other.mkdir()
            path = other / 'slot-000.ready'
            path.write_text(json.dumps({'run_id':'session'}))
            (base / '.staging/barrier-012345abcdef').symlink_to(other, target_is_directory=True)
            with self.assertRaises(ValueError):
                cleanup_barriers(base, {'slot-000':'session'})
            self.assertTrue(path.exists())
