"""Counterexamples for new-batch lineage and concurrent namespace isolation."""
import unittest
from split50_training import assert_lineages, audit_overlap


class FreshBatchTests(unittest.TestCase):
    def test_repeated_lineage_cannot_cross_frozen_split(self):
        slots = [dict(slot_id=str(i), lineage='source', split='train') for i in range(2)]
        samples = [dict(slot_id=str(i), group='source', split='train') for i in range(2)]
        assert_lineages(samples, slots)
        samples[1]['split'] = 'test'
        with self.assertRaises(ValueError):
            assert_lineages(samples, slots)

    def test_duplicate_and_unplanned_slots_rejected(self):
        slots = [dict(slot_id=str(i), lineage='source', split='train') for i in range(2)]
        samples = [dict(slot_id='0', group='source', split='train') for _ in range(2)]
        with self.assertRaises(ValueError):
            assert_lineages(samples, slots)
        samples[1]['slot_id'] = 'old-unplanned-session'
        with self.assertRaises(ValueError):
            assert_lineages(samples, slots)

    def test_real_overlap_requires_all_four_namespaces_distinct(self):
        def report(prefix):
            return dict(run_id=prefix, task_started_at=1, task_ended_at=3, business_network_name=prefix,
                roles={r: {k: prefix + r for k in ('container_id', 'mount_namespace', 'network_namespace')} for r in ('agent', 'backend')})
        reports = [report('a'), report('b')]
        self.assertEqual(audit_overlap(reports)[0]['overlap_seconds'], 2)
        reports[1]['roles']['backend']['network_namespace'] = 'aagent'
        with self.assertRaises(ValueError):
            audit_overlap(reports)

    def test_sequential_intervals_are_not_concurrency_evidence(self):
        with self.assertRaises(ValueError):
            audit_overlap([dict(task_started_at=0, task_ended_at=1), dict(task_started_at=1, task_ended_at=2)])


if __name__ == '__main__':
    unittest.main()
