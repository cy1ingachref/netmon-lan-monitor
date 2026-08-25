"""tests/test_compare.py - reproducibility of the accuracy claim.

Proves netmon's dissection/detection accuracy vs the repo you sent is
reproducible (not hand-waved): run_comparison() is deterministic and the
netmon content/alert accuracy is 100%.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netmon import compare


class CompareIntegrationTest(unittest.TestCase):
    def test_run_comparison_reproducible(self):
        r1 = compare.run_comparison()
        r2 = compare.run_comparison()
        # deterministic across runs
        self.assertEqual(r1["netmon_acc"], r2["netmon_acc"])
        self.assertEqual(r1["netmon_alert_acc"], r2["netmon_alert_acc"])

    def test_netmon_accuracy_full(self):
        r = compare.run_comparison()
        # netmon recovers 100% of content-bearing packets and 100% of the
        # expected alerts (.xyz, tor, telnet) — the core accuracy claim.
        self.assertEqual(r["netmon_acc"], 100.0)
        self.assertEqual(r["netmon_alert_acc"], 100.0)


if __name__ == "__main__":
    unittest.main()
