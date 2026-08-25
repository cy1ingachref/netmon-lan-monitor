"""tests/test_cli.py - graceful handling when capture backends fail.

Proves the High-severity fix: when BOTH tshark and scapy fail, cmd_sniff must
not crash on `for rec in records` / `run_detections(None)`. We mock capture
to return None (simulating "no backend") and assert the pipeline degrades
gracefully to an empty record set (no exception).
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netmon import cli


class _Args:
    seconds = 5
    with_demo = False
    whole_lan = False
    arp_spoof = False
    enrich = False
    iface = None
    export = None
    fetch_router = False
    router_user = "admin"
    router_pass = "admin"
    vendor = None
    ip_filter = None
    port = 8080


class TestGracefulNoBackend(unittest.TestCase):
    def test_none_records_does_not_crash(self):
        # Simulate BOTH backends unavailable: tshark_path() -> None (skip),
        # scapy_sniff returns None (failure). records must end as [].
        args = _Args()
        with mock.patch.object(cli.capture, "tshark_path", return_value=None), \
             mock.patch.object(cli.capture, "scapy_sniff", return_value=None), \
             mock.patch.object(cli.capture, "clear_artifacts"), \
             mock.patch.object(cli.discover, "detect_self",
                               return_value=("192.168.1.5", "24", "Wi-Fi",
                                              "192.168.1.1", "192.168.1.0/24")), \
             mock.patch.object(cli.discover, "discover", return_value={}), \
             mock.patch.object(cli.discover, "merge_router_devices", return_value={}), \
             mock.patch.object(cli.detect, "learn_baseline"), \
             mock.patch.object(cli.detect, "run_detections", return_value=[]), \
             mock.patch.object(cli.reportmod, "write_report",
                               return_value="netmon_report.html") as wr:
            # should not raise
            cli.cmd_sniff(args)
            # write_report must have been called with a LIST (not None)
            self.assertIsInstance(wr.call_args.args[1], list)


if __name__ == "__main__":
    unittest.main()
