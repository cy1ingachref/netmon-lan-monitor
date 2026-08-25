"""tests/test_report.py - report.py HTML export smoke tests (no NIC needed)."""

import os, sys, unittest
import tempfile
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import netmon.report as report


class TestReport(unittest.TestCase):
    def test_empty_input_valid_html(self):
        """Empty devices/records/alerts must still produce valid HTML with
        graceful 'no data' fallbacks (no crash, no broken markup)."""
        path = report.write_report({}, [], [], capture_mode="host-only", path=None)
        self.assertTrue(os.path.exists(path))
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
        self.assertIn("<html", html)
        self.assertIn("</html>", html)
        self.assertIn("no devices", html.lower())

    def test_with_devices_no_crash(self):
        devs = {"192.168.1.5": {"ip": "192.168.1.5", "mac": "AA:BB:CC:DD:EE:FF",
                                "vendor": "Apple, Inc.", "os": "?"}}
        path = report.write_report(devs, [], [], capture_mode="host-only", path=None)
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
        self.assertIn("192.168.1.5", html)
        self.assertIn("Apple, Inc.", html)

    def test_write_to_path(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "r.html")
            returned = report.write_report({}, [], [], path=out)
            self.assertEqual(returned, out)
            self.assertTrue(os.path.exists(out))
            self.assertGreater(os.path.getsize(out), 0)

    def tearDown(self):
        # write_report to default path leaves an artifact; clean it so the
        # source tree stays artifact-free for packaging.
        try:
            os.remove(report.REPORT_FILE)
        except OSError:
            pass


if __name__ == "__main__":
    unittest.main()
