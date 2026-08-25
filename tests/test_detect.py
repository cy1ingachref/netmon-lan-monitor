"""tests/test_detect.py - detection logic (indicators + behavioral)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netmon import detect


class DetectTest(unittest.TestCase):
    def test_tor_sni(self):
        rec = {"sni": "torproject.org", "dns": "", "src": "10.0.0.5", "dst": "1.2.3.4"}
        alerts = detect.check_indicators(rec)
        self.assertTrue(any("Tor" in a["reason"] for a in alerts))

    def test_suspicious_port(self):
        rec = {"dport": 4444, "src": "10.0.0.5", "dst": "1.2.3.4"}
        alerts = detect.check_indicators(rec)
        self.assertTrue(any("Metasploit" in a["reason"] for a in alerts))

    def test_beaconing(self):
        records = [{"src": "10.0.0.5", "dst": "10.0.0.1"}] * 25
        alerts = detect.analyze_traffic(records, threshold=20)
        self.assertEqual(len(alerts), 1)


class BaselinePlaceholderMacTest(unittest.TestCase):
    """Regression guard for the HIGH-severity baseline false positive:
    a device first seen via router DHCP with an empty MAC stores vc='?';
    a later ARP-resolved real MAC must NOT trip a 'MAC spoof' alert."""
    def setUp(self):
        self._bak = detect.BASELINE_FILE
        import tempfile
        self._tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        self._tf.close()
        detect.BASELINE_FILE = self._tf.name

    def tearDown(self):
        detect.BASELINE_FILE = self._bak
        try:
            import os
            os.remove(self._tf.name)
        except OSError:
            pass

    def test_placeholder_mac_no_spoof_alert(self):
        ip, mac_known = "192.168.1.10", "9C:95:61:AA:BB:CC"
        # First scan: router listed the IP but MAC was empty -> placeholder.
        detect.learn_baseline({ip: "?"}, "192.168.1.0/24")
        # Second scan: ARP resolves the real MAC.
        alerts = detect.check_baseline({ip: mac_known}, "192.168.1.0/24")
        self.assertFalse(
            any(a["reason"].startswith("vendor class changed") for a in alerts),
            "placeholder->real MAC upgrade must NOT raise a MAC-spoof alert")


class AnalyzeThresholdTest(unittest.TestCase):
    def test_default_threshold_raised(self):
        # 30 repeats of one pair should NOT alert at default threshold=60.
        recs = [{"src": "10.0.0.5", "dst": "1.2.3.4"} for _ in range(30)]
        self.assertEqual(detect.analyze_traffic(recs), [])
        # But 80 repeats should.
        recs = [{"src": "10.0.0.5", "dst": "1.2.3.4"} for _ in range(80)]
        self.assertEqual(len(detect.analyze_traffic(recs)), 1)


class TldExactMatchTest(unittest.TestCase):
    def test_subdomain_xyz_not_flagged(self):
        rec = {"sni": "sub.xyz.google.com", "src": "10.0.0.5", "dst": "1.2.3.4"}
        alerts = detect.check_indicators(rec)
        self.assertFalse(any("uncommon TLD" in a["reason"] for a in alerts))

    def test_real_xyz_flagged(self):
        rec = {"sni": "evil.xyz", "src": "10.0.0.5", "dst": "1.2.3.4"}
        alerts = detect.check_indicators(rec)
        self.assertTrue(any("uncommon TLD" in a["reason"] for a in alerts))


if __name__ == "__main__":
    unittest.main()
