"""tests/test_discover.py - identity layer (device_key, vendor_of, cidr)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netmon import discover


class TestDeviceKey(unittest.TestCase):
    def test_question_mark_mac_uses_ip(self):
        # Bug B: a "?" MAC must NOT collide (was truthy -> key became "?")
        self.assertEqual(discover.device_key("?", "192.168.1.5"), "192.168.1.5")
        self.assertEqual(discover.device_key("?", "192.168.1.6"), "192.168.1.6")

    def test_empty_mac_uses_ip(self):
        self.assertEqual(discover.device_key("", "10.0.0.9"), "10.0.0.9")

    def test_real_mac_upper(self):
        self.assertEqual(discover.device_key("9c:95:61:xx:xx:xx", "192.168.1.7"),
                         "9C:95:61:XX:XX:XX")

    def test_two_unknown_macs_distinct(self):
        a = discover.device_key("?", "192.168.1.5")
        b = discover.device_key("?", "192.168.1.6")
        self.assertNotEqual(a, b)


class TestVendorOf(unittest.TestCase):
    def test_known_oui(self):
        # authoritative IEEE name (the tool no longer trusts guess aliases)
        self.assertEqual(discover.vendor_of("9C-95-61-11-22-33"),
                         "Hui Zhou Gaoshengda Technology Co.,LTD")

    def test_partial_mac_known(self):
        # 1C:61:B4 is the real TP-Link OUI -> IEEE registered name
        self.assertEqual(discover.vendor_of("1C:61:B4:xx:xx:xx"),
                         "TP-Link Systems Inc")

    def test_unknown_mac(self):
        # unknown OUIs get a MAC: prefix (display fallback, not a crash)
        self.assertTrue(discover.vendor_of("ZZ:ZZ:ZZ:11:22:33").startswith("MAC:"))

    def test_question_mark(self):
        self.assertEqual(discover.vendor_of("?"), "?")


class TestCidr(unittest.TestCase):
    def test_cidr_to_range_slash24(self):
        rng = discover.cidr_to_range("192.168.1.0/24")
        self.assertIsInstance(rng, list)
        self.assertIn("192.168.1.1", rng)
        self.assertIn("192.168.1.254", rng)

    def test_cidr_to_range_single(self):
        # a /32 has no host range (net+1 == bcast), so the range is empty
        rng = discover.cidr_to_range("10.0.0.5/32")
        self.assertEqual(rng, [])


class TestTagGateway(unittest.TestCase):
    def test_role_tagged(self):
        devs = {"192.168.1.1": "1C:61:B4:3F:CF:E8", "192.168.1.5": "aa:bb:cc:dd:ee:ff"}
        out = discover.tag_gateway(devs, "192.168.1.1")
        self.assertEqual(out["192.168.1.1"]["role"], "gateway")

    def test_gateway_banner_string(self):
        # returns a string (may be empty if no gateway); must not raise
        self.assertIsInstance(discover.gateway_banner(), str)


class PlaceholderMacUpgradeTest(unittest.TestCase):
    """Regression guard for the HIGH-severity duplicate-device bug: a device
    first stored with a placeholder '?' MAC (router DHCP with empty MAC) must
    be upgraded (not duplicated) when the real MAC is later discovered."""
    def setUp(self):
        self._bak = discover.DEVICES_DB
        import tempfile
        self._tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        self._tf.close()
        discover.DEVICES_DB = self._tf.name

    def tearDown(self):
        discover.DEVICES_DB = self._bak
        try:
            import os
            os.remove(self._tf.name)
        except OSError:
            pass

    def test_no_duplicate_when_mac_resolved(self):
        ip = "192.168.1.20"
        # First scan: router lists the IP with no MAC -> placeholder entry.
        discover.log_new_devices({ip: "?"}, "192.168.1.0/24")
        db = discover.load_known_devices()
        self.assertEqual(len(db), 1)
        # Second scan: real MAC discovered -> must upgrade, not duplicate.
        discover.log_new_devices({ip: "9C:95:61:11:22:33"}, "192.168.1.0/24")
        db = discover.load_known_devices()
        self.assertEqual(len(db), 1, "device must not be duplicated")
        only = next(iter(db.values()))
        self.assertEqual(only["mac"], "9C:95:61:11:22:33")
        self.assertEqual(only["ip"], ip)


class BulkUpsertTest(unittest.TestCase):
    """Accurate, MAC-primary device recognition for continuous capture."""
    def setUp(self):
        self._bak = discover.DEVICES_DB
        import tempfile
        self._tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        self._tf.close()
        discover.DEVICES_DB = self._tf.name
        discover._last_bulk_flush = 0.0

    def tearDown(self):
        discover.DEVICES_DB = self._bak
        try:
            import os
            os.remove(self._tf.name)
        except OSError:
            pass

    def test_placeholder_upgraded_not_duplicated(self):
        # First packet: IP with no MAC yet.
        discover.bulk_upsert_devices([("192.168.1.20", "?")], throttle_s=0)
        db = discover.load_known_devices()
        self.assertEqual(len(db), 1)
        # Later: real MAC on same IP -> upgrade, not duplicate.
        discover.bulk_upsert_devices([("192.168.1.20", "9C:95:61:11:22:33")], throttle_s=0)
        db = discover.load_known_devices()
        self.assertEqual(len(db), 1, "placeholder must be upgraded, not duplicated")
        only = next(iter(db.values()))
        self.assertEqual(only["mac"], "9C:95:61:11:22:33")

    def test_ip_change_keeps_single_entry(self):
        # DHCP renewal: same MAC, new IP -> still ONE entry, IP updated.
        discover.bulk_upsert_devices([("192.168.1.20", "9C:95:61:11:22:33")], throttle_s=0)
        discover.bulk_upsert_devices([("192.168.1.77", "9C:95:61:11:22:33")], throttle_s=0)
        db = discover.load_known_devices()
        self.assertEqual(len(db), 1, "MAC-primary key keeps one entry across IP change")
        only = next(iter(db.values()))
        self.assertEqual(only["ip"], "192.168.1.77")


if __name__ == "__main__":
    unittest.main()
