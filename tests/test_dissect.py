"""tests/test_dissect.py - dissection accuracy (no live NIC required)."""
import os
import sys
import struct
import unittest

# Make the netmon package importable when run from anywhere.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netmon import dissect


def make_dns_query(name):
    txid = b"\x12\x34"
    flags = struct.pack(">H", 0x0100)          # standard query
    qd = struct.pack(">H", 1)                  # 1 question
    qname = b"".join(bytes([len(l)]) + l.encode()
                     for l in name.split(".")) + b"\x00"
    return txid + flags + qd + b"\x00\x00\x00\x00\x00\x00" + qname + struct.pack(">HH", 1, 1)


class DissectTest(unittest.TestCase):
    def test_dns_google(self):
        raw = make_dns_query("google.com")
        self.assertEqual(dissect.dns_qname(raw), "google.com")

    def test_dissect_record_dns(self):
        raw = make_dns_query("evil.xyz")
        rec = dissect.dissect_record("10.0.0.1", "8.8.8.8", 17, 53000, 53, raw)
        self.assertEqual(rec["dns"], "evil.xyz")
        self.assertIn("xyz", rec["dns"])

    def test_app_from_sni(self):
        rec = {"sni": "www.youtube.com", "dns": "", "http": ""}
        dissect._enrich_record(rec, "", "www.youtube.com", "", "", "")
        self.assertEqual(rec["app"], "YouTube")

    def test_raw_l4_tcp(self):
        # minimal TCP packet bytes are not needed; just ensure helper exists
        self.assertTrue(callable(dissect.raw_l4))


if __name__ == "__main__":
    unittest.main()
