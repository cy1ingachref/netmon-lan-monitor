"""tests/test_capture.py - tshark row parsing (tab separator, field order)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netmon import capture


def _row(ts, src, dst, ttl, proto, sport, dport, sni="", dns="", http="",
         eth_src="", eth_dst=""):
    # field order (see capture.TSHARK_FIELDS):
    #   no, eth.src, eth.dst, time_rel, ip.src, ip.dst, ttl, _ws.col.Protocol,
    #   ip.proto, tcp.sport, tcp.dport, udp.sport, udp.dport, dns.qry, dns.resp,
    #   sni, http.host, http.method, http.ua, tcp.flags
    cols = ["1", eth_src, eth_dst, ts, src, dst, ttl, "TLSv1.3", proto,
            sport, dport, "", "", dns, "", sni, http, "", "", ""]
    return "\t".join(cols)


class TestParseTsharkRow(unittest.TestCase):
    def test_full_row_extraction(self):
        line = _row("0.123", "192.168.1.5", "1.2.3.4", "64", "6",
                    "51000", "443", sni="github.com")
        rec = capture._parse_tshark_row(line, "192.168.1.5")
        self.assertIsNotNone(rec)
        self.assertEqual(rec["src"], "192.168.1.5")
        self.assertEqual(rec["dst"], "1.2.3.4")
        self.assertEqual(rec["sport"], 51000)
        self.assertEqual(rec["dport"], 443)
        self.assertEqual(rec["proto"], "TCP")

    def test_dns_row(self):
        line = _row("0.250", "192.168.1.5", "8.8.8.8", "64", "17",
                    "53000", "53", dns="google.com")
        rec = capture._parse_tshark_row(line, "192.168.1.5")
        self.assertIsNotNone(rec)
        self.assertEqual(rec["dns"], "google.com")

    def test_short_row_skipped(self):
        # a non-IP row with too few columns returns None
        rec = capture._parse_tshark_row("1\t0.1\t192.168.1.5", "192.168.1.5")
        self.assertIsNone(rec)

    def test_tab_separator_no_shift(self):
        # the old "|" separator collided with the aggregator "|"; tab is safe.
        # A comma inside the SNI field must stay in its own column (not shift).
        line = _row("0.1", "192.168.1.5", "1.2.3.4", "64", "6",
                    "51000", "443", sni="a,b,c.example.com")
        rec = capture._parse_tshark_row(line, "192.168.1.5")
        self.assertIsNotNone(rec)
        self.assertEqual(rec["sni"], "a,b,c.example.com")  # comma stays, no shift
        self.assertEqual(rec["sport"], 51000)


class TestEthMacFields(unittest.TestCase):
    def test_eth_src_dst_parsed(self):
        line = _row("0.1", "192.168.1.5", "1.2.3.4", "64", "6",
                    "51000", "443", eth_src="1c:61:b4:3f:cf:e8",
                    eth_dst="9c:95:61:00:00:01")
        rec = capture._parse_tshark_row(line, "192.168.1.5")
        self.assertIsNotNone(rec)
        self.assertEqual(rec["eth_src"], "1c:61:b4:3f:cf:e8")
        self.assertEqual(rec["eth_dst"], "9c:95:61:00:00:01")


class TestContinuousContract(unittest.TestCase):
    def test_stop_event_honored_no_hang(self):
        # continuous + pre-set stop_event must return promptly (no timeout wait).
        import threading
        ev = threading.Event()
        ev.set()  # already stopped -> should not block
        # With no tshark on PATH this returns (None,...) fast anyway; we assert
        # the call does not raise and returns a 3-tuple (records, raw, mode).
        out = capture.tshark_capture(seconds=0, continuous=True,
                                     stop_event=ev, with_demo=False)
        self.assertEqual(len(out), 3)


if __name__ == "__main__":
    unittest.main()
