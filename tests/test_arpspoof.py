"""tests/test_arpspoof.py - safe packet construction (no injection).

build_spoof() returns raw bytes; it is unit-testable WITHOUT performing any
ARP spoofing on the network.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netmon import arpspoof


class ARPTest(unittest.TestCase):
    def test_build_spoof_length(self):
        pkt = arpspoof.build_spoof("192.168.1.5", "aa:bb:cc:dd:ee:ff",
                                    "192.168.1.1", "11:22:33:44:55:66")
        # 14-byte Ethernet header + 28-byte ARP payload = 42 bytes
        self.assertEqual(len(pkt), 42)
        self.assertEqual(pkt[12:14], b"\x08\x06")   # EtherType = ARP
        self.assertEqual(pkt[20:22], b"\x00\x02")   # ARP operation = reply

    def test_build_spoof_sender_is_gateway(self):
        # The spoofed sender IP must be the gateway (so victim thinks WE are it)
        pkt = arpspoof.build_spoof("192.168.1.5", "aa:bb:cc:dd:ee:ff",
                                    "192.168.1.1", "11:22:33:44:55:66")
        # sender IP = gateway, encoded in ARP payload after the sender MAC
        self.assertEqual(pkt[28:32], bytes([192, 168, 1, 1]))


if __name__ == "__main__":
    unittest.main()
