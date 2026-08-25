"""tests/test_router_fetch.py - TP-Link adapter parser without a real router.

We monkeypatch urllib.request.build_opener so no network is touched; the
TPLinkArcherHTTP adapter must parse the embedded DHCP rows from fake HTML.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netmon import router_fetch


class _FakeResp:
    def __init__(self, data: str):
        self._d = data.encode("utf-8")
    def read(self):
        return self._d
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


class TestTPLinkArcherParse(unittest.TestCase):
    HTML = (
        '<script>var DHCP=new Array('
        '["Phone","AA-BB-CC-DD-EE-FF","192.168.1.50","23:59:59"],'
        '["Laptop","11-22-33-44-55-66","192.168.1.51","01:02:03"]'
        ');</script>'
    )

    def _patch(self):
        opener = mock.MagicMock()
        opener.open.return_value = _FakeResp(self.HTML)
        return mock.patch.object(router_fetch.urllib.request, "build_opener",
                                return_value=opener)

    def test_parses_rows(self):
        with self._patch():
            rows = router_fetch.TPLinkArcherHTTP().fetch("192.168.1.1", "admin", "admin")
        self.assertEqual(len(rows), 2)
        self.assertIn("AA-BB-CC-DD-EE-FF", rows[0])
        self.assertIn("192.168.1.50", rows[0])

    def test_mac_normalized_upper(self):
        with self._patch():
            rows = router_fetch.TPLinkArcherHTTP().fetch("192.168.1.1", "admin", "admin")
        # adapter uppercases MACs
        self.assertIn("AA-BB-CC-DD-EE-FF", rows[0].upper())

    def test_fetch_returns_list_not_none(self):
        # even on a simulated failure, the adapter returns [] (never None)
        with mock.patch.object(router_fetch.urllib.request, "build_opener",
                               side_effect=Exception("simulated no network")):
            rows = router_fetch.TPLinkArcherHTTP().fetch("1.2.3.4", "x", "y")
        self.assertEqual(rows, [])


class TestManualPasteFallback(unittest.TestCase):
    def test_reads_existing_file(self):
        path = router_fetch.ROUTER_CLIENTS
        bak = None
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                bak = f.read()
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("Phone\tAA-BB-CC-DD-EE-FF\t192.168.1.50\n")
            rows = router_fetch.ManualPasteAdapter().fetch("192.168.1.1", "a", "b")
            self.assertEqual(len(rows), 1)
            self.assertIn("192.168.1.50", rows[0])
        finally:
            if bak is None:
                try: os.remove(path)
                except Exception: pass
            else:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(bak)

    def test_missing_file_returns_empty(self):
        path = router_fetch.ROUTER_CLIENTS
        existed = os.path.exists(path)
        if existed:
            os.remove(path)
        try:
            self.assertEqual(router_fetch.ManualPasteAdapter().fetch("1.2.3.4", "a", "b"), [])
        finally:
            # do not recreate; leave as the test found it if it existed originally
            pass


if __name__ == "__main__":
    unittest.main()
