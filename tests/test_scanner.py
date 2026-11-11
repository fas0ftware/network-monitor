import unittest
from types import SimpleNamespace
from unittest import mock

import scanner


def fake_reply(ip, mac):
    return (None, SimpleNamespace(psrc=ip, hwsrc=mac))


class ScanTests(unittest.TestCase):
    def test_scan_merges_multiple_passes(self):
        passes = iter([
            ([fake_reply("192.168.1.1", "00:11:22:33:44:55")], []),
            ([fake_reply("192.168.1.2", "66:77:88:99:aa:bb")], []),
            ([fake_reply("192.168.1.1", "00:11:22:33:44:55")], []),
        ])
        with mock.patch.object(scanner, "srp", lambda *a, **k: next(passes)), \
                mock.patch.object(scanner, "find_vendor", lambda mac: "V"):
            devices = scanner.scan("192.168.1.0/24", retries=3)

        self.assertEqual(sorted(d["ip"] for d in devices), ["192.168.1.1", "192.168.1.2"])
        self.assertTrue(all(d["vendor"] == "V" for d in devices))


class FindVendorTests(unittest.TestCase):
    def test_random_mac_is_labelled_private(self):
        # Locally administered (randomized) MACs have no vendor; v2 labels them explicitly
        self.assertEqual(scanner.find_vendor("02:00:00:00:00:01"), "Private (randomized MAC)")

    def test_handles_errors(self):
        class Broken:
            def _get_manuf(self, mac):
                raise RuntimeError("boom")

        # Scapy's conf object ignores manufdb assignment, so replace conf entirely
        with mock.patch.object(scanner, "conf", SimpleNamespace(manufdb=Broken())):
            self.assertEqual(scanner.find_vendor("00:11:22:33:44:55"), "Unknown")


class RandomizedMacTests(unittest.TestCase):
    def test_locally_administered_bit(self):
        for mac in ("9a:1f:44:c2:0b:7d", "02:00:00:00:00:01", "de:ad:be:ef:00:01", "f6:aa:bb:cc:dd:ee"):
            self.assertTrue(scanner.is_randomized(mac), mac)
            self.assertEqual(scanner.find_vendor(mac), "Private (randomized MAC)")
        for mac in ("3c:84:6a:12:a4:01", "00:17:88:6b:2f:90", "garbage"):
            self.assertFalse(scanner.is_randomized(mac), mac)


if __name__ == "__main__":
    unittest.main()
