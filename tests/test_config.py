import unittest

from config import normalize_ip_range


class NormalizeIpRangeTests(unittest.TestCase):
    def test_host_bits_are_cleared(self):
        self.assertEqual(normalize_ip_range("192.168.1.6/24"), "192.168.1.0/24")

    def test_whitespace_is_ignored(self):
        self.assertEqual(normalize_ip_range("  10.0.0.0/24 "), "10.0.0.0/24")

    def test_garbage_is_rejected(self):
        for value in ("", "hello", "300.1.1.1/24", "192.168.1.0/99"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_ip_range(value)

    def test_ipv6_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_ip_range("fe80::/64")

    def test_huge_ranges_are_rejected(self):
        with self.assertRaises(ValueError):
            normalize_ip_range("10.0.0.0/8")

    def test_largest_allowed_range(self):
        self.assertEqual(normalize_ip_range("172.16.0.0/20"), "172.16.0.0/20")


if __name__ == "__main__":
    unittest.main()
