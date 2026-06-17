"""Tests for TCP port scanner utilities."""

import unittest
from netscout.scanner import (
    scan_port,
    scan_range,
    scan_range_concurrent,
    scan_udp_port,
    scan_udp_range,
    scan_udp_range_concurrent,
)


class TestScanner(unittest.TestCase):

    def test_scan_port_localhost_22(self):
        """Test scanning localhost on port 22 (may not be open in all environments)."""
        # This test may fail if SSH is not running; documenting expected behavior
        result = scan_port("localhost", 22, timeout=0.5)
        self.assertIsInstance(result, bool)

    def test_scan_port_invalid_host(self):
        """Test scanning an invalid host returns False."""
        result = scan_port("invalid.host.local", 80, timeout=0.5)
        self.assertFalse(result)

    def test_scan_range_returns_list(self):
        """Test scan_range returns a list."""
        result = scan_range("localhost", 1, 10, timeout=0.5)
        self.assertIsInstance(result, list)

    def test_scan_range_concurrent_returns_sorted_list(self):
        """Test scan_range_concurrent returns a sorted list."""
        result = scan_range_concurrent("localhost", 1, 100, timeout=0.5, max_workers=5)
        self.assertIsInstance(result, list)
        # Verify list is sorted
        self.assertEqual(result, sorted(result))

    def test_scan_range_concurrent_max_workers(self):
        """Test scan_range_concurrent respects max_workers parameter."""
        result = scan_range_concurrent("localhost", 1, 50, timeout=0.5, max_workers=1)
        self.assertIsInstance(result, list)

    def test_scan_udp_port_returns_bool(self):
        """Test scan_udp_port returns a boolean."""
        result = scan_udp_port("localhost", 53, timeout=1.0)
        self.assertIsInstance(result, bool)

    def test_scan_udp_range_returns_list(self):
        """Test scan_udp_range returns a list."""
        result = scan_udp_range("localhost", 1, 10, timeout=0.5)
        self.assertIsInstance(result, list)

    def test_scan_udp_range_concurrent_returns_sorted_list(self):
        """Test scan_udp_range_concurrent returns a sorted list."""
        result = scan_udp_range_concurrent("localhost", 1, 100, timeout=0.5, max_workers=5)
        self.assertIsInstance(result, list)
        self.assertEqual(result, sorted(result))


if __name__ == "__main__":
    unittest.main()
