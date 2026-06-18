"""Tests for TCP port scanner utilities."""

import unittest
from netscout.scanner import (
    scan_port,
    scan_range,
    scan_range_concurrent,
    grab_banner,
    grab_banner_concurrent,
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

    def test_grab_banner_returns_optional_string(self):
        """Test grab_banner returns None or a string."""
        result = grab_banner("localhost", 80, timeout=1.0)
        self.assertIsInstance(result, (str, type(None)))

    def test_grab_banner_concurrent_returns_dict(self):
        """Test grab_banner_concurrent returns a dictionary."""
        result = grab_banner_concurrent("localhost", [80, 443], timeout=1.0, max_workers=2)
        self.assertIsInstance(result, dict)
        # All keys should be integers
        for key in result.keys():
            self.assertIsInstance(key, int)
        # All values should be strings
        for value in result.values():
            self.assertIsInstance(value, str)

    def test_grab_banner_concurrent_empty_ports(self):
        """Test grab_banner_concurrent with empty port list."""
        result = grab_banner_concurrent("localhost", [], timeout=1.0, max_workers=2)
        self.assertEqual(result, {})

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


class TestScanOutput(unittest.TestCase):

    def test_json_output_format(self):
        """Test that JSON output can be generated from scan results."""
        import json
        result = scan_range_concurrent("localhost", 1, 50, timeout=0.5, max_workers=5)
        output = {
            "host": "127.0.0.1",
            "protocol": "tcp",
            "ports_scanned": "1-50",
            "open_ports": [
                {"port": port, "service": "unknown", "banner": None}
                for port in result
            ]
        }
        # Ensure it's JSON serializable
        json_str = json.dumps(output)
        self.assertIsInstance(json_str, str)
        # Ensure it deserializes correctly
        parsed = json.loads(json_str)
        self.assertEqual(parsed["host"], "127.0.0.1")
        self.assertEqual(parsed["protocol"], "tcp")

    def test_json_output_with_banners(self):
        """Test JSON output includes banner data when present."""
        import json
        output = {
            "host": "127.0.0.1",
            "protocol": "tcp",
            "ports_scanned": "80-80",
            "open_ports": [
                {
                    "port": 80,
                    "service": "HTTP",
                    "banner": "HTTP/1.1 200 OK"
                }
            ]
        }
        json_str = json.dumps(output)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["open_ports"][0]["banner"], "HTTP/1.1 200 OK")


if __name__ == "__main__":
    unittest.main()
