"""Tests for DNS resolver utilities."""

import unittest
from netscout.resolver import resolve, resolve_all, reverse_lookup


class TestResolver(unittest.TestCase):

    def test_resolve_known_host(self):
        ip = resolve("localhost")
        self.assertIn(ip, ("127.0.0.1", "::1"))

    def test_resolve_invalid_host(self):
        result = resolve("this.hostname.does.not.exist.invalid")
        self.assertIsNone(result)

    def test_resolve_all_returns_list(self):
        results = resolve_all("localhost")
        self.assertIsInstance(results, list)


if __name__ == "__main__":
    unittest.main()
