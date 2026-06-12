import tempfile
import unittest
from pathlib import Path

from utils.network import load_machines, parse_ip_range


class NetworkExpansionLimitTests(unittest.TestCase):
    def test_parse_ip_range_rejects_huge_cidr(self):
        with self.assertRaises(ValueError):
            parse_ip_range("10.0.0.0/19")

    def test_parse_ip_range_rejects_huge_ip_range(self):
        with self.assertRaises(ValueError):
            parse_ip_range("10.0.0.1-10.0.32.1")

    def test_load_machines_skips_huge_cidr_but_keeps_safe_targets(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "machines.txt"
            path.write_text("10.0.0.0/19\n192.0.2.10\n", encoding="utf-8")

            ips = load_machines(str(path))

        self.assertEqual(ips, ["192.0.2.10"])


if __name__ == "__main__":
    unittest.main()
