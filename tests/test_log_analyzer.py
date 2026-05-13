import unittest

from analyzer.log_analyzer import LogAnalyzer


class LogAnalyzerAggregationTests(unittest.TestCase):
    def test_policyid_default_aggregation_keeps_dstip_in_key(self):
        analyzer = LogAnalyzer([], columns={"connections": True})
        logs = [
            {"srcip": "10.0.0.10", "dstip": "10.0.0.20", "dstport": 22, "proto": 6, "policyid": 100},
            {"srcip": "10.0.0.10", "dstip": "10.0.0.30", "dstport": 22, "proto": 6, "policyid": 100},
        ]

        stats = analyzer.aggregate_by_policyid(logs, [])

        self.assertEqual(len(stats), 2)
        self.assertEqual(stats[("10.0.0.10", "10.0.0.20", "22", "tcp", "100")]["count"], 1)
        self.assertEqual(stats[("10.0.0.10", "10.0.0.30", "22", "tcp", "100")]["count"], 1)

    def test_policyid_aggregation_can_ignore_dstip(self):
        analyzer = LogAnalyzer(
            [],
            columns={"connections": True},
            aggregation={"dstip": False},
        )
        logs = [
            {"srcip": "10.0.0.10", "dstip": "10.0.0.20", "dstport": 22, "proto": 6, "policyid": 100},
            {"srcip": "10.0.0.10", "dstip": "10.0.0.30", "dstport": 22, "proto": 6, "policyid": 100},
        ]

        stats = analyzer.aggregate_by_policyid(logs, [])
        report = analyzer.build_policyid_report(stats, 100)
        header = next(line for line in report.splitlines() if line.startswith("SRC"))

        self.assertEqual(len(stats), 1)
        self.assertEqual(stats[("10.0.0.10", "22", "tcp", "100")]["count"], 2)
        self.assertNotIn("DST", header)
        self.assertIn("2", report)


if __name__ == "__main__":
    unittest.main()
