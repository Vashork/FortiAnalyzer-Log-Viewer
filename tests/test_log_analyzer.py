import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from analyzer.log_analyzer import LogAnalyzer, analyze_logs, analyze_policyid_logs


class BatchClient:
    def __init__(self, batches):
        self.batches = batches
        self.fetch_logs_called = False

    def create_search_task(self, filter_str, start_time, end_time):
        return 1

    def wait_for_task_completion(self, task_id):
        return True, sum(len(batch) for batch in self.batches)

    def iter_fetch_logs(self, task_id, total_logs, batch_size=100):
        yield from self.batches

    def fetch_logs(self, task_id, total_logs, batch_size=100):
        self.fetch_logs_called = True
        return [log for batch in self.batches for log in batch]


class LogAnalyzerAggregationTests(unittest.TestCase):
    def test_direction_analysis_aggregates_streamed_batches(self):
        client = BatchClient([
            [{"srcip": "10.0.0.10", "dstip": "8.8.8.8", "dstport": 53, "proto": 17}],
            [{"srcip": "10.0.0.10", "dstip": "8.8.8.8", "dstport": 53, "proto": 17}],
        ])

        with patch("analyzer.log_analyzer.MAX_TASK_HOURS", 24):
            reports = analyze_logs(
                client=client,
                target_ips=["10.0.0.10"],
                direction="outbound",
                start_time="2026-06-01 00:00:00",
                end_time="2026-06-01 01:00:00",
                exclude_ips=[],
            )

        self.assertFalse(client.fetch_logs_called)
        report = reports[("10.0.0.10", "outbound")]
        self.assertIn("8.8.8.8", report)
        self.assertIn("Total connections: 2", report)

    def test_policyid_analysis_aggregates_streamed_batches(self):
        client = BatchClient([
            [{"srcip": "10.0.0.10", "dstip": "10.0.0.20", "dstport": 443, "proto": 6, "policyid": 100}],
            [{"srcip": "10.0.0.10", "dstip": "10.0.0.20", "dstport": 443, "proto": 6, "policyid": 100}],
        ])

        with (
            patch("analyzer.log_analyzer.MAX_TASK_HOURS", 24),
            redirect_stdout(io.StringIO()),
        ):
            report = analyze_policyid_logs(
                client=client,
                target_ips=[],
                policyid=100,
                start_time="2026-06-01 00:00:00",
                end_time="2026-06-01 01:00:00",
                exclude_ips=[],
            )

        self.assertFalse(client.fetch_logs_called)
        self.assertIn("10.0.0.10", report)
        self.assertIn("10.0.0.20", report)
        self.assertIn("Total entries: 2", report)

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

    def test_policyid_report_resolves_source_and_destination_hostnames(self):
        analyzer = LogAnalyzer([], columns={"connections": True})
        logs = [
            {"srcip": "10.0.0.10", "dstip": "10.0.0.20", "dstport": 22, "proto": 6, "policyid": 100},
        ]

        stats = analyzer.aggregate_by_policyid(logs, [])
        with patch(
            "analyzer.log_analyzer.resolve_hostnames",
            return_value={"10.0.0.10": "src.example", "10.0.0.20": "dst.example"},
        ):
            report = analyzer.build_policyid_report(stats, 100)

        header = next(line for line in report.splitlines() if line.startswith("Srcip"))
        self.assertIn("SrcHostname", header)
        self.assertIn("DstHostname", header)
        self.assertIn("src.example", report)
        self.assertIn("dst.example", report)

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
        header = next(line for line in report.splitlines() if line.startswith("Srcip"))

        self.assertEqual(len(stats), 1)
        self.assertEqual(stats[("10.0.0.10", "22", "tcp", "100")]["count"], 2)
        self.assertNotIn("Dstip", header)
        self.assertIn("2", report)

    def test_srcport_can_be_added_as_report_column(self):
        analyzer = LogAnalyzer([], columns={"connections": True, "srcport": True})
        logs = [
            {
                "srcip": "10.0.0.10",
                "dstip": "10.0.0.20",
                "srcport": 50123,
                "dstport": 22,
                "proto": 6,
                "policyid": 100,
            }
        ]

        stats = analyzer.aggregate_by_policyid(logs, [])
        report = analyzer.build_policyid_report(stats, 100)

        self.assertIn("Srcport", report)
        self.assertIn("50123", report)

    def test_local_stats_only_create_sets_for_enabled_columns_and_keep_report_format(self):
        analyzer = LogAnalyzer(
            [],
            columns={"connections": True, "policyid": True},
        )
        logs = [
            {
                "srcip": "10.0.0.10",
                "dstip": "8.8.8.8",
                "dstport": 53,
                "proto": 17,
                "policyid": 100,
                "app": "dns",
                "policyname": "allow-dns",
                "devname": "fg-01",
            }
        ]

        stats = analyzer.aggregate_by_local(logs, "outbound", ["10.0.0.10"])
        entry = stats["10.0.0.10"][("8.8.8.8", "53", "udp")]
        report = analyzer.build_reports_per_local(stats, "outbound", ["10.0.0.10"])[("10.0.0.10", "outbound")]

        self.assertEqual(entry["count"], 1)
        self.assertEqual(entry["policyids"], {"100"})
        self.assertNotIn("remote_ips", entry)
        self.assertNotIn("apps", entry)
        self.assertNotIn("policynames", entry)
        self.assertNotIn("devnames", entry)
        self.assertIn("Remote IP", report)
        self.assertIn("PolicyID", report)
        self.assertIn("Total unique remotes: 1", report)
        self.assertIn("Total connections: 1", report)

    def test_policyid_stats_only_create_sets_for_enabled_columns_and_keep_report_format(self):
        analyzer = LogAnalyzer(
            [],
            columns={"connections": True, "srcport": True},
        )
        logs = [
            {
                "srcip": "10.0.0.10",
                "dstip": "10.0.0.20",
                "srcport": 50123,
                "dstport": 22,
                "proto": 6,
                "policyid": 100,
                "app": "ssh",
                "policyname": "admin-ssh",
                "devname": "fg-01",
            }
        ]

        stats = analyzer.aggregate_by_policyid(logs, [])
        entry = stats[("10.0.0.10", "10.0.0.20", "22", "tcp", "100")]
        report = analyzer.build_policyid_report(stats, 100)

        self.assertEqual(entry["count"], 1)
        self.assertEqual(entry["srcports"], {"50123"})
        self.assertNotIn("policyids", entry)
        self.assertNotIn("apps", entry)
        self.assertNotIn("policynames", entry)
        self.assertNotIn("devnames", entry)
        self.assertIn("Srcport", report)
        self.assertIn("50123", report)
        self.assertIn("Total entries: 1", report)

    def test_high_cardinality_report_fields_are_capped(self):
        analyzer = LogAnalyzer(
            [],
            columns={"connections": True, "app": True, "policyname": True, "devname": True},
        )
        logs = [
            {
                "srcip": "10.0.0.10",
                "dstip": "8.8.8.8",
                "dstport": 53,
                "proto": 17,
                "policyid": 100,
                "app": f"app-{idx}",
                "policyname": f"policy-{idx}",
                "devname": f"fg-{idx}",
            }
            for idx in range(5)
        ]

        with patch.dict("os.environ", {"AGGREGATE_FIELD_VALUE_LIMIT": "2"}):
            stats = analyzer.aggregate_by_local(logs, "outbound", ["10.0.0.10"])
            entry = stats["10.0.0.10"][("8.8.8.8", "53", "udp")]
            report = analyzer.build_reports_per_local(stats, "outbound", ["10.0.0.10"])[("10.0.0.10", "outbound")]

        self.assertLessEqual(len(entry["apps"]), 3)
        self.assertLessEqual(len(entry["policynames"]), 3)
        self.assertLessEqual(len(entry["devnames"]), 3)
        self.assertIn("<truncated>", entry["apps"])
        self.assertIn("<truncated>", report)
        self.assertIn("Total connections: 5", report)


if __name__ == "__main__":
    unittest.main()
