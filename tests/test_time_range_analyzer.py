import unittest
from unittest.mock import patch

from analyzer.log_analyzer import LogAnalyzer
from analyzer.time_range_analyzer import analyze_logs_time_split, fetch_local_stats_for_segments


class BatchClient:
    def __init__(self, batches):
        self.batches = batches
        self.fetch_logs_called = False
        self.created_tasks = []

    def create_search_task(self, filter_str, start_time, end_time):
        self.created_tasks.append((filter_str, start_time, end_time))
        return len(self.created_tasks)

    def wait_for_task_completion(self, task_id):
        return True, sum(len(batch) for batch in self.batches)

    def iter_fetch_logs(self, task_id, total_logs, batch_size=100):
        yield from self.batches

    def fetch_logs(self, task_id, total_logs, batch_size=100):
        self.fetch_logs_called = True
        return [log for batch in self.batches for log in batch]


class MainClient:
    url = "https://faz.example/jsonrpc"
    username = "user"
    password = "pass"

    def transport_kwargs(self):
        return {}


class WorkerBatchClient(BatchClient):
    batches = []
    instances = []

    def __init__(self, *args, **kwargs):
        super().__init__(self.__class__.batches)
        self.__class__.instances.append(self)

    def login(self):
        return True

    def logout(self):
        return None


class TimeRangeAnalyzerTests(unittest.TestCase):
    def test_fetch_local_stats_for_segments_streams_batches_without_fetch_logs(self):
        client = BatchClient([
            [{"srcip": "10.0.0.10", "dstip": "8.8.8.8", "dstport": 53, "proto": 17}],
            [{"srcip": "10.0.0.10", "dstip": "8.8.8.8", "dstport": 53, "proto": 17}],
        ])
        analyzer = LogAnalyzer([], columns={"connections": True})

        with patch("analyzer.time_range_analyzer.MAX_MATCHED_LOGS_PER_TASK", 0):
            stats, total_logs = fetch_local_stats_for_segments(
                client=client,
                filter_str='srcip="10.0.0.10"',
                segments=[("2026-06-01 00:00:00", "2026-06-01 01:00:00")],
                batch_size=1,
                target_ips=["10.0.0.10"],
                direction="outbound",
                analyzer=analyzer,
            )

        self.assertFalse(client.fetch_logs_called)
        self.assertEqual(total_logs, 2)
        self.assertEqual(stats["10.0.0.10"][("8.8.8.8", "53", "udp")]["count"], 2)

    def test_analyze_logs_time_split_builds_reports_from_streamed_worker_stats(self):
        WorkerBatchClient.batches = [
            [{"srcip": "10.0.0.10", "dstip": "8.8.8.8", "dstport": 53, "proto": 17}],
            [{"srcip": "10.0.0.10", "dstip": "8.8.8.8", "dstport": 53, "proto": 17}],
        ]
        WorkerBatchClient.instances = []

        with (
            patch("analyzer.time_range_analyzer.FortiAnalyzerClient", WorkerBatchClient),
            patch("analyzer.time_range_analyzer.MAX_TASK_HOURS", 24),
        ):
            reports = analyze_logs_time_split(
                main_client=MainClient(),
                target_ips=["10.0.0.10"],
                direction="outbound",
                start_time="2026-06-01 00:00:00",
                end_time="2026-06-01 01:00:00",
                exclude_ips=[],
                batch_size=1,
                ports=None,
                columns={"connections": True},
                num_workers=1,
            )

        self.assertEqual(len(WorkerBatchClient.instances), 1)
        self.assertFalse(WorkerBatchClient.instances[0].fetch_logs_called)
        report = reports[("10.0.0.10", "outbound")]
        self.assertIn("8.8.8.8", report)
        self.assertIn("Total connections: 2", report)


if __name__ == "__main__":
    unittest.main()
