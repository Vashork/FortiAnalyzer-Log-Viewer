import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from analyzer.analysis_service import AnalysisRunContext, AnalysisRunOptions, AnalysisService, AnalysisServiceConfig


class FakeClient:
    def __init__(self):
        self.login = Mock(return_value=True)
        self.logout = Mock(return_value=True)


class AnalysisServiceTests(unittest.TestCase):
    def test_run_policyid_uses_shared_service_and_saves_result_with_history(self):
        client = FakeClient()
        history_calls = []
        context = AnalysisRunContext(
            start_time="2026-06-01 00:00:00",
            end_time="2026-06-01 01:00:00",
            target_ips=["10.0.0.10"],
            exclude_ips={"10.0.0.1"},
            ports=["443"],
            cmd="main.py --policyid 100",
        )

        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "analyzer.analysis_service.analyze_policyid_logs",
            return_value="policy report\n",
        ) as analyze:
            service = AnalysisService(
                client_factory=lambda: client,
                config=AnalysisServiceConfig(batch_size=50, max_workers=1, target_group_size=1),
            )

            result = service.run_policyid(
                context=context,
                policyid=100,
                results_dir=Path(tmpdir),
                history_callback=lambda *args: history_calls.append(args),
            )
            saved_text = result.files[0].path.read_text(encoding="utf-8")

        analyze.assert_called_once_with(
            client=client,
            target_ips=["10.0.0.10"],
            policyid=100,
            start_time="2026-06-01 00:00:00",
            end_time="2026-06-01 01:00:00",
            exclude_ips=["10.0.0.1"],
            batch_size=50,
            ports=["443"],
            columns=None,
            aggregation=None,
            progress=None,
            smart_action=None,
            filter_mode=None,
        )
        client.login.assert_called_once()
        client.logout.assert_called_once()
        self.assertEqual(result.texts["policy_100"], "policy report\n")
        self.assertEqual(result.files[0].path.name, "policy_100.txt")
        self.assertEqual(saved_text, "policy report\n")
        self.assertEqual(history_calls[0][3], "main.py --policyid 100")
        self.assertEqual(history_calls[0][4], "policy_100.txt")

    def test_run_direction_groups_targets_and_saves_direction_reports(self):
        created_clients = []
        progress = []
        context = AnalysisRunContext(
            start_time="2026-06-01 00:00:00",
            end_time="2026-06-01 01:00:00",
            target_ips=["10.0.0.10", "10.0.0.11"],
            exclude_ips=set(),
            ports=None,
            cmd="main.py --direction inbound",
        )

        def client_factory():
            client = FakeClient()
            created_clients.append(client)
            return client

        def fake_analyze_logs(**kwargs):
            target = kwargs["target_ips"][0]
            direction = kwargs["direction"]
            return {(target, direction): f"report for {target} {direction}\n"}

        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "analyzer.analysis_service.analyze_logs",
            side_effect=fake_analyze_logs,
        ) as analyze:
            service = AnalysisService(
                client_factory=client_factory,
                config=AnalysisServiceConfig(batch_size=25, max_workers=1, target_group_size=1),
                progress=progress.append,
            )

            result = service.run_direction(
                context=context,
                directions=["inbound"],
                results_dir=Path(tmpdir),
                workers=1,
            )
            saved_text = result.files[0].path.read_text(encoding="utf-8")

        self.assertEqual(analyze.call_count, 2)
        self.assertEqual(len(created_clients), 2)
        for client in created_clients:
            client.login.assert_called_once()
            client.logout.assert_called_once()
        self.assertIn("Target groups: 2 (TARGET_GROUP_SIZE=1)", progress)
        self.assertEqual(result.files[0].path.name, "inbound.txt")
        self.assertIn("report for 10.0.0.10 inbound", saved_text)
        self.assertIn("report for 10.0.0.11 inbound", saved_text)

    def test_run_policyid_writes_no_data_when_analyzer_returns_blank_text(self):
        client = FakeClient()
        context = AnalysisRunContext(
            start_time="2026-06-01 00:00:00",
            end_time="2026-06-01 01:00:00",
            target_ips=["10.0.0.10"],
        )

        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "analyzer.analysis_service.analyze_policyid_logs",
            return_value="   ",
        ):
            service = AnalysisService(client_factory=lambda: client)
            result = service.run_policyid(context=context, policyid=101, results_dir=Path(tmpdir))
            saved_text = result.files[0].path.read_text(encoding="utf-8")

        self.assertEqual(result.texts["policy_101"], "NO DATA\n")
        self.assertEqual(saved_text, "NO DATA\n")
    def test_run_direction_group_forwards_web_style_options(self):
        client = FakeClient()
        progress = Mock()
        context = AnalysisRunContext(
            start_time="2026-06-01 00:00:00",
            end_time="2026-06-01 01:00:00",
            target_ips=["10.0.0.10"],
            exclude_ips={"10.0.0.1"},
            ports=["443"],
        )
        options = AnalysisRunOptions(
            columns={"hostname": True},
            aggregation={"remote_ip": True},
            progress=progress,
            smart_action="deny",
            filter_mode="faz",
        )

        with patch("analyzer.analysis_service.analyze_logs", return_value={}) as analyze:
            service = AnalysisService(
                client_factory=lambda: client,
                config=AnalysisServiceConfig(batch_size=75, max_workers=1, target_group_size=1),
            )
            service.run_direction_group(
                ip_group=["10.0.0.10"],
                direction="outbound",
                context=context,
                options=options,
            )

        analyze.assert_called_once_with(
            client=client,
            target_ips=["10.0.0.10"],
            direction="outbound",
            start_time="2026-06-01 00:00:00",
            end_time="2026-06-01 01:00:00",
            exclude_ips=["10.0.0.1"],
            batch_size=75,
            ports=["443"],
            columns={"hostname": True},
            aggregation={"remote_ip": True},
            progress=progress,
            smart_action="deny",
            filter_mode="faz",
        )


if __name__ == "__main__":
    unittest.main()
