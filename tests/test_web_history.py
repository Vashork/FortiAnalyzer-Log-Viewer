import asyncio
import importlib
import json
import logging
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import mock_open, patch


class WebHistoryTests(unittest.TestCase):
    def test_parse_history_reads_timestamp_and_state(self):
        with (
            patch("logging.FileHandler", side_effect=lambda *args, **kwargs: logging.NullHandler()),
            patch("logging.StreamHandler", side_effect=lambda *args, **kwargs: logging.NullHandler()),
        ):
            web_app = importlib.import_module("web.app")

        history_text = (
            "\n=== 2026-05-27 16:20:20 ===\n"
            "CMD: policyid=247\n"
            "TIME: 2026-05-26 16:20:20 -> 2026-05-27 16:20:20\n"
            "SMART_ACTION=all | FILTER_MODE=faz\n"
            "FILE: policy_247.txt\n"
            'STATE_JSON: {"analysis_mode": "policyid", "policyid": 247}\n'
            "------------------------------------------------------------\n"
            "POLICYID ANALYSIS - policyid=247\n"
            "Total entries: 4306\n"
        )

        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("builtins.open", mock_open(read_data=history_text)),
        ):
            entries = web_app.parse_history()

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["timestamp"], "2026-05-27 16:20:20")
        self.assertEqual(entries[0]["cmd"], "policyid=247")
        self.assertEqual(entries[0]["policyid"], "247")
        self.assertEqual(entries[0]["state"], {"analysis_mode": "policyid", "policyid": 247})
        self.assertEqual(entries[0]["summary_lines"], ["Total entries: 4306"])

    def test_attach_run_metadata_appends_structured_jsonl_history(self):
        from web.analysis_scheduler import _attach_run_metadata

        with tempfile.TemporaryDirectory() as tmp:
            results_root = Path(tmp)
            run_dir = results_root / "20260612T120000Z-deadbeef"
            run_dir.mkdir()
            request = SimpleNamespace(
                analysis_mode="direction",
                direction="inbound",
                policyid=None,
                policyids=None,
                time_mode="exact",
                time_value=24,
                start_time="2026-06-01 00:00:00",
                end_time="2026-06-01 01:00:00",
                output_format="txt",
                smart_action="all",
                use_machines_file=False,
                targets=[],
                exclude_internal=False,
                proto_enabled=False,
                ports="",
                columns={},
                aggregation={},
            )

            with patch("web.analysis_scheduler.get_results_dir_path", return_value=results_root):
                _attach_run_metadata(
                    {"files": [{"path": "20260612T120000Z-deadbeef/inbound.txt"}], "texts": {}},
                    "20260612T120000Z-deadbeef",
                    run_dir,
                    request,
                    "2026-06-01 00:00:00",
                    "2026-06-01 01:00:00",
                )

            rows = [json.loads(line) for line in (results_root / "history.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["run_id"], "20260612T120000Z-deadbeef")
            self.assertEqual(rows[0]["status"], "completed")
            self.assertEqual(rows[0]["request"]["analysis_mode"], "direction")
            self.assertEqual(rows[0]["files"], ["20260612T120000Z-deadbeef/inbound.txt"])
            self.assertIn("finished_at", rows[0])
            self.assertIn("duration_seconds", rows[0])

    def test_parse_history_prefers_jsonl_and_supports_pagination(self):
        with (
            patch("logging.FileHandler", side_effect=lambda *args, **kwargs: logging.NullHandler()),
            patch("logging.StreamHandler", side_effect=lambda *args, **kwargs: logging.NullHandler()),
        ):
            web_app = importlib.import_module("web.app")

        with tempfile.TemporaryDirectory() as tmp:
            results_root = Path(tmp)
            rows = [
                {"run_id": "run-1", "finished_at": "2026-06-01T10:00:00Z", "status": "completed", "cmd": "direction=inbound", "files": ["run-1/inbound.txt"], "request": {"analysis_mode": "direction"}},
                {"run_id": "run-2", "finished_at": "2026-06-01T11:00:00Z", "status": "completed", "cmd": "policyid=100", "files": ["run-2/policy_100.txt"], "request": {"analysis_mode": "policyid", "policyid": 100}},
                {"run_id": "run-3", "finished_at": "2026-06-01T12:00:00Z", "status": "error", "cmd": "direction=outbound", "files": [], "request": {"analysis_mode": "direction"}},
            ]
            (results_root / "history.jsonl").write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

            with patch("web.app.get_results_dir_path", return_value=results_root):
                page = web_app.parse_history(limit=2, offset=1)

        self.assertEqual([entry["run_id"] for entry in page], ["run-2", "run-1"])
        self.assertEqual(page[0]["timestamp"], "2026-06-01T11:00:00Z")
        self.assertEqual(page[0]["policyid"], "100")
        self.assertEqual(page[0]["file"], "run-2/policy_100.txt")

    def test_history_endpoint_returns_pagination_metadata(self):
        with (
            patch("logging.FileHandler", side_effect=lambda *args, **kwargs: logging.NullHandler()),
            patch("logging.StreamHandler", side_effect=lambda *args, **kwargs: logging.NullHandler()),
        ):
            web_app = importlib.import_module("web.app")

        with patch("web.app.parse_history", return_value=[{"run_id": "run-2"}]) as parse_history:
            result = asyncio.run(web_app.get_history(limit=1, offset=1))

        parse_history.assert_called_once_with(limit=1, offset=1)
        self.assertEqual(result, {"entries": [{"run_id": "run-2"}], "limit": 1, "offset": 1})


if __name__ == "__main__":
    unittest.main()
