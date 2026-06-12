import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from web.analysis_scheduler import SchedulerEmitter, _run_direction


class RunResultDirectoryTests(unittest.TestCase):
    def request(self, **overrides):
        data = {
            "direction": "inbound",
            "workers": 1,
            "columns": {},
            "aggregation": {},
            "output_format": "txt",
            "time_mode": "exact",
            "time_value": 24,
            "start_time": "2026-06-01 00:00:00",
            "end_time": "2026-06-01 01:00:00",
            "analysis_mode": "direction",
            "policyid": None,
            "policyids": None,
            "smart_action": "all",
            "use_machines_file": False,
            "targets": [],
            "exclude_internal": False,
            "proto_enabled": False,
            "ports": "",
        }
        data.update(overrides)
        return SimpleNamespace(**data)

    def test_direction_results_are_saved_under_unique_run_directory_with_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            results_root = Path(tmp)
            events = []
            emitter = SchedulerEmitter(events.append)
            request = self.request()

            with (
                patch("web.analysis_scheduler.get_results_dir_path", return_value=results_root),
                patch("web.analysis_scheduler.get_dynamic_split_mode", return_value="ip"),
                patch("web.analysis_scheduler.get_dynamic_target_group_size", return_value=1),
                patch("web.analysis_scheduler.get_dynamic_workers", return_value=1),
                patch("web.analysis_scheduler.get_dynamic_batch_size", return_value=100),
                patch(
                    "web.analysis_scheduler._run_faz_search",
                    return_value={("10.0.0.10", "inbound"): "INBOUND REPORT\n"},
                ),
            ):
                result = _run_direction(
                    request,
                    emitter,
                    cancel_check=lambda: False,
                    start_time="2026-06-01 00:00:00",
                    end_time="2026-06-01 01:00:00",
                    target_ips=["10.0.0.10"],
                    exclude_ips=set(),
                    ports=None,
                )

            self.assertIn("run_id", result)
            run_id = result["run_id"]
            self.assertRegex(run_id, r"^\d{8}T\d{6}Z-[0-9a-f]{8}$")
            self.assertEqual(result["run_dir"], run_id)
            self.assertEqual(result["files"][0]["path"], f"{run_id}/inbound.txt")
            self.assertEqual((results_root / run_id / "inbound.txt").read_text(encoding="utf-8"), "INBOUND REPORT\n")
            self.assertFalse((results_root / "inbound.txt").exists())

            metadata = json.loads((results_root / run_id / "metadata.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["run_id"], run_id)
            self.assertEqual(metadata["analysis_mode"], "direction")
            self.assertEqual(metadata["status"], "completed")
            self.assertEqual(metadata["files"], [f"{run_id}/inbound.txt"])

    def test_policy_results_use_same_run_directory_for_multiple_files(self):
        # Lightweight contract test for file path construction used by policy and direction modes.
        with tempfile.TemporaryDirectory() as tmp:
            from web.analysis_scheduler import _save_result

            results_root = Path(tmp)
            run_dir = results_root / "20260612T120000Z-deadbeef"
            run_dir.mkdir()
            events = []

            with patch("web.analysis_scheduler.get_results_dir_path", return_value=results_root):
                files, texts = _save_result(
                    "POLICY REPORT\n",
                    SchedulerEmitter(events.append),
                    run_dir,
                    "policy_100",
                    "2026-06-01 00:00:00",
                    "2026-06-01 01:00:00",
                    "policyid=100",
                    "both",
                )

            self.assertEqual([f["path"] for f in files], [
                "20260612T120000Z-deadbeef/policy_100.txt",
                "20260612T120000Z-deadbeef/policy_100.csv",
            ])
            self.assertIn("policy_100.txt", texts)
            self.assertTrue((run_dir / "policy_100.txt").exists())
            self.assertTrue((run_dir / "policy_100.csv").exists())


if __name__ == "__main__":
    unittest.main()
