import importlib
import logging
import unittest
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


if __name__ == "__main__":
    unittest.main()
