import unittest
from types import SimpleNamespace
from unittest.mock import patch

import config
from analyzer import log_analyzer
from analyzer.analysis_config import AnalysisConfig
from web.analysis_scheduler import _collect_request_context


class RequestScopedConfigTests(unittest.TestCase):
    def request(self, **overrides):
        data = {
            "time_mode": "exact",
            "time_value": 24,
            "start_time": "2026-06-01T00:00:00",
            "end_time": "2026-06-01T01:00:00",
            "use_machines_file": False,
            "targets": [],
            "exclude_internal": False,
            "proto_enabled": False,
            "ports": "",
            "columns": {"action": True, "smart_action": True},
            "smart_action": "deny",
        }
        data.update(overrides)
        return SimpleNamespace(**data)

    def test_collect_request_context_does_not_mutate_module_level_config(self):
        original_smart_action = config.SMART_ACTION
        original_columns = dict(config.COLUMNS_CONFIG)
        try:
            config.SMART_ACTION = "all"
            config.COLUMNS_CONFIG["action"] = False
            config.COLUMNS_CONFIG["smart_action"] = False

            _collect_request_context(self.request())

            self.assertEqual(config.SMART_ACTION, "all")
            self.assertFalse(config.COLUMNS_CONFIG["action"])
            self.assertFalse(config.COLUMNS_CONFIG["smart_action"])
        finally:
            config.SMART_ACTION = original_smart_action
            config.COLUMNS_CONFIG.clear()
            config.COLUMNS_CONFIG.update(original_columns)

    def test_build_faz_filter_uses_explicit_smart_action_without_global_mutation(self):
        original_smart_action = log_analyzer.SMART_ACTION
        try:
            log_analyzer.SMART_ACTION = "all"

            filter_str = log_analyzer.build_faz_filter(
                "inbound",
                ["10.0.0.10"],
                smart_action="deny",
                filter_mode="faz",
            )

            self.assertIn('action="deny"', filter_str)
            self.assertEqual(log_analyzer.SMART_ACTION, "all")
        finally:
            log_analyzer.SMART_ACTION = original_smart_action
    def test_analysis_config_is_immutable_request_snapshot(self):
        columns = {"action": True}
        aggregation = {"remote_ip": False}
        request = self.request(columns=columns, smart_action="DENY")
        request.aggregation = aggregation

        analysis_config = AnalysisConfig.from_request(request, filter_mode="FAZ")
        columns["action"] = False
        aggregation["remote_ip"] = True

        self.assertEqual(analysis_config.smart_action, "deny")
        self.assertEqual(analysis_config.filter_mode, "faz")
        self.assertEqual(analysis_config.columns["action"], True)
        self.assertEqual(analysis_config.aggregation["remote_ip"], False)
        with self.assertRaises(Exception):
            analysis_config.smart_action = "all"


if __name__ == "__main__":
    unittest.main()
