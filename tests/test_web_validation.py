import importlib
import logging
import unittest
from unittest.mock import patch

from pydantic import ValidationError


class WebValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with (
            patch("logging.FileHandler", side_effect=lambda *args, **kwargs: logging.NullHandler()),
            patch("logging.StreamHandler", side_effect=lambda *args, **kwargs: logging.NullHandler()),
        ):
            cls.web_app = importlib.import_module("web.app")

    def assert_model_rejects(self, model_cls, **payload):
        with self.assertRaises(ValidationError):
            model_cls(**payload)

    def test_analyze_rejects_invalid_time_mode_before_config_validation(self):
        self.assert_model_rejects(self.web_app.AnalysisRequest, time_mode="forever")

    def test_analyze_rejects_too_many_workers(self):
        self.assert_model_rejects(self.web_app.AnalysisRequest, workers=999)

    def test_analyze_rejects_invalid_ports(self):
        self.assert_model_rejects(
            self.web_app.AnalysisRequest,
            proto_enabled=True,
            ports="22,70000",
        )

    def test_analyze_rejects_huge_target_network(self):
        self.assert_model_rejects(
            self.web_app.AnalysisRequest,
            use_machines_file=False,
            targets=[{"ip": "10.0.0.0", "mask": "/8"}],
        )

    def test_settings_rejects_invalid_split_mode(self):
        self.assert_model_rejects(self.web_app.SettingsUpdate, session_split_mode="auto")


if __name__ == "__main__":
    unittest.main()
