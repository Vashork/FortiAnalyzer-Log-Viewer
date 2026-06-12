import asyncio
import importlib
import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError


class WebGuardrailTests(unittest.TestCase):
    def import_web_app(self, env_updates=None):
        env = os.environ.copy()
        if env_updates:
            env.update(env_updates)
        with (
            patch.dict(os.environ, env, clear=True),
            patch("logging.FileHandler", side_effect=lambda *args, **kwargs: logging.NullHandler()),
            patch("logging.StreamHandler", side_effect=lambda *args, **kwargs: logging.NullHandler()),
        ):
            import web.app as web_app
            return importlib.reload(web_app)

    def test_cors_uses_env_allowlist_without_wildcard(self):
        web_app = self.import_web_app({"WEB_CORS_ALLOW_ORIGINS": "https://allowed.example"})

        cors_middleware = next(
            middleware for middleware in web_app.app.user_middleware
            if middleware.cls.__name__ == "CORSMiddleware"
        )

        self.assertEqual(cors_middleware.kwargs["allow_origins"], ["https://allowed.example"])
        self.assertNotIn("*", cors_middleware.kwargs["allow_origins"])

    def test_settings_rejects_absolute_results_dir(self):
        web_app = self.import_web_app()

        with self.assertRaises(ValidationError):
            web_app.SettingsUpdate(results_dir="/tmp/falv2-outside-results")

    def test_settings_rejects_results_dir_parent_traversal(self):
        web_app = self.import_web_app()

        with self.assertRaises(ValidationError):
            web_app.SettingsUpdate(results_dir="../outside-results")

    def test_results_dir_endpoint_guard_rejects_path_outside_project(self):
        web_app = self.import_web_app()
        outside = Path(tempfile.gettempdir()) / "falv2-outside-results"

        with patch.object(web_app, "get_results_dir_path", return_value=outside):
            with self.assertRaises(web_app.HTTPException) as ctx:
                web_app._results_dir_path()

        self.assertEqual(ctx.exception.status_code, 500)
        self.assertIn("project directory", ctx.exception.detail)

    def test_result_preview_is_limited_and_reports_truncation(self):
        web_app = self.import_web_app()
        with tempfile.TemporaryDirectory() as tmpdir:
            results_dir = Path(tmpdir)
            result_file = results_dir / "large.txt"
            result_file.write_text("0123456789ABCDEFGHIJ", encoding="utf-8")

            with (
                patch.object(web_app, "_results_dir_path", return_value=results_dir.resolve()),
                patch.object(web_app, "MAX_RESULT_PREVIEW_BYTES", 10),
            ):
                payload = asyncio.run(web_app.get_result("large.txt"))

        self.assertEqual(payload["name"], "large.txt")
        self.assertEqual(payload["content"], "0123456789")
        self.assertTrue(payload["truncated"])
        self.assertEqual(payload["size"], 20)
        self.assertEqual(payload["preview_limit"], 10)


if __name__ == "__main__":
    unittest.main()
