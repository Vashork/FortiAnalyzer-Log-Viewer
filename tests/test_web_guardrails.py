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
        self.assertEqual(payload["preview_bytes"], 10)
        self.assertEqual(payload["download_url"], "/api/results/download/large.txt")

    def test_result_preview_respects_line_limit_even_when_byte_limit_is_large(self):
        web_app = self.import_web_app()
        with tempfile.TemporaryDirectory() as tmpdir:
            results_dir = Path(tmpdir)
            result_file = results_dir / "multi-line.txt"
            result_file.write_text("line1\nline2\nline3\n", encoding="utf-8")

            with patch.object(web_app, "_results_dir_path", return_value=results_dir.resolve()):
                payload = asyncio.run(web_app.get_result("multi-line.txt", max_bytes=1000, max_lines=2))

        self.assertEqual(payload["content"], "line1\nline2\n")
        self.assertTrue(payload["truncated"])
        self.assertEqual(payload["preview_lines"], 2)
        self.assertEqual(payload["total_lines_read"], 3)
        self.assertEqual(payload["preview_limit"], 1000)

    def test_result_preview_query_limits_are_clamped(self):
        web_app = self.import_web_app({"MAX_RESULT_PREVIEW_BYTES": "20", "MAX_RESULT_PREVIEW_LINES": "3"})
        with tempfile.TemporaryDirectory() as tmpdir:
            results_dir = Path(tmpdir)
            result_file = results_dir / "large.txt"
            result_file.write_text("a" * 100, encoding="utf-8")

            with patch.object(web_app, "_results_dir_path", return_value=results_dir.resolve()):
                payload = asyncio.run(web_app.get_result("large.txt", max_bytes=99999999, max_lines=99999999))

        self.assertEqual(payload["preview_bytes"], 20)
        self.assertLessEqual(payload["preview_lines"], 3)
        self.assertTrue(payload["truncated"])

    def test_ui_warns_when_preview_is_truncated_and_keeps_download_path(self):
        script = (Path(__file__).resolve().parents[1] / "web" / "static" / "script.js").read_text(encoding="utf-8")

        self.assertIn("d.truncated", script)
        self.assertIn("download_url", script)
        self.assertIn("Показан фрагмент", script)


if __name__ == "__main__":
    unittest.main()
