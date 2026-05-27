import asyncio
import importlib
import logging
import socket
import unittest
from unittest.mock import patch

import utils.network as network


class ReverseDnsCacheTests(unittest.TestCase):
    def tearDown(self):
        network.clear_hostname_cache()
        network._last_reverse_dns_enabled = None

    def test_resolve_retries_after_reverse_dns_toggle(self):
        enabled = True

        def reverse_dns_enabled():
            return enabled

        with (
            patch.object(network, "get_dynamic_reverse_dns_enabled", side_effect=reverse_dns_enabled),
            patch.object(
                network.socket,
                "gethostbyaddr",
                side_effect=[socket.herror(), ("host.example", [], ["192.0.2.10"])],
            ) as gethostbyaddr,
        ):
            self.assertEqual(network.resolve_hostname("192.0.2.10"), "192.0.2.10")
            self.assertEqual(network.resolve_hostname("192.0.2.10"), "192.0.2.10")
            self.assertEqual(gethostbyaddr.call_count, 1)

            enabled = False
            self.assertEqual(network.resolve_hostname("192.0.2.10"), "192.0.2.10")

            enabled = True
            self.assertEqual(network.resolve_hostname("192.0.2.10"), "host.example")
            self.assertEqual(gethostbyaddr.call_count, 2)


class WebSettingsReverseDnsTests(unittest.TestCase):
    def test_saving_reverse_dns_setting_clears_cache(self):
        with (
            patch("logging.FileHandler", side_effect=lambda *args, **kwargs: logging.NullHandler()),
            patch("logging.StreamHandler", side_effect=lambda *args, **kwargs: logging.NullHandler()),
        ):
            web_app = importlib.import_module("web.app")

        with (
            patch("web.app.update_env_file") as update_env_file,
            patch("web.app.clear_hostname_cache") as clear_hostname_cache,
        ):
            result = asyncio.run(
                web_app.update_settings(web_app.SettingsUpdate(disable_reverse_dns=False))
            )

        update_env_file.assert_called_once_with({"DISABLE_REVERSE_DNS": "false"})
        clear_hostname_cache.assert_called_once_with()
        self.assertEqual(result, {"status": "ok", "updated": 1})


if __name__ == "__main__":
    unittest.main()
