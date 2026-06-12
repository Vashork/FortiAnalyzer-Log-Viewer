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
        if hasattr(network, "configure_reverse_dns"):
            network.configure_reverse_dns(None)

    def test_resolve_uses_configured_reverse_dns_flag_without_env_reload_per_ip(self):
        with (
            patch.object(network, "get_dynamic_reverse_dns_enabled", side_effect=AssertionError("env reloaded in hot path")),
            patch.object(
                network.socket,
                "gethostbyaddr",
                side_effect=[("host-a.example", [], ["192.0.2.10"]), ("host-b.example", [], ["192.0.2.11"])],
            ) as gethostbyaddr,
        ):
            network.configure_reverse_dns(True)
            self.assertEqual(network.resolve_hostname("192.0.2.10"), "host-a.example")
            self.assertEqual(network.resolve_hostname("192.0.2.11"), "host-b.example")

        self.assertEqual(gethostbyaddr.call_count, 2)

    def test_resolve_hostname_does_not_change_global_socket_timeout(self):
        with (
            patch.object(network, "get_dynamic_reverse_dns_enabled", return_value=True),
            patch.object(network.socket, "setdefaulttimeout", side_effect=AssertionError("global timeout changed")),
            patch.object(network.socket, "gethostbyaddr", return_value=("host.example", [], ["192.0.2.10"])),
        ):
            network.configure_reverse_dns(True)
            self.assertEqual(network.resolve_hostname("192.0.2.10"), "host.example")

    def test_resolve_retries_after_reverse_dns_toggle(self):
        with patch.object(
            network.socket,
            "gethostbyaddr",
            side_effect=[socket.herror(), ("host.example", [], ["192.0.2.10"])],
        ) as gethostbyaddr:
            network.configure_reverse_dns(True)
            self.assertEqual(network.resolve_hostname("192.0.2.10"), "192.0.2.10")
            self.assertEqual(network.resolve_hostname("192.0.2.10"), "192.0.2.10")
            self.assertEqual(gethostbyaddr.call_count, 1)

            network.configure_reverse_dns(False)
            self.assertEqual(network.resolve_hostname("192.0.2.10"), "192.0.2.10")

            network.configure_reverse_dns(True)
            self.assertEqual(network.resolve_hostname("192.0.2.10"), "host.example")
            self.assertEqual(gethostbyaddr.call_count, 2)

    def test_resolve_hostnames_uses_cache_and_bounded_bulk_lookup(self):
        with patch.object(
            network.socket,
            "gethostbyaddr",
            side_effect=lambda ip: (f"host-{ip}", [], [ip]),
        ) as gethostbyaddr:
            network.configure_reverse_dns(True)
            first = network.resolve_hostnames(["192.0.2.10", "192.0.2.11", "192.0.2.10"], max_workers=2)
            second = network.resolve_hostnames(["192.0.2.10", "192.0.2.11"], max_workers=2)

        self.assertEqual(first["192.0.2.10"], "host-192.0.2.10")
        self.assertEqual(first["192.0.2.11"], "host-192.0.2.11")
        self.assertEqual(second, first)
        self.assertEqual(gethostbyaddr.call_count, 2)

    def test_resolve_hostname_refreshes_expired_ttl_cache_entry(self):
        with (
            patch.object(network, "_reverse_dns_cache_ttl", 0.001),
            patch.object(
                network.socket,
                "gethostbyaddr",
                side_effect=[("old.example", [], ["192.0.2.10"]), ("new.example", [], ["192.0.2.10"])],
            ) as gethostbyaddr,
        ):
            network.configure_reverse_dns(True)
            self.assertEqual(network.resolve_hostname("192.0.2.10"), "old.example")
            import time
            time.sleep(0.01)
            self.assertEqual(network.resolve_hostname("192.0.2.10"), "new.example")

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
            patch("web.app.configure_reverse_dns") as configure_reverse_dns,
        ):
            result = asyncio.run(
                web_app.update_settings(web_app.SettingsUpdate(disable_reverse_dns=False))
            )

        update_env_file.assert_called_once_with({"DISABLE_REVERSE_DNS": "false"})
        clear_hostname_cache.assert_called_once_with()
        configure_reverse_dns.assert_called_once_with(True)
        self.assertEqual(result, {"status": "ok", "updated": 1})


if __name__ == "__main__":
    unittest.main()
