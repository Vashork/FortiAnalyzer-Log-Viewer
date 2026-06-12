import unittest
from unittest.mock import Mock, patch

import requests
from requests.adapters import HTTPAdapter

from client.faz_client import FortiAnalyzerClient


class FortiAnalyzerClientSessionTests(unittest.TestCase):
    def test_client_uses_reusable_session_with_connection_pooling(self):
        client = FortiAnalyzerClient(
            "https://faz.example/jsonrpc",
            "admin",
            "secret",
            pool_connections=7,
            pool_maxsize=13,
        )

        self.assertIsInstance(client.http, requests.Session)
        for prefix in ("https://", "http://"):
            adapter = client.http.adapters[prefix]
            self.assertIsInstance(adapter, HTTPAdapter)
            self.assertEqual(adapter._pool_connections, 7)
            self.assertEqual(adapter._pool_maxsize, 13)

    def test_tls_verify_defaults_to_false_for_existing_self_signed_appliance_compatibility(self):
        client = FortiAnalyzerClient("https://faz.example/jsonrpc", "admin", "secret")

        self.assertIs(client.verify, False)

    def test_ca_bundle_path_is_used_as_requests_verify_value(self):
        client = FortiAnalyzerClient(
            "https://faz.example/jsonrpc",
            "admin",
            "secret",
            verify_tls=True,
            ca_bundle="/etc/ssl/faz-ca.pem",
        )

        self.assertEqual(client.verify, "/etc/ssl/faz-ca.pem")

    def test_post_uses_session_verify_and_timeout_tuple(self):
        client = FortiAnalyzerClient(
            "https://faz.example/jsonrpc",
            "admin",
            "secret",
            verify_tls=True,
            connect_timeout=4,
            read_timeout=40,
        )
        response = Mock()
        response.json.return_value = {"ok": True}
        client.http.post = Mock(return_value=response)

        result = client._post({"id": 1})

        self.assertEqual(result, {"ok": True})
        client.http.post.assert_called_once_with(
            "https://faz.example/jsonrpc",
            json={"id": 1},
            timeout=(4, 40),
            verify=True,
        )
        response.raise_for_status.assert_called_once()

    def test_post_retries_transient_connection_error_then_succeeds(self):
        client = FortiAnalyzerClient(
            "https://faz.example/jsonrpc",
            "admin",
            "secret",
            retry_attempts=2,
            retry_backoff_seconds=0,
        )
        response = Mock()
        response.json.return_value = {"ok": True}
        client.http.post = Mock(side_effect=[requests.ConnectionError("temporary"), response])

        result = client._post({"id": 1})

        self.assertEqual(result, {"ok": True})
        self.assertEqual(client.http.post.call_count, 2)

    def test_post_retries_http_503_then_succeeds(self):
        client = FortiAnalyzerClient(
            "https://faz.example/jsonrpc",
            "admin",
            "secret",
            retry_attempts=2,
            retry_backoff_seconds=0,
        )
        failed_response = Mock(status_code=503)
        failed_response.raise_for_status.side_effect = requests.HTTPError(
            "service unavailable",
            response=failed_response,
        )
        ok_response = Mock()
        ok_response.json.return_value = {"ok": True}
        client.http.post = Mock(side_effect=[failed_response, ok_response])

        result = client._post({"id": 1})

        self.assertEqual(result, {"ok": True})
        self.assertEqual(client.http.post.call_count, 2)

    def test_post_does_not_retry_auth_http_error(self):
        client = FortiAnalyzerClient(
            "https://faz.example/jsonrpc",
            "admin",
            "secret",
            retry_attempts=3,
            retry_backoff_seconds=0,
        )
        failed_response = Mock(status_code=401)
        failed_response.raise_for_status.side_effect = requests.HTTPError(
            "unauthorized",
            response=failed_response,
        )
        client.http.post = Mock(return_value=failed_response)

        with self.assertRaises(requests.HTTPError):
            client._post({"id": 1})

        client.http.post.assert_called_once()


class FortiAnalyzerClientEnvFactoryTests(unittest.TestCase):
    def test_from_env_reads_tls_and_pool_settings(self):
        env = {
            "FORTIANALYZER_URL": "https://faz.example/jsonrpc",
            "FORTIANALYZER_USERNAME": "admin",
            "FORTIANALYZER_PASSWORD": "secret",
            "FORTIANALYZER_TLS_VERIFY": "true",
            "FORTIANALYZER_CA_BUNDLE": "/etc/ssl/faz-ca.pem",
            "FORTIANALYZER_POOL_CONNECTIONS": "3",
            "FORTIANALYZER_POOL_MAXSIZE": "9",
            "FORTIANALYZER_CONNECT_TIMEOUT": "2",
            "FORTIANALYZER_READ_TIMEOUT": "25",
            "FORTIANALYZER_RETRY_ATTEMPTS": "4",
            "FORTIANALYZER_RETRY_BACKOFF_SECONDS": "0",
        }

        with patch.dict("os.environ", env, clear=False):
            client = FortiAnalyzerClient.from_env()

        self.assertEqual(client.url, "https://faz.example/jsonrpc")
        self.assertEqual(client.username, "admin")
        self.assertEqual(client.password, "secret")
        self.assertEqual(client.verify, "/etc/ssl/faz-ca.pem")
        self.assertEqual(client.pool_connections, 3)
        self.assertEqual(client.pool_maxsize, 9)
        self.assertEqual(client.connect_timeout, 2)
        self.assertEqual(client.read_timeout, 25)
        self.assertEqual(client.retry_attempts, 4)
        self.assertEqual(client.retry_backoff_seconds, 0)


class TimeSplitWorkerClientCompatibilityTests(unittest.TestCase):
    def test_time_split_worker_clients_inherit_main_client_transport_settings(self):
        from analyzer import time_range_analyzer

        main_client = FortiAnalyzerClient(
            "https://faz.example/jsonrpc",
            "admin",
            "secret",
            verify_tls=True,
            ca_bundle="/etc/ssl/faz-ca.pem",
            pool_connections=5,
            pool_maxsize=11,
            connect_timeout=3,
            read_timeout=33,
            retry_attempts=4,
            retry_backoff_seconds=0,
        )
        created_clients = []

        def fake_client(**kwargs):
            client = FortiAnalyzerClient(**kwargs)
            client.login = Mock(return_value=True)
            client.logout = Mock(return_value=True)
            created_clients.append(client)
            return client

        with (
            patch.object(time_range_analyzer, "FortiAnalyzerClient", side_effect=fake_client),
            patch.object(time_range_analyzer, "fetch_logs_for_segments", return_value=[]),
        ):
            result = time_range_analyzer._run_worker_segments(
                main_client=main_client,
                filter_str="dstip=10.0.0.1",
                workers_segments=[[('2026-06-01 00:00:00', '2026-06-01 01:00:00')]],
                target_ips=["10.0.0.1"],
                batch_size=100,
                num_workers=1,
            )

        self.assertEqual(result, {0: []})
        self.assertEqual(len(created_clients), 1)
        worker = created_clients[0]
        self.assertEqual(worker.verify, "/etc/ssl/faz-ca.pem")
        self.assertEqual(worker.pool_connections, 5)
        self.assertEqual(worker.pool_maxsize, 11)
        self.assertEqual(worker.connect_timeout, 3)
        self.assertEqual(worker.read_timeout, 33)
        self.assertEqual(worker.retry_attempts, 4)
        self.assertEqual(worker.retry_backoff_seconds, 0)


if __name__ == "__main__":
    unittest.main()
