import os
import time
from typing import Iterator, Optional, List, Dict, Tuple, Union

import requests
import urllib3
from requests.adapters import HTTPAdapter

from config import EMPTY_BATCH_LIMIT


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return int(value)


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise ValueError(f"Missing required environment variable: {name}")
    return value


class FortiAnalyzerClient:
    """Simple JSON-RPC client for FortiAnalyzer logsearch API."""

    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        cancel_check=None,
        *,
        verify_tls: bool = False,
        ca_bundle: Optional[str] = None,
        pool_connections: int = 10,
        pool_maxsize: int = 10,
        connect_timeout: int = 5,
        read_timeout: int = 30,
    ):
        self.url = url
        self.username = username
        self.password = password
        self.session: Optional[str] = None
        self._login_session_id = "1"
        self.cancel_check = cancel_check  # callable() -> bool
        self._active_tasks: List[int] = []  # отслеживаем созданные search tasks
        self.verify_tls = verify_tls
        self.ca_bundle = ca_bundle.strip() if ca_bundle else None
        self.verify: Union[bool, str] = self.ca_bundle if verify_tls and self.ca_bundle else verify_tls
        self.pool_connections = pool_connections
        self.pool_maxsize = pool_maxsize
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.http = requests.Session()
        adapter = HTTPAdapter(pool_connections=pool_connections, pool_maxsize=pool_maxsize)
        self.http.mount("https://", adapter)
        self.http.mount("http://", adapter)
        if self.verify is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            print("⚠ FortiAnalyzer TLS verification is disabled (FORTIANALYZER_TLS_VERIFY=false)")

    @classmethod
    def from_env(cls, cancel_check=None) -> "FortiAnalyzerClient":
        """Create a client from environment variables with safe compatibility defaults."""
        verify_tls = _env_bool("FORTIANALYZER_TLS_VERIFY", False)
        return cls(
            url=_required_env("FORTIANALYZER_URL"),
            username=_required_env("FORTIANALYZER_USERNAME"),
            password=_required_env("FORTIANALYZER_PASSWORD"),
            cancel_check=cancel_check,
            verify_tls=verify_tls,
            ca_bundle=os.getenv("FORTIANALYZER_CA_BUNDLE") or None,
            pool_connections=_env_int("FORTIANALYZER_POOL_CONNECTIONS", 10),
            pool_maxsize=_env_int("FORTIANALYZER_POOL_MAXSIZE", 10),
            connect_timeout=_env_int("FORTIANALYZER_CONNECT_TIMEOUT", 5),
            read_timeout=_env_int("FORTIANALYZER_READ_TIMEOUT", 30),
        )

    def transport_kwargs(self) -> Dict:
        """Return transport settings for worker clients spawned from this client."""
        return {
            "verify_tls": self.verify_tls,
            "ca_bundle": self.ca_bundle,
            "pool_connections": self.pool_connections,
            "pool_maxsize": self.pool_maxsize,
            "connect_timeout": self.connect_timeout,
            "read_timeout": self.read_timeout,
        }

    # ==========================
    #  Low-level wrapper
    # ==========================

    def _post(self, payload: Dict, timeout: Optional[Union[int, Tuple[int, int]]] = None) -> Dict:
        request_timeout = timeout if timeout is not None else (self.connect_timeout, self.read_timeout)
        response = self.http.post(self.url, json=payload, timeout=request_timeout, verify=self.verify)
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _normalize_result(payload: Dict) -> Dict:
        """FAZ иногда возвращает result как dict, а иногда как list[dict]."""
        raw = payload.get("result", {})
        if isinstance(raw, list):
            return raw[0] if raw else {}
        return raw if isinstance(raw, dict) else {}

    # ==========================
    #  Authentication
    # ==========================

    def login(self) -> bool:
        payload = {
            "method": "exec",
            "params": [
                {
                    "data": {"user": self.username, "passwd": self.password},
                    "url": "/sys/login/user",
                }
            ],
            "session": self._login_session_id,
            "id": 1,
        }
        try:
            result = self._post(payload)
            if result.get("result") and result["result"][0]["status"]["code"] == 0:
                self.session = result["session"]
                print("✓ Successfully logged in to FortiAnalyzer")
                return True
            print(f"✗ Login failed: {result}")
            return False
        except Exception:
            return False

    def close(self) -> None:
        """Close the underlying reusable HTTP session."""
        self.http.close()

    def logout(self) -> bool:
        # Перед logout отменяем все активные search tasks
        if self._active_tasks:
            self.cancel_all_tasks()

        if not self.session:
            self.close()
            return True

        payload = {
            "method": "exec",
            "params": [{"url": "/sys/logout"}],
            "session": self.session,
            "id": 1,
        }
        try:
            self._post(payload)
            print("✓ Successfully logged out")
            return True
        except Exception as e:
            print(f"✗ Logout error: {e}")
            return False
        finally:
            self.close()

    # ==========================
    #  Log Search
    # ==========================

    def create_search_task(self, filter_str: str, start_time: str, end_time: str) -> Optional[int]:
        payload = {
            "id": "123456789",
            "jsonrpc": "2.0",
            "method": "add",
            "params": [
                {
                    "apiver": 3,
                    "case-sensitive": False,
                    "device": [{"devid": "All_Devices"}],
                    "filter": filter_str,
                    "logtype": "traffic",
                    "time-order": "asc",
                    "time-range": {"start": start_time, "end": end_time},
                    "url": "/logview/adom/root/logsearch",
                }
            ],
            "session": self.session,
        }

        try:
            result = self._post(payload)
            raw = result.get("result")

            if isinstance(raw, dict) and "tid" in raw:
                tid = raw["tid"]
                self._active_tasks.append(tid)  # трекаем созданный task
                print(f"✓ Created search task with ID: {tid}")
                return tid

            print(f"✗ Failed to create search task: {result}")
            return None

        except Exception as e:
            print(f"✗ Search task creation error: {e}")
            return None

    def cancel_search_task(self, task_id: int) -> bool:
        """Отменяет search task на сервере FAZ."""
        if not self.session:
            return False
        payload = {
            "id": "123456789",
            "jsonrpc": "2.0",
            "method": "delete",
            "params": [{"apiver": 3, "url": f"/logview/adom/root/logsearch/{task_id}"}],
            "session": self.session,
        }
        try:
            self._post(payload)
            print(f"  ⏹ Cancelled search task {task_id} on FAZ")
            return True
        except Exception as e:
            print(f"  ⚠ Failed to cancel task {task_id}: {e}")
            return False

    def cancel_all_tasks(self) -> None:
        """Отменяет все активные search tasks."""
        for task_id in list(self._active_tasks):
            if self.cancel_check and self.cancel_check():
                break
            self.cancel_search_task(task_id)
        self._active_tasks.clear()

    def wait_for_task_completion(self, task_id: int, max_wait_seconds: int = 300) -> Tuple[bool, int]:
        start_ts = time.time()
        last_progress = -1

        try:
            while time.time() - start_ts < max_wait_seconds:
                # Проверяем отмену
                if self.cancel_check and self.cancel_check():
                    print(f"  ⏹ Cancelled by user (wait_for_task_completion)")
                    self.cancel_search_task(task_id)  # отменяем task на сервере
                    if task_id in self._active_tasks:
                        self._active_tasks.remove(task_id)
                    return False, 0

                payload = {
                    "id": "123456789",
                    "jsonrpc": "2.0",
                    "method": "get",
                    "params": [
                        {
                            "apiver": 3,
                            "url": f"/logview/adom/root/logsearch/count/{task_id}",
                        }
                    ],
                    "session": self.session,
                }

                try:
                    result = self._post(payload)
                    raw = self._normalize_result(result)

                    status = raw.get("status", {})
                    status_code = status.get("code", -1)
                    matched_logs = raw.get("matched-logs", 0)
                    progress = raw.get("progress-percent", 0)

                    if progress != last_progress:
                        print(f"Progress: {progress}%")
                        last_progress = progress

                    if status_code == 0 and progress == 100:
                        print(f"✓ Task completed successfully. Found {matched_logs} matching logs")
                        return True, matched_logs

                    if status_code in (0, 1):
                        # Проверяем отмену во время ожидания
                        for _ in range(10):  # разбиваем sleep(5) на 10 × 0.5s
                            if self.cancel_check and self.cancel_check():
                                return False, 0
                            time.sleep(0.5)
                        continue

                    print(f"✗ Task failed with status code: {status_code}")
                    return False, 0

                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    print(f"✗ Error checking task status: {e}")
                    time.sleep(5)

        except KeyboardInterrupt:
            print("\n⛔ Interrupted while waiting for FAZ task completion.")
            return False, 0

        print("✗ Task did not complete within allowed time")
        return False, 0

    # ==========================
    #  Fetch Logs
    # ==========================

    def iter_fetch_logs(self, task_id: int, total_logs: int, batch_size: int = 100) -> Iterator[List[Dict]]:
        offset = 0

        MAX_INCOMPLETE_RETRIES = 3

        print(f"📥 Fetching logs (matched={total_logs}, batch={batch_size})...")

        try:
            while offset < total_logs:

                payload = {
                    "id": "123456789",
                    "jsonrpc": "2.0",
                    "method": "get",
                    "params": [{
                        "apiver": 3,
                        "limit": batch_size,
                        "offset": offset,
                        "url": f"/logview/adom/root/logsearch/{task_id}"
                    }],
                    "session": self.session
                }

                empty_retry = 0
                incomplete_retry = 0

                while True:
                    # Проверяем отмену перед каждым запросом
                    if self.cancel_check and self.cancel_check():
                        print(f"  ⏹ Cancelled by user (fetch_logs at offset {offset})")
                        self.cancel_search_task(task_id)  # отменяем task на сервере
                        if task_id in self._active_tasks:
                            self._active_tasks.remove(task_id)
                        return

                    try:
                        result = self._post(payload)
                        data = self._normalize_result(result).get("data", [])

                    except Exception as e:
                        empty_retry += 1
                        if empty_retry <= EMPTY_BATCH_LIMIT:
                            print(f"✗ Error at offset {offset}, retrying ({empty_retry}/{EMPTY_BATCH_LIMIT}): {e}")
                            time.sleep(3)
                            continue
                        print(f"✗ Max retries reached at offset {offset}")
                        return

                    if not data:
                        empty_retry += 1
                        if empty_retry <= EMPTY_BATCH_LIMIT:
                            print(f"⚠️ Empty data received at offset {offset}, retrying ({empty_retry}/{EMPTY_BATCH_LIMIT})...")
                            time.sleep(3)
                            continue
                        print(f"⚠️ No data at offset {offset} after {EMPTY_BATCH_LIMIT} retries.")
                        return

                    if len(data) < batch_size and (total_logs - offset) > len(data):
                        incomplete_retry += 1
                        if incomplete_retry <= MAX_INCOMPLETE_RETRIES:
                            print(f"⚠️ Incomplete batch at offset {offset}: got {len(data)}, retrying ({incomplete_retry}/{MAX_INCOMPLETE_RETRIES})...")
                            time.sleep(3)
                            continue
                        print(f"⚠️ Incomplete batch persists, accepting partial {len(data)}")

                    offset += len(data)
                    print(f"📥 Fetched {offset}/{total_logs} logs")
                    yield data
                    break

        except KeyboardInterrupt:
            print(f"\n⛔ Interrupted during fetch at offset {offset}. "
                  f"Using {offset} already fetched logs.")
            return

        if offset != total_logs:
            print(f"⚠️ Warning: Expected {total_logs} logs but got {offset}")

    def fetch_logs(self, task_id: int, total_logs: int, batch_size: int = 100) -> List[Dict]:
        all_logs: List[Dict] = []
        for batch in self.iter_fetch_logs(task_id, total_logs, batch_size):
            all_logs.extend(batch)
        return all_logs
