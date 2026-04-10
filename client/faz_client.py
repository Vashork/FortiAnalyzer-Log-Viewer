import time
from typing import Optional, List, Dict, Tuple

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from config import EMPTY_BATCH_LIMIT


class FortiAnalyzerClient:
    """Simple JSON-RPC client for FortiAnalyzer logsearch API."""

    def __init__(self, url: str, username: str, password: str, cancel_check=None):
        self.url = url
        self.username = username
        self.password = password
        self.session: Optional[str] = None
        self._login_session_id = "1"
        self.cancel_check = cancel_check  # callable() -> bool
        self._active_tasks: List[int] = []  # отслеживаем созданные search tasks

    # ==========================
    #  Low-level wrapper
    # ==========================

    def _post(self, payload: Dict, timeout: int = 30) -> Dict:
        response = requests.post(self.url, json=payload, timeout=timeout, verify=False)
        response.raise_for_status()
        return response.json()

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

    def logout(self) -> bool:
        # Перед logout отменяем все активные search tasks
        if self._active_tasks:
            self.cancel_all_tasks()

        if not self.session:
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
                    raw = result.get("result", {})

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

    def fetch_logs(self, task_id: int, total_logs: int, batch_size: int = 100) -> List[Dict]:
        all_logs: List[Dict] = []
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
                        return all_logs

                    try:
                        result = self._post(payload)
                        data = result.get("result", {}).get("data", [])

                    except Exception as e:
                        empty_retry += 1
                        if empty_retry <= EMPTY_BATCH_LIMIT:
                            print(f"✗ Error at offset {offset}, retrying ({empty_retry}/{EMPTY_BATCH_LIMIT}): {e}")
                            time.sleep(3)
                            continue
                        print(f"✗ Max retries reached at offset {offset}")
                        return all_logs

                    if not data:
                        empty_retry += 1
                        if empty_retry <= EMPTY_BATCH_LIMIT:
                            print(f"⚠️ Empty data received at offset {offset}, retrying ({empty_retry}/{EMPTY_BATCH_LIMIT})...")
                            time.sleep(3)
                            continue
                        print(f"⚠️ No data at offset {offset} after {EMPTY_BATCH_LIMIT} retries.")
                        return all_logs

                    if len(data) < batch_size and (total_logs - offset) > len(data):
                        incomplete_retry += 1
                        if incomplete_retry <= MAX_INCOMPLETE_RETRIES:
                            print(f"⚠️ Incomplete batch at offset {offset}: got {len(data)}, retrying ({incomplete_retry}/{MAX_INCOMPLETE_RETRIES})...")
                            time.sleep(3)
                            continue
                        print(f"⚠️ Incomplete batch persists, accepting partial {len(data)}")

                    all_logs.extend(data)
                    offset += len(data)
                    print(f"📥 Fetched {len(all_logs)}/{total_logs} logs")
                    break

        except KeyboardInterrupt:
            print(f"\n⛔ Interrupted during fetch at offset {offset}. "
                  f"Using {len(all_logs)} already fetched logs.")
            return all_logs

        if len(all_logs) != total_logs:
            print(f"⚠️ Warning: Expected {total_logs} logs but got {len(all_logs)}")

        return all_logs
