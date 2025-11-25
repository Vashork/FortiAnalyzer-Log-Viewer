import sys
import time
from typing import Optional, List, Dict, Tuple

import requests
import urllib3

from config import EMPTY_BATCH_LIMIT

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FortiAnalyzerClient:
    """Simple JSON-RPC client for FortiAnalyzer logsearch API."""

    def __init__(self, url: str, username: str, password: str):
        self.url = url
        self.username = username
        self.password = password
        self.session: Optional[str] = None
        # session id only for first login request
        self._login_session_id = "1"

    # ==========================
    #  Low-level wrapper
    # ==========================

    def _post(self, payload: Dict, timeout: int = 30) -> Dict:
        """HTTP POST wrapper with error logging."""
        try:
            response = requests.post(self.url, json=payload, timeout=timeout, verify=False)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"✗ HTTP error: {e}")
            raise

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
            else:
                print(f"✗ Login failed: {result}")
                return False
        except Exception:
            return False

    def logout(self) -> bool:
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
        """Creates a logsearch task and returns tid (task id). Supports both FAZ reply formats."""
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
                print(f"✓ Created search task with ID: {tid}")
                return tid

            if isinstance(raw, list) and raw and "tid" in raw[0]:
                tid = raw[0]["tid"]
                print(f"✓ Created search task with ID: {tid}")
                return tid

            print(f"✗ Failed to create search task: {result}")
            return None

        except Exception as e:
            print(f"✗ Search task creation error: {e}")
            return None

    def wait_for_task_completion(self, task_id: int, max_wait_seconds: int = 300) -> Tuple[bool, int]:
        """Waits for task to complete and returns (True, matched_logs)."""
        start_ts = time.time()
        last_progress = -1

        while time.time() - start_ts < max_wait_seconds:
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
                    time.sleep(5)
                    continue

                print(f"✗ Task failed with status code: {status_code}")
                return False, 0

            except Exception as e:
                print(f"✗ Error checking task status: {e}")
                time.sleep(5)

        print("✗ Task did not complete within allowed time")
        return False, 0

    # ==========================
    #  REAL WORKING FETCH LOGS
    #  (из первой стабильной версии)
    # ==========================

    def fetch_logs(self, task_id: int, total_logs: int, batch_size: int = 100) -> List[Dict]:

        all_logs: List[Dict] = []
        offset = 0

        MAX_EMPTY_RETRIES = 10
        MAX_INCOMPLETE_RETRIES = 3

        print(f"📥 Fetching logs (matched={total_logs}, batch={batch_size})...")

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
                try:
                    response = requests.post(self.url, json=payload, timeout=30, verify=False)
                    response.raise_for_status()
                    result = response.json()

                    data = result.get("result", {}).get("data", [])

                except Exception as e:
                    empty_retry += 1
                    if empty_retry <= MAX_EMPTY_RETRIES:
                        print(f"✗ Error at offset {offset}, retrying ({empty_retry}/{MAX_EMPTY_RETRIES}): {e}")
                        time.sleep(3)
                        continue
                    else:
                        print(f"✗ Max retries reached at offset {offset}")
                        return all_logs

                # CASE 1: empty batch
                if not data:
                    if empty_retry < MAX_EMPTY_RETRIES:
                        empty_retry += 1
                        print(f"⚠️ Empty data received at offset {offset}, retrying ({empty_retry}/{MAX_EMPTY_RETRIES})...")
                        time.sleep(3)
                        continue
                    else:
                        print(f"⚠️ No data at offset {offset} after {MAX_EMPTY_RETRIES} retries.")
                        return all_logs

                # CASE 2: incomplete batch
                if len(data) < batch_size and (total_logs - offset) > len(data):
                    incomplete_retry += 1
                    if incomplete_retry <= MAX_INCOMPLETE_RETRIES:
                        print(f"⚠️ Incomplete batch at offset {offset}: got {len(data)}, retrying ({incomplete_retry}/{MAX_INCOMPLETE_RETRIES})...")
                        time.sleep(3)
                        continue
                    else:
                        print(f"⚠️ Incomplete batch persists, accepting partial {len(data)}")
                        all_logs.extend(data)
                        offset += len(data)
                        print(f"📥 Fetched {len(all_logs)}/{total_logs} logs")
                        break

                # CASE 3: normal batch
                all_logs.extend(data)
                offset += len(data)
                print(f"📥 Fetched {len(all_logs)}/{total_logs} logs")
                break

        if len(all_logs) != total_logs:
            print(f"⚠️ Warning: Expected {total_logs} logs but got {len(all_logs)}")

        return all_logs
