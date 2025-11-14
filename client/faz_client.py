import sys
import time
import requests
import urllib3
from typing import Optional, List, Dict, Tuple

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FortiAnalyzerClient:
    def __init__(self, url: str, username: str, password: str):
        self.url = url
        self.username = username
        self.password = password
        self.session = None
        self.session_id = "1"

    def login(self) -> bool:
        payload = {
            "method": "exec",
            "params": [{
                "data": {"user": self.username, "passwd": self.password},
                "url": "/sys/login/user"
            }],
            "session": self.session_id,
            "id": 1
        }
        try:
            response = requests.post(self.url, json=payload, timeout=30, verify=False)
            response.raise_for_status()
            result = response.json()
            if result.get("result") and result["result"][0]["status"]["code"] == 0:
                self.session = result["session"]
                print("✓ Successfully logged in to FortiAnalyzer")
                return True
            else:
                print(f"✗ Login failed: {result}")
                return False
        except Exception as e:
            print(f"✗ Login error: {e}")
            return False

    def logout(self) -> bool:
        if not self.session:
            return True
        payload = {
            "method": "exec",
            "params": [{"url": "/sys/logout"}],
            "session": self.session,
            "id": 1
        }
        try:
            response = requests.post(self.url, json=payload, timeout=30, verify=False)
            response.raise_for_status()
            print("✓ Successfully logged out")
            return True
        except Exception as e:
            print(f"✗ Logout error: {e}")
            return False

    def create_search_task(self, filter_str: str, start_time: str, end_time: str) -> Optional[int]:
        payload = {
            "id": "123456789",
            "jsonrpc": "2.0",
            "method": "add",
            "params": [{
                "apiver": 3,
                "case-sensitive": False,
                "device": [{"devid": "All_Devices"}],
                "filter": filter_str,
                "logtype": "traffic",
                "time-order": "asc",
                "time-range": {"start": start_time, "end": end_time},
                "url": "/logview/adom/root/logsearch"
            }],
            "session": self.session
        }
        try:
            response = requests.post(self.url, json=payload, timeout=30, verify=False)
            response.raise_for_status()
            result = response.json()
            if "result" in result and "tid" in result["result"]:
                task_id = result["result"]["tid"]
                print(f"✓ Created search task with ID: {task_id}")
                return task_id
            else:
                print(f"✗ Failed to create search task: {result}")
                return None
        except Exception as e:
            print(f"✗ Search task creation error: {e}")
            return None

    def wait_for_task_completion(self, task_id: int, max_wait_seconds: int = 300) -> Tuple[bool, int]:
        start_time = time.time()
        last_progress = -1
        while time.time() - start_time < max_wait_seconds:
            payload = {
                "id": "123456789",
                "jsonrpc": "2.0",
                "method": "get",
                "params": [{
                    "apiver": 3,
                    "url": f"/logview/adom/root/logsearch/count/{task_id}"
                }],
                "session": self.session
            }
            try:
                response = requests.post(self.url, json=payload, timeout=30, verify=False)
                response.raise_for_status()
                result = response.json()
                if "result" in result:
                    status_code = result["result"]["status"]["code"]
                    matched_logs = result["result"]["matched-logs"]
                    progress = result["result"]["progress-percent"]

                    if progress != last_progress:
                        print(f"Progress: {progress}%")
                        last_progress = progress

                    if status_code == 0 and progress == 100:
                        print(f"✓ Task completed successfully. Found {matched_logs} matching logs")
                        return True, matched_logs
                    elif status_code in (0, 1):
                        time.sleep(5)
                        continue
                    else:
                        print(f"✗ Task failed with status code: {status_code}")
                        return False, 0
            except Exception as e:
                print(f"✗ Error checking task status: {e}")
                time.sleep(5)
        print(f"✗ Task did not complete within {max_wait_seconds} seconds")
        return False, 0

    def fetch_logs(self, task_id: int, total_logs: int, batch_size: int = 100) -> List[Dict]:
        all_logs = []
        offset = 0
        max_retries = 10
        max_incomplete_retries = 3

        print(f"📥 Starting to fetch {total_logs:,} logs in batches of {batch_size}...")

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

            batch_logs = []
            retry_count = 0
            incomplete_retries = 0

            while retry_count <= max_retries:
                try:
                    sys.stdout.write(f"\r📡 Requesting logs at offset {offset} (retry {retry_count})... ")
                    sys.stdout.flush()

                    response = requests.post(self.url, json=payload, timeout=30, verify=False)
                    response.raise_for_status()
                    result = response.json()

                    if "result" in result and "data" in result["result"]:
                        batch_logs = result["result"]["data"]
                        if not batch_logs and offset < total_logs:
                            retry_count += 1
                            time.sleep(3)
                            continue
                        else:
                            break
                    else:
                        print(f"\n✗ Bad response at offset {offset}: {result}")
                        break

                except Exception as e:
                    if retry_count < max_retries:
                        retry_count += 1
                        time.sleep(3)
                        continue
                    else:
                        print(f"\n✗ Final error at offset {offset}: {e}")
                        break

            sys.stdout.write("\n")

            if batch_logs:
                expected = min(batch_size, total_logs - offset)
                if len(batch_logs) < expected and offset + len(batch_logs) < total_logs:
                    incomplete_retries += 1
                    if incomplete_retries <= max_incomplete_retries:
                        print(f"⚠️ Incomplete batch at offset {offset}, retrying...")
                        time.sleep(3)
                        continue

                all_logs.extend(batch_logs)
                offset += len(batch_logs)

                if len(all_logs) % (5 * batch_size) == 0 or len(all_logs) >= total_logs:
                    print(f"📥 Fetched {len(all_logs):,} / {total_logs:,} logs")

                if len(batch_logs) < batch_size:
                    break
            else:
                if offset < total_logs:
                    print(f"⚠️ No data at offset {offset}, stopping early")
                break

        if len(all_logs) != total_logs:
            print(f"⚠️ Warning: Expected {total_logs:,} logs, got {len(all_logs):,}")

        return all_logs