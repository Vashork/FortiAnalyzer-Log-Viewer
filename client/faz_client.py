import sys
import time
from typing import Optional, List, Dict, Tuple

import requests
import urllib3

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

            # --- FORMAT 1: result is dict with tid ---
            if isinstance(raw, dict) and "tid" in raw:
                tid = raw["tid"]
                print(f"✓ Created search task with ID: {tid}")
                return tid

            # --- FORMAT 2: result is array [{ tid, status }]
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

                # Всегда показываем прогресс, включая 0%
                if progress != last_progress:
                    print(f"Progress: {progress}%")
                    last_progress = progress

                # Успешно завершилось
                if status_code == 0 and progress == 100:
                    print(f"✓ Task completed successfully. Found {matched_logs} matching logs")
                    return True, matched_logs

                # 0/1 — нормальные состояния, ждём дальше
                if status_code in (0, 1):
                    time.sleep(5)
                    continue

                # Любой другой код — ошибка
                print(f"✗ Task failed with status code: {status_code}")
                return False, 0

            except Exception as e:
                print(f"✗ Error checking task status: {e}")
                time.sleep(5)

        print("✗ Task did not complete within allowed time")
        return False, 0

    # ==========================
    #  Log Fetch (robust)
    # ==========================

    @staticmethod
    def _build_log_key(log: Dict) -> Tuple:
        """
        Строим "почти уникальный" ключ лога для дедупликации.
        Не идеально, но сильно снижает дубликаты при странном поведении FAZ.
        """
        return (
            log.get("logid") or log.get("_logid"),
            log.get("itime") or log.get("time") or log.get("eventtime"),
            log.get("srcip"),
            log.get("dstip"),
            log.get("srcport"),
            log.get("dstport"),
            log.get("proto"),
            log.get("policyid"),
        )

    def fetch_logs(self, task_id: int, total_logs: int, batch_size: int = 100) -> List[Dict]:
        """
        Fetch logs in batches, максимально устойчиво к:
          - неточным matched-logs,
          - дубликатам,
          - пустым батчам,
          - временным ошибкам FAZ.
        Рабочая версия: url = /logview/adom/root/logsearch/{task_id}, offset += batch_size
        """
        all_logs: List[Dict] = []
        seen_keys = set()

        offset = 0
        max_empty_batches = 5
        empty_batches = 0

        # "Безопасный лимит" на случай, если matched-logs врет
        safe_cap = max(total_logs * 2, batch_size * 10)

        print(f"📥 Fetching logs (matched={total_logs}, batch={batch_size})...")

        while True:
            remaining = max(total_logs - len(all_logs), 0)
            print(
                f"📡 Requesting logs at offset {offset} "
                f"(collected={len(all_logs)}/{total_logs}, remaining={remaining})..."
            )

            payload = {
                "id": "123456789",
                "jsonrpc": "2.0",
                "method": "get",
                "params": [
                    {
                        "apiver": 3,
                        "limit": batch_size,
                        "offset": offset,
                        # ВАЖНО: рабочий URL БЕЗ /result/
                        "url": f"/logview/adom/root/logsearch/{task_id}",
                    }
                ],
                "session": self.session,
            }

            try:
                result = self._post(payload, timeout=60)
                raw = result.get("result", {})
                data = raw.get("data") or []

            except Exception as e:
                print(f"✗ Error fetching logs at offset {offset}: {e}")
                empty_batches += 1
                if empty_batches >= max_empty_batches:
                    print("⚠️ Too many consecutive errors, stopping fetch.")
                    break
                time.sleep(3)
                continue

            # Пустой батч
            if not data:
                empty_batches += 1
                if empty_batches >= max_empty_batches:
                    print("⚠️ No data returned for several attempts, stopping fetch.")
                    break
                time.sleep(2)
                continue

            # получили непустой батч — сбрасываем счётчик пустых
            empty_batches = 0

            for log in data:
                key = self._build_log_key(log)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                all_logs.append(log)

            # как в рабочей версии — двигаем offset "страницами"
            offset += batch_size

            # Условие остановки №1: собрали хотя бы заявленное число и текущий батч меньше лимита
            if len(all_logs) >= total_logs and len(data) < batch_size:
                break

            # Условие остановки №2: сработал "safety cap"
            if len(all_logs) >= safe_cap:
                print(f"⚠️ Safety cap reached while fetching logs: {len(all_logs)} unique entries")
                break

        # Финальный sanity-check
        if len(all_logs) != total_logs:
            print(f"⚠️ Requested {total_logs} logs, actually collected {len(all_logs)} unique logs.")

        return all_logs
