#!/usr/bin/env python3
import json
import argparse
from datetime import datetime, timedelta

from config import (
    FORTIANALYZER_URL,
    FORTIANALYZER_USERNAME,
    FORTIANALYZER_PASSWORD,
    validate_config,
)
from client.faz_client import FortiAnalyzerClient


def dump_raw_logs(ip: str, hours: int = 1, limit: int = 50):
    validate_config()

    client = FortiAnalyzerClient(
        url=FORTIANALYZER_URL,
        username=FORTIANALYZER_USERNAME,
        password=FORTIANALYZER_PASSWORD,
    )

    if not client.login():
        print("❌ Login failed")
        return

    end_dt = datetime.now()
    start_dt = end_dt - timedelta(hours=hours)

    start_time = start_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_time = end_dt.strftime("%Y-%m-%d %H:%M:%S")

    filter_str = f'(srcip="{ip}" or dstip="{ip}")'

    print(f"🔍 FILTER: {filter_str}")
    print(f"🕒 RANGE : {start_time} → {end_time}")

    task_id = client.create_search_task(filter_str, start_time, end_time)
    if not task_id:
        print("❌ Task creation failed")
        client.logout()
        return

    ok, matched = client.wait_for_task_completion(task_id)
    if not ok:
        print("❌ Task did not complete")
        client.logout()
        return

    print(f"📌 Matched logs: {matched}")
    if matched == 0:
        print("⚠️ No logs found")
        client.logout()
        return

    logs = client.fetch_logs(task_id, matched, batch_size=200)
    print(f"📦 Retrieved logs: {len(logs)}\n")

    print(f"===== RAW LOGS (first {limit}) =====\n")
    for i, log in enumerate(logs[:limit], 1):
        print(f"[{i}] {json.dumps(log, indent=2, ensure_ascii=False)}\n")

    client.logout()


def main():
    parser = argparse.ArgumentParser(description="Raw FAZ log dumper")
    parser.add_argument("ip", help="IP-адрес, по которому искать логи")
    parser.add_argument("--hours", type=int, default=1)
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()
    dump_raw_logs(args.ip, hours=args.hours, limit=args.limit)


if __name__ == "__main__":
    main()
