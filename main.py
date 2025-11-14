#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

"""
FortiAnalyzer Log Viewer — Modular Edition
Supports inbound & outbound traffic analysis with ports.
"""


import argparse
from datetime import datetime, timedelta
from typing import List

from config import (
    FORTIANALYZER_URL,
    FORTIANALYZER_USERNAME,
    FORTIANALYZER_PASSWORD,
    DEFAULT_TIME_RANGE_HOURS,
    BATCH_SIZE,
    validate_config,
)
from client import FortiAnalyzerClient
from analyzer import LogAnalyzer
import socket


def load_machine_list(filename: str) -> List[str]:
    machines = []
    try:
        with open(filename, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    machines.append(line)
        return machines
    except FileNotFoundError:
        print(f"✗ Machine list file not found: {filename}")
        return []
    except Exception as e:
        print(f"✗ Error reading machine list: {e}")
        return []


def load_exclude_ips(filename: str) -> List[str]:
    if not filename:
        return []
    exclude_ips = []
    try:
        with open(filename, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    exclude_ips.append(line)
        print(f"✓ Loaded {len(exclude_ips)} IP addresses to exclude")
        return exclude_ips
    except FileNotFoundError:
        print(f"⚠️ Exclude file not found: {filename}")
        return []
    except Exception as e:
        print(f"✗ Error reading exclude file: {e}")
        return []


def resolve_machines_to_ips(machines: List[str]) -> List[str]:
    ips = []
    for machine in machines:
        try:
            socket.inet_aton(machine)
            ips.append(machine)
            print(f"✓ Using IP: {machine}")
        except socket.error:
            try:
                ip = socket.gethostbyname(machine)
                ips.append(ip)
                print(f"✓ Resolved {machine} -> {ip}")
            except socket.gaierror:
                print(f"✗ Could not resolve: {machine}")
    return ips


def parse_time_args(args) -> (str, str):
    if args.start or args.end:
        if not args.start or not args.end:
            print("✗ Both --start and --end must be provided together")
            sys.exit(1)
        try:
            start_dt = datetime.fromisoformat(args.start.replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(args.end.replace("Z", "+00:00"))
        except ValueError:
            print("✗ Invalid ISO datetime format. Use: YYYY-MM-DDTHH:MM:SS")
            sys.exit(1)
    else:
        end_dt = datetime.now()
        start_dt = end_dt - timedelta(hours=args.hours)

    return start_dt.strftime("%Y-%m-%dT%H:%M:%S"), end_dt.strftime("%Y-%m-%dT%H:%M:%S")


def main():
    parser = argparse.ArgumentParser(description="FortiAnalyzer Log Viewer (Inbound + Outbound)")
    parser.add_argument("machine_list", help="File containing machine names/IPs")
    parser.add_argument("--hours", type=int, default=DEFAULT_TIME_RANGE_HOURS,
                        help=f"Hours to look back (default: {DEFAULT_TIME_RANGE_HOURS})")
    parser.add_argument("--start", help="Start time in ISO format (e.g. 2025-11-13T08:00:00)")
    parser.add_argument("--end", help="End time in ISO format")
    parser.add_argument("--direction", choices=["inbound", "outbound", "all"], default="all",
                        help="Traffic direction to analyze (default: all)")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument("--exclude", help="File with IPs to exclude from stats")

    args = parser.parse_args()

    validate_config()

    machines = load_machine_list(args.machine_list)
    if not machines:
        return 1

    ips = resolve_machines_to_ips(machines)
    if not ips:
        print("✗ No valid IPs found")
        return 1

    exclude_ips = load_exclude_ips(args.exclude)
    start_str, end_str = parse_time_args(args)

    print(f"🔍 Searching logs from {start_str} to {end_str}")
    print(f"🎯 Target IPs: {', '.join(ips)}")
    print(f"🧭 Direction: {args.direction}")

    client = FortiAnalyzerClient(FORTIANALYZER_URL, FORTIANALYZER_USERNAME, FORTIANALYZER_PASSWORD)
    analyzer = LogAnalyzer(exclude_ips)

    try:
        if not client.login():
            return 1

        output_content = []

        # Определяем набор направлений для анализа
        direction_filters = {
            "outbound": "srcip={ip} dstintf!=SRX smart_action=all-accept",
            "inbound":  "dstip={ip} srcintf!=SRX smart_action=all-accept"
        }

        if args.direction == "all":
            selected_dirs = direction_filters
        else:
            selected_dirs = {args.direction: direction_filters[args.direction]}

        for i, ip in enumerate(ips):
            machine_name = machines[i] if i < len(machines) else ip
            print(f"\n🔍 Processing machine: {machine_name} ({ip})")

            for direction, filter_template in selected_dirs.items():
                filter_str = filter_template.format(ip=ip)
                print(f"  → Fetching {direction} traffic...")

                task_id = client.create_search_task(filter_str, start_str, end_str)
                if not task_id:
                    continue

                success, total_logs = client.wait_for_task_completion(task_id)
                if not success or total_logs == 0:
                    msg = f"    ℹ️ No {direction} logs for {machine_name}"
                    print(msg)
                    output_content.append(f"\n{msg}")
                    continue

                logs = client.fetch_logs(task_id, total_logs, batch_size=BATCH_SIZE)
                if not logs:
                    print(f"    ✗ Failed to fetch {direction} logs")
                    continue

                stats = analyzer.aggregate_traffic(logs, direction)
                if stats:
                    results = analyzer.format_results(stats, direction)
                    block = f"\n📊 {direction.upper()} for {machine_name}:\n{results}"
                    output_content.append(block)
                    if not args.output:
                        print(block)
                else:
                    msg = f"    ℹ️ No {direction} statistics for {machine_name}"
                    output_content.append(f"\n{msg}")
                    if not args.output:
                        print(msg)

        if args.output:
            with open(args.output, "w") as f:
                f.write("\n".join(output_content))
            print(f"✓ Results saved to {args.output}")

        return 0

    finally:
        client.logout()


if __name__ == "__main__":
    sys.exit(main())