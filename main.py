# main.py

import os
import sys
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

from dotenv import load_dotenv

from config import (
    RESULTS_DIR,
    BATCH_SIZE,
    MAX_WORKERS,
    DEFAULT_TIME_RANGE_HOURS,
    validate_config,
    FORTIANALYZER_URL,
    FORTIANALYZER_USERNAME,
    FORTIANALYZER_PASSWORD,
    SMART_ACTION,
    FILTER_MODE,
)

from utils.network import (
    load_machines,
    load_vlans,
    parse_ip_range,
    normalize_vlan_key,
    load_ports,
)

from client.faz_client import FortiAnalyzerClient
from analyzer.log_analyzer import analyze_logs
from utils.output import save_results


load_dotenv()


# --------------------------
# VLAN → список IP
# --------------------------
def expand_targets_from_vlans(vlan_query, vlans_map):
    targets = []
    q = normalize_vlan_key(vlan_query)

    for cidr_or_range, vlan_id, vlan_name in vlans_map:
        if q == normalize_vlan_key(str(vlan_id)) or q == normalize_vlan_key(vlan_name):
            targets.extend(parse_ip_range(cidr_or_range))

    return targets


# --------------------------
# Воркер одного направления
# --------------------------
def process_single_direction(ip_list, direction, start_time, end_time, exclude_ips, ports):
    results = {}

    client = FortiAnalyzerClient(
        url=FORTIANALYZER_URL,
        username=FORTIANALYZER_USERNAME,
        password=FORTIANALYZER_PASSWORD,
    )

    if not client.login():
        print("❌ Worker login failed", file=sys.stderr)
        return {}

    try:
        for ip in ip_list:
            print(f"\n⚙️ Worker processing {ip} ({direction}) ...")

            report_dict = analyze_logs(
                client=client,
                target_ips=[ip],
                direction=direction,
                start_time=start_time,
                end_time=end_time,
                exclude_ips=exclude_ips,
                batch_size=BATCH_SIZE,
                ports=ports,
            )

            results.update(report_dict)
    finally:
        client.logout()

    return results


# --------------------------
# Разбиение списка на чанки
# --------------------------
def chunk_list(lst, n):
    if n <= 1:
        return [lst]

    k, m = divmod(len(lst), n)
    return [lst[i * k + min(i, m) : (i + 1) * k + min(i + 1, m)] for i in range(n)]


# --------------------------
# HISTORY
# --------------------------
def append_history(history_path: Path, inbound_text: str, outbound_text: str,
                   start_time: str, end_time: str, cmd: str) -> None:

    if not inbound_text and not outbound_text:
        return

    history_path = Path(history_path)
    history_path.parent.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y-%m-%d %H:%M")

    header_lines = [
        f"=== FortiAnalyzer Export — {ts} (UTC+3) ===",
        f"Command: {cmd}",
        f"Time range: {start_time} → {end_time}",
        f"SMART_ACTION={SMART_ACTION} | FILTER_MODE={FILTER_MODE}",
        "=========================================================\n",
    ]
    header = "\n".join(header_lines)

    # Подсчёт количества записей
    def count_entries(block: str) -> int:
        if not block:
            return 0
        cnt = 0
        for line in block.splitlines():
            parts = line.strip().split()
            if parts and parts[0].count(".") == 3:
                cnt += 1
        return cnt

    inbound_count = count_entries(inbound_text)
    outbound_count = count_entries(outbound_text)

    summary = (
        f"Inbound: {inbound_count} records\n"
        f"Outbound: {outbound_count} records\n"
        f"=========================================================\n\n"
    )

    output = [header, summary]

    if inbound_text:
        output.append("--- INBOUND LOGS ---\n")
        output.append(inbound_text.strip() + "\n\n")

    if outbound_text:
        output.append("--- OUTBOUND LOGS ---\n")
        output.append(outbound_text.strip() + "\n\n")

    output_text = "".join(output)

    with open(history_path, "a", encoding="utf-8") as f:
        f.write(output_text)

    print(f"📝 Appended results to history: {history_path}")


# --------------------------
# MAIN
# --------------------------
def main():
    parser = argparse.ArgumentParser(description="FortiAnalyzer Log Viewer")

    parser.add_argument("--input", type=str, help="Input file (default: machines.txt)")
    parser.add_argument("--exclude", type=str, help="Exclude list")

    parser.add_argument("--hours", type=int)
    parser.add_argument("--days", type=int)
    parser.add_argument("--start", type=str)
    parser.add_argument("--end", type=str)

    parser.add_argument("--direction", choices=["inbound", "outbound", "all"], default="all")

    parser.add_argument("--vlan", type=str, help="Filter targets by VLAN (vlans.txt)")
    parser.add_argument("--output", type=str, help="Single output file for combined report")

    parser.add_argument("--workers", type=int, help="Workers count override")

    parser.add_argument(
        "--proto",
        action="store_true",
        help="Filter logs by dstport list from PORTS_FILE (ports.txt)",
    )

    args = parser.parse_args()

    validate_config()

    # --------------------------
    # Time window
    # --------------------------
    if args.start and args.end:
        start_time, end_time = args.start, args.end
    else:
        if args.hours is not None:
            hours = args.hours
        elif args.days is not None:
            hours = args.days * 24
        else:
            hours = DEFAULT_TIME_RANGE_HOURS

        end_dt = datetime.now()
        start_dt = end_dt - timedelta(hours=hours)

        start_time = start_dt.strftime("%Y-%m-%d %H:%M:%S")
        end_time = end_dt.strftime("%Y-%m-%d %H:%M:%S")

    print(f"🔍 Analyzing (direction: {args.direction}, time: {start_time} → {end_time})")

    # --------------------------
    # RESULT DIR
    # --------------------------
    output_dir = Path(RESULTS_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)

    # --------------------------
    # VLANs
    # --------------------------
    vlans_file = os.getenv("VLANS_FILE", "vlans.txt")
    vlans_map = load_vlans(vlans_file) if Path(vlans_file).exists() else []

    # --------------------------
    # Targets
    # --------------------------
    target_ips = []

    if args.vlan:
        target_ips = expand_targets_from_vlans(args.vlan, vlans_map)
    else:
        input_file = args.input or os.getenv("MACHINES_FILE", "machines.txt")
        if Path(input_file).exists():
            target_ips = load_machines(input_file)

    if not target_ips:
        print("❌ No target IPs found")
        sys.exit(1)

    # --------------------------
    # EXCLUDE
    # --------------------------
    exclude_ips = set()
    if args.exclude and Path(args.exclude).exists():
        exclude_ips = set(load_machines(args.exclude))

    # удаляем исключённые цели
    target_ips = [ip for ip in target_ips if ip not in exclude_ips]

    # --------------------------
    # Workers
    # --------------------------
    workers = args.workers if args.workers else MAX_WORKERS
    workers = max(1, workers)
    print(f"🧵 Using {workers} worker(s)")

    # --------------------------
    # PORT FILTER (--proto)
    # --------------------------
    ports = None
    if args.proto:
        ports_file = os.getenv("PORTS_FILE", "ports.txt")
        ports = load_ports(ports_file)
        if ports:
            print(f"🎯 Using port filter from {ports_file}: {', '.join(ports)}")
        else:
            print(f"⚠️ {ports_file} empty → ignoring --proto")
            ports = None

    # --------------------------
    # Directions
    # --------------------------
    directions = ["inbound", "outbound"] if args.direction == "all" else [args.direction]

    final_results: dict[tuple[str, str], str] = {}

    # --------------------------
    # Processing
    # --------------------------
    for direc in directions:
        print("\n" + "=" * 60)
        print(f"➡️  Direction: {direc}")
        print("=" * 60)

        chunks = chunk_list(target_ips, workers)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(
                    process_single_direction,
                    chunk,
                    direc,
                    start_time,
                    end_time,
                    exclude_ips,
                    ports,
                )
                for chunk in chunks
            ]

            for fut in as_completed(futures):
                batch_results = fut.result()
                final_results.update(batch_results)

    # --------------------------
    # Build combined text
    # --------------------------
    inbound_text = "\n\n".join(
        text for (ip, d), text in final_results.items() if d == "inbound"
    ).strip()

    outbound_text = "\n\n".join(
        text for (ip, d), text in final_results.items() if d == "outbound"
    ).strip()

    # --------------------------
    # Save last-run files
    # --------------------------
    if inbound_text:
        save_results(inbound_text, output_dir / "inbound_last.txt")

    if outbound_text:
        save_results(outbound_text, output_dir / "outbound_last.txt")

    # --------------------------
    # Optional single file
    # --------------------------
    if args.output:
        parts = []
        if inbound_text:
            parts.append("[INBOUND]\n" + inbound_text)
        if outbound_text:
            parts.append("[OUTBOUND]\n" + outbound_text)
        if parts:
            save_results("\n\n".join(parts), Path(args.output))

    # --------------------------
    # HISTORY
    # --------------------------
    cmd = " ".join(sys.argv)
    history_path = output_dir / "history.txt"
    append_history(history_path, inbound_text, outbound_text, start_time, end_time, cmd)


if __name__ == "__main__":
    main()
