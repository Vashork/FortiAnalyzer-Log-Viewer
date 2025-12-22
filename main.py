import os
import sys
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed, CancelledError

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
    ADAPTIVE_WORKER_THRESHOLD_HOURS,
)

from utils.network import (
    load_machines,
    load_vlans,
    parse_ip_range,
    normalize_vlan_key,
    load_ports,
)

from client.faz_client import FortiAnalyzerClient
from analyzer.log_analyzer import analyze_logs, analyze_policyid_logs
from utils.output import save_results


load_dotenv()


# --------------------------
# VLAN Expansion
# --------------------------
def expand_targets_from_vlans(vlan_query, vlans_map):
    targets = []
    q = normalize_vlan_key(vlan_query)

    for cidr_or_range, vlan_id, vlan_name in vlans_map:
        if q == normalize_vlan_key(str(vlan_id)) or q == normalize_vlan_key(vlan_name):
            targets.extend(parse_ip_range(cidr_or_range))

    return targets


# --------------------------
# Worker for inbound/outbound
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
        return results

    try:
        for ip in ip_list:
            print(f"\n⚙️ Worker processing {ip} ({direction})...")
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
# Split list into N chunks
# --------------------------
def chunk_list(lst, n):
    if n <= 1:
        return [lst]

    k, m = divmod(len(lst), n)
    return [lst[i * k + min(i, m) : (i + 1) * k + min(i + 1, m)] for i in range(n)]


# --------------------------
# HISTORY APPEND
# --------------------------
def append_history(history_path: Path, inbound_text: str, outbound_text: str,
                   start_time: str, end_time: str, cmd: str) -> None:

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

    # Count entries by IP-looking patterns
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


# ----------------------------------------------------
# POLICY MODE (single report)
# ----------------------------------------------------
def run_policy_mode(args, target_ips, exclude_ips, ports, start_time, end_time):
    policyid = args.policyid

    print("\n" + "=" * 60)
    if not target_ips:
        print("ℹ Policy mode: GLOBAL search (no IP filter applied)")
    print("=" * 60)

    client = FortiAnalyzerClient(
        url=FORTIANALYZER_URL,
        username=FORTIANALYZER_USERNAME,
        password=FORTIANALYZER_PASSWORD,
    )

    if not client.login():
        print("❌ Login failed in policyid mode", file=sys.stderr)
        sys.exit(1)

    try:
        report_text = analyze_policyid_logs(
            client=client,
            target_ips=target_ips,
            policyid=policyid,
            start_time=start_time,
            end_time=end_time,
            exclude_ips=exclude_ips,
            batch_size=BATCH_SIZE,
            ports=ports,
        )
    finally:
        client.logout()

    if not report_text:
        print("⚠️ No data for this policyid.")
        return

    # prepend command
    cmd = " ".join(sys.argv)
    report_with_cmd = cmd + "\n\n" + report_text.strip() + "\n"

    # file name
    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(RESULTS_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)

    policy_file = output_dir / f"policy_{policyid}_{date_str}_last.txt"
    save_results(report_with_cmd, policy_file)
    print(f"💾 Saved policyid report to: {policy_file}")

    # user-specified output
    if args.output:
        save_results(report_with_cmd, Path(args.output))

    # history as inbound-block
    history_path = output_dir / "history.txt"
    append_history(history_path, report_with_cmd, "", start_time, end_time, cmd)

    return


# ----------------------------------------------------
# Graceful STOP — builds partial reports
# ----------------------------------------------------
def finalize_partial_results(final_results, start_time, end_time, cmd):
    """
    Build inbound/outbound combined results from whatever is ready.
    """
    inbound_text = "\n\n".join(
        text for (ip, d), text in final_results.items() if d == "inbound"
    ).strip()

    outbound_text = "\n\n".join(
        text for (ip, d), text in final_results.items() if d == "outbound"
    ).strip()

    # prepend command
    if inbound_text:
        inbound_text = cmd + "\n\n" + inbound_text
    if outbound_text:
        outbound_text = cmd + "\n\n" + outbound_text

    # save
    output_dir = Path(RESULTS_DIR)
    if inbound_text:
        save_results(inbound_text, output_dir / "inbound_last.txt")
    if outbound_text:
        save_results(outbound_text, output_dir / "outbound_last.txt")

    # history
    history_path = output_dir / "history.txt"
    append_history(history_path, inbound_text, outbound_text, start_time, end_time, cmd)

    return inbound_text, outbound_text


# ----------------------------------------------------
# MAIN
# ----------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="FortiAnalyzer Log Viewer")

    parser.add_argument("--input", type=str, help="Input file or CIDR/range (default: machines.txt)")
    parser.add_argument("--exclude", type=str, help="Exclude list")
    parser.add_argument("--hours", type=int)
    parser.add_argument("--days", type=int)
    parser.add_argument("--start", type=str)
    parser.add_argument("--end", type=str)
    parser.add_argument("--direction", choices=["inbound", "outbound", "all"], default="all")
    parser.add_argument("--vlan", type=str)
    parser.add_argument("--output", type=str)
    parser.add_argument("--workers", type=int)
    parser.add_argument("--proto", action="store_true")
    parser.add_argument("--policyid", type=int, help="PolicyID analysis mode")

    args = parser.parse_args()
    validate_config()

    # --------------------------
    # TIME WINDOW
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

    # Оценим длительность окна для адаптивного лимита воркеров
    fmt = "%Y-%m-%d %H:%M:%S"
    try:
        start_dt_parsed = datetime.strptime(start_time, fmt)
        end_dt_parsed = datetime.strptime(end_time, fmt)
        time_span_hours = max(
            0.0, (end_dt_parsed - start_dt_parsed).total_seconds() / 3600.0
        )
    except Exception:
        time_span_hours = 0.0

    print(f"🔍 Analyzing: {start_time} → {end_time} (≈{time_span_hours:.2f}h)")

    output_dir = Path(RESULTS_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)

    # --------------------------
    # VLAN
    # --------------------------
    vlans_file = os.getenv("VLANS_FILE", "vlans.txt")
    vlans_map = load_vlans(vlans_file) if Path(vlans_file).exists() else []

    # --------------------------
    # TARGETS
    # --------------------------
    target_ips = []

    if args.vlan:
        target_ips = expand_targets_from_vlans(args.vlan, vlans_map)
    else:
        # CIDR or range?
        if args.input and any(ch in args.input for ch in ["/", "-"]):
            target_ips = parse_ip_range(args.input)
        else:
            input_file = args.input or os.getenv("MACHINES_FILE", "machines.txt")
            if Path(input_file).exists():
                target_ips = load_machines(input_file)

    if not target_ips and args.policyid is None:
        print("❌ No target IPs found")
        sys.exit(1)

    # --------------------------
    # EXCLUDE
    # --------------------------
    exclude_ips = set()
    if args.exclude and Path(args.exclude).exists():
        exclude_ips = set(load_machines(args.exclude))

    # filter out excluded targets
    target_ips = [ip for ip in target_ips if ip not in exclude_ips]

    if not target_ips and args.policyid is None:
        print("❌ All target IPs were excluded")
        sys.exit(1)

    # --------------------------
    # PORT FILTER
    # --------------------------
    ports = None
    if args.proto:
        ports_file = os.getenv("PORTS_FILE", "ports.txt")
        ports = load_ports(ports_file)
        if ports:
            print(f"🎯 Port filter: {', '.join(ports)}")
        else:
            print(f"⚠️ {ports_file} empty — ignoring --proto")
            ports = None

    # --------------------------
    # POLICY MODE
    # --------------------------
    if args.policyid is not None:
        return run_policy_mode(
            args=args,
            target_ips=target_ips,
            exclude_ips=exclude_ips,
            ports=ports,
            start_time=start_time,
            end_time=end_time,
        )

    # --------------------------
    # ORDINARY inbound/outbound MODE
    # --------------------------
    directions = ["inbound", "outbound"] if args.direction == "all" else [args.direction]

    # Базовое количество воркеров
    workers = max(1, args.workers if args.workers else MAX_WORKERS)

    # Адаптивное ограничение по длительности окна
    if (
            ADAPTIVE_WORKER_THRESHOLD_HOURS > 0
            and time_span_hours >= ADAPTIVE_WORKER_THRESHOLD_HOURS
            and workers > 1
    ):
        print(
            f"⚠ Large time window (≈{time_span_hours:.1f}h ≥ "
            f"{ADAPTIVE_WORKER_THRESHOLD_HOURS}h). Forcing single worker to protect FortiAnalyzer."
        )
        workers = 1

    # Не имеет смысла воркеров больше, чем целей
    workers = min(workers, len(target_ips))
    print(f"🧵 Using {workers} worker(s)")

    chunks = chunk_list(target_ips, workers)
    final_results = {}

    executor = ThreadPoolExecutor(max_workers=workers)
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
        for direc in directions
        for chunk in chunks
        if chunk  # пустые чанки не запускаем
    ]

    cmd = " ".join(sys.argv)

    try:
        for fut in as_completed(futures):
            try:
                res = fut.result()
                final_results.update(res)
            except CancelledError:
                pass

    except KeyboardInterrupt:
        print("\n⛔ Interrupted by user — stopping workers...")
        executor.shutdown(wait=False, cancel_futures=True)

        # finalize partial results
        inbound_text, outbound_text = finalize_partial_results(
            final_results, start_time, end_time, cmd
        )
        print("💾 Partial results saved. Exiting gracefully.")
        return

    # --------------------------
    # FINALIZE NORMAL MODE
    # --------------------------
    inbound_text = "\n\n".join(
        text for (ip, d), text in final_results.items() if d == "inbound"
    ).strip()
    outbound_text = "\n\n".join(
        text for (ip, d), text in final_results.items() if d == "outbound"
    ).strip()

    if inbound_text:
        inbound_text = cmd + "\n\n" + inbound_text
    if outbound_text:
        outbound_text = cmd + "\n\n" + outbound_text

    # save results
    if inbound_text:
        save_results(inbound_text, output_dir / "inbound_last.txt")
    if outbound_text:
        save_results(outbound_text, output_dir / "outbound_last.txt")

    # user output
    if args.output:
        parts = []
        if inbound_text:
            parts.append("[INBOUND]\n" + inbound_text)
        if outbound_text:
            parts.append("[OUTBOUND]\n" + outbound_text)
        save_results("\n\n".join(parts), Path(args.output))

    # history
    history_path = output_dir / "history.txt"
    append_history(history_path, inbound_text, outbound_text, start_time, end_time, cmd)


if __name__ == "__main__":
    main()
