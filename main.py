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
    return [lst[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n)]


# ----------------------------------------------------
# POLICY MODE (single report) — FIXED
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

    report_text = ""
    cmd = " ".join(sys.argv)

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

    except KeyboardInterrupt:
        print("\n⛔ Interrupted by user (policyid mode)")

    finally:
        client.logout()

    if not report_text:
        print("⚠️ No data retrieved.")
        return

    report_with_cmd = cmd + "\n\n" + report_text.strip() + "\n"

    output_dir = Path(RESULTS_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)

    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")

    suffix = "partial" if "Interrupted" in report_with_cmd else "last"
    policy_file = output_dir / f"policy_{policyid}_{date_str}_{suffix}.txt"

    save_results(report_with_cmd, policy_file)
    print(f"💾 Saved policyid report to: {policy_file}")

    if args.output:
        save_results(report_with_cmd, Path(args.output))

    history_path = output_dir / "history.txt"
    append_history(history_path, report_with_cmd, "", start_time, end_time, cmd)


# ----------------------------------------------------
# HISTORY APPEND
# ----------------------------------------------------
def append_history(history_path: Path, inbound_text: str, outbound_text: str,
                   start_time: str, end_time: str, cmd: str) -> None:

    history_path.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")

    header = (
        f"=== FortiAnalyzer Export — {ts} (UTC+3) ===\n"
        f"Command: {cmd}\n"
        f"Time range: {start_time} → {end_time}\n"
        f"SMART_ACTION={SMART_ACTION} | FILTER_MODE={FILTER_MODE}\n"
        f"{'=' * 60}\n\n"
    )

    with open(history_path, "a", encoding="utf-8") as f:
        f.write(header)
        if inbound_text:
            f.write("--- INBOUND ---\n" + inbound_text + "\n\n")
        if outbound_text:
            f.write("--- OUTBOUND ---\n" + outbound_text + "\n\n")

    print(f"📝 Appended results to history: {history_path}")


# ----------------------------------------------------
# MAIN
# ----------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="FortiAnalyzer Log Viewer")

    parser.add_argument("--input")
    parser.add_argument("--exclude")
    parser.add_argument("--hours", type=int)
    parser.add_argument("--days", type=int)
    parser.add_argument("--start")
    parser.add_argument("--end")
    parser.add_argument("--direction", choices=["inbound", "outbound", "all"], default="all")
    parser.add_argument("--vlan")
    parser.add_argument("--output")
    parser.add_argument("--workers", type=int)
    parser.add_argument("--proto", action="store_true")
    parser.add_argument("--policyid", type=int)

    args = parser.parse_args()
    validate_config()

    # --- TIME WINDOW ---
    if args.start and args.end:
        start_time, end_time = args.start, args.end
    else:
        hours = args.hours or (args.days * 24 if args.days else DEFAULT_TIME_RANGE_HOURS)
        end_dt = datetime.now()
        start_dt = end_dt - timedelta(hours=hours)
        start_time = start_dt.strftime("%Y-%m-%d %H:%M:%S")
        end_time = end_dt.strftime("%Y-%m-%d %H:%M:%S")

    print(f"🔍 Analyzing: {start_time} → {end_time}")

    # --- TARGETS ---
    target_ips = []
    if args.input and any(x in args.input for x in ["/", "-"]):
        target_ips = parse_ip_range(args.input)
    else:
        input_file = args.input or "machines.txt"
        if Path(input_file).exists():
            target_ips = load_machines(input_file)

    exclude_ips = set(load_machines(args.exclude)) if args.exclude and Path(args.exclude).exists() else set()
    target_ips = [ip for ip in target_ips if ip not in exclude_ips]

    ports = load_ports("ports.txt") if args.proto else None

    if args.policyid is not None:
        run_policy_mode(args, target_ips, exclude_ips, ports, start_time, end_time)
        return

    print("❌ Only policyid mode shown here (rest unchanged)")


if __name__ == "__main__":
    main()
