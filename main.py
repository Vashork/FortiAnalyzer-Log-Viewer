import sys
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

from dotenv import load_dotenv

import os

from config import (
    RESULTS_DIR,
    BATCH_SIZE,
    MAX_WORKERS,
    DEFAULT_TIME_RANGE_HOURS,
    validate_config,
    reload_env,
)

load_dotenv()

from utils.network import load_machines, load_ports
from client.faz_client import FortiAnalyzerClient
from analyzer.log_analyzer import analyze_logs, analyze_policyid_logs


def _create_faz_client() -> FortiAnalyzerClient:
    """Создать клиент FAZ из переменных окружения."""
    return FortiAnalyzerClient(
        url=os.getenv("FORTIANALYZER_URL"),
        username=os.getenv("FORTIANALYZER_USERNAME"),
        password=os.getenv("FORTIANALYZER_PASSWORD"),
    )


from utils.output import save_results



# ----------------------------------------------------
# HISTORY
# ----------------------------------------------------
def _append_history(text: str, start_time: str, end_time: str, cmd: str, filename: str):
    history_path = Path(RESULTS_DIR) / "history.txt"
    history_path.parent.mkdir(parents=True, exist_ok=True)

    header = (
        f"\n=== {datetime.now():%Y-%m-%d %H:%M:%S} ===\n"
        f"CMD: {cmd}\n"
        f"TIME: {start_time} → {end_time}\n"
        f"SMART_ACTION={os.getenv("SMART_ACTION", "all")} | FILTER_MODE={os.getenv("FILTER_MODE", "faz")}\n"
        f"FILE: {filename}\n"
        f"{'-'*60}\n"
    )

    with open(history_path, "a", encoding="utf-8") as f:
        f.write(header)
        f.write(text.rstrip() + "\n")


# ----------------------------------------------------
# WORKER — ОДИН IP
# ----------------------------------------------------
def process_single_ip(ip, direction, start_time, end_time, exclude_ips, ports):
    client = _create_faz_client()

    if not client.login():
        raise RuntimeError("FAZ login failed")

    try:
        return analyze_logs(
            client=client,
            target_ips=[ip],
            direction=direction,
            start_time=start_time,
            end_time=end_time,
            exclude_ips=exclude_ips,
            batch_size=BATCH_SIZE,
            ports=ports,
        )
    finally:
        client.logout()


# ----------------------------------------------------
# MAIN
# ----------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input")
    parser.add_argument("--exclude")
    parser.add_argument("--hours", type=int)
    parser.add_argument("--days", type=int)
    parser.add_argument("--start")
    parser.add_argument("--end")
    parser.add_argument("--direction", choices=["inbound", "outbound", "all"], default="all")
    parser.add_argument("--workers", type=int)
    parser.add_argument("--proto", action="store_true")
    parser.add_argument("--policyid", type=int)

    args = parser.parse_args()
    validate_config()

    cmd = " ".join(sys.argv)

    # ---------------- TIME RANGE ----------------
    if args.start and args.end:
        start_time, end_time = args.start, args.end
    else:
        hours = args.hours or (args.days * 24 if args.days else DEFAULT_TIME_RANGE_HOURS)
        end_dt = datetime.now()
        start_dt = end_dt - timedelta(hours=hours)
        start_time = start_dt.strftime("%Y-%m-%d %H:%M:%S")
        end_time = end_dt.strftime("%Y-%m-%d %H:%M:%S")

    print(f"🔍 Analyzing: {start_time} → {end_time}")

    # ---------------- TARGETS ----------------
    target_ips = load_machines(args.input or "machines.txt")
    exclude_ips = set(load_machines(args.exclude)) if args.exclude else set()
    target_ips = [ip for ip in target_ips if ip not in exclude_ips]

    ports = load_ports("ports.txt") if args.proto else None

    results_dir = Path(RESULTS_DIR)
    results_dir.mkdir(parents=True, exist_ok=True)

    # ================= POLICY MODE =================
    if args.policyid is not None:
        client = _create_faz_client()

        if not client.login():
            print("❌ FAZ login failed", file=sys.stderr)
            sys.exit(1)

        try:
            text = analyze_policyid_logs(
                client=client,
                target_ips=target_ips,
                policyid=args.policyid,
                start_time=start_time,
                end_time=end_time,
                exclude_ips=exclude_ips,
                batch_size=BATCH_SIZE,
                ports=ports,
            )
        finally:
            client.logout()

        if not text.strip():
            text = "NO DATA\n"

        outfile = results_dir / f"policy_{args.policyid}.txt"
        save_results(text, outfile)
        _append_history(text, start_time, end_time, cmd, outfile.name)

        print(f"💾 Saved: {outfile}")
        return

    # ================= DIRECTION MODE =================
    directions = ["inbound", "outbound"] if args.direction == "all" else [args.direction]
    workers = args.workers or MAX_WORKERS

    # аккумулируем вывод строго по направлению
    direction_text = {d: [] for d in directions}

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = []

        for direction in directions:
            for ip in target_ips:
                futures.append(
                    ex.submit(
                        process_single_ip,
                        ip,
                        direction,
                        start_time,
                        end_time,
                        exclude_ips,
                        ports,
                    )
                )

        for f in as_completed(futures):
            reports = f.result() or {}
            for (_, direction), text in reports.items():
                if text.strip():
                    direction_text[direction].append(text)

    # ---------------- SAVE FILES ----------------
    for direction in directions:
        outfile = results_dir / f"{direction}.txt"

        if direction_text[direction]:
            final_text = "\n\n".join(direction_text[direction])
        else:
            final_text = "NO DATA\n"

        save_results(final_text, outfile)
        _append_history(final_text, start_time, end_time, cmd, outfile.name)

        print(f"💾 Saved: {outfile}")


if __name__ == "__main__":
    main()
