import sys
import argparse
from datetime import datetime, timedelta

import os

from analyzer.analysis_service import AnalysisRunContext, AnalysisService, AnalysisServiceConfig
from config import (
    get_results_dir_path,
    BATCH_SIZE,
    MAX_WORKERS,
    TARGET_GROUP_SIZE,
    DEFAULT_TIME_RANGE_HOURS,
    get_dynamic_reverse_dns_enabled,
    validate_config,
)
from utils.network import configure_reverse_dns, load_machines, load_ports


# ----------------------------------------------------
# HISTORY
# ----------------------------------------------------
def _append_history(text: str, start_time: str, end_time: str, cmd: str, filename: str):
    history_path = get_results_dir_path() / "history.txt"
    history_path.parent.mkdir(parents=True, exist_ok=True)

    header = (
        f"\n=== {datetime.now():%Y-%m-%d %H:%M:%S} ===\n"
        f"CMD: {cmd}\n"
        f"TIME: {start_time} → {end_time}\n"
        f"SMART_ACTION={os.getenv('SMART_ACTION', 'all')} | FILTER_MODE={os.getenv('FILTER_MODE', 'faz')}\n"
        f"FILE: {filename}\n"
        f"{'-'*60}\n"
    )

    with open(history_path, "a", encoding="utf-8") as f:
        f.write(header)
        f.write(text.rstrip() + "\n")


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
    configure_reverse_dns(get_dynamic_reverse_dns_enabled())

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

    results_dir = get_results_dir_path()
    results_dir.mkdir(parents=True, exist_ok=True)

    service = AnalysisService(
        config=AnalysisServiceConfig(
            batch_size=BATCH_SIZE,
            max_workers=args.workers or MAX_WORKERS,
            target_group_size=TARGET_GROUP_SIZE,
        ),
        progress=lambda message: print(f"🎯 {message}"),
    )
    context = AnalysisRunContext(
        start_time=start_time,
        end_time=end_time,
        target_ips=target_ips,
        exclude_ips=exclude_ips,
        ports=ports,
        cmd=cmd,
    )

    try:
        if args.policyid is not None:
            result = service.run_policyid(
                context=context,
                policyid=args.policyid,
                results_dir=results_dir,
                history_callback=_append_history,
            )
        else:
            directions = ["inbound", "outbound"] if args.direction == "all" else [args.direction]
            result = service.run_direction(
                context=context,
                directions=directions,
                results_dir=results_dir,
                history_callback=_append_history,
                workers=args.workers or MAX_WORKERS,
            )
    except RuntimeError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        sys.exit(1)

    for saved in result.files:
        print(f"💾 Saved: {saved.path}")


if __name__ == "__main__":
    main()
