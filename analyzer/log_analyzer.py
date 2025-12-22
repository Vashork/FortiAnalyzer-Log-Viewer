from collections import defaultdict
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta

from utils.network import resolve_hostname
from config import (
    COLUMNS_CONFIG,
    SMART_ACTION,
    FILTER_MODE,
    MAX_TASK_HOURS,
    MAX_MATCHED_LOGS_PER_TASK,
)


# ------------------------------------------
# PROTOCOL NAMES
# ------------------------------------------
def proto_to_name(proto_id) -> str:
    try:
        return {6: "tcp", 17: "udp", 1: "icmp"}.get(int(proto_id), str(proto_id))
    except Exception:
        return "unknown"


# ------------------------------------------
# SMART ACTION MAP (используется на FAZ)
# ------------------------------------------
SMART_ACTION_MAP = {
    "all-accept": 'smart_action="all-accept"',
    "deny": 'action="deny"',
}


class LogAnalyzer:
    """Aggregates logs into structured reports."""

    def __init__(self, exclude_ips: List[str]):
        self.exclude_ips = set(exclude_ips)

    # ----------------------------------------------------------
    # GROUP LOGS BY LOCAL → REMOTE (inbound/outbound)
    # ----------------------------------------------------------
    def aggregate_by_local(self, logs, direction: str, target_ips: List[str]):
        if direction == "inbound":
            local_field = "dstip"
            remote_field = "srcip"
            port_field = "dstport"
        else:
            local_field = "srcip"
            remote_field = "dstip"
            port_field = "dstport"

        result: Dict[str, Dict[Tuple[str, str, str], Dict]] = defaultdict(
            lambda: defaultdict(
                lambda: {
                    "count": 0,
                    "actions": set(),
                    "policyids": set(),
                    "apps": set(),
                    "srcintfs": set(),
                    "dstintfs": set(),
                    "policynames": set(),
                    "devnames": set(),
                }
            )
        )

        for log in logs:
            local_ip = log.get(local_field)
            remote_ip = log.get(remote_field)

            if not local_ip or not remote_ip:
                continue
            if local_ip not in target_ips:
                continue
            if remote_ip in self.exclude_ips:
                continue

            proto = proto_to_name(log.get("proto"))
            port = log.get(port_field, "-")
            key = (remote_ip, str(port), proto)
            entry = result[local_ip][key]

            entry["count"] += 1

            if log.get("smart_action"):
                entry["actions"].add(log["smart_action"])
            if log.get("policyid") is not None:
                entry["policyids"].add(str(log["policyid"]))
            if log.get("app"):
                entry["apps"].add(log["app"])
            if log.get("srcintf"):
                entry["srcintfs"].add(log["srcintf"])
            if log.get("dstintf"):
                entry["dstintfs"].add(log["dstintf"])
            if log.get("policyname"):
                entry["policynames"].add(log["policyname"])
            if log.get("devname"):
                entry["devnames"].add(log["devname"])

        return result

    # ----------------------------------------------------------
    # BUILD REPORTS (inbound/outbound)
    # ----------------------------------------------------------
    def build_reports_per_local(self, stats, direction: str, target_ips: List[str]):
        reports: Dict[Tuple[str, str], str] = {}
        show_connections = COLUMNS_CONFIG.get("connections", True)

        extra_cols = []
        if COLUMNS_CONFIG.get("action"):
            extra_cols.append(("Action", "actions"))
        if COLUMNS_CONFIG.get("policyid"):
            extra_cols.append(("PolicyID", "policyids"))
        if COLUMNS_CONFIG.get("app"):
            extra_cols.append(("App", "apps"))
        if COLUMNS_CONFIG.get("srcintf"):
            extra_cols.append(("SrcIntf", "srcintfs"))
        if COLUMNS_CONFIG.get("dstintf"):
            extra_cols.append(("DstIntf", "dstintfs"))
        if COLUMNS_CONFIG.get("policyname"):
            extra_cols.append(("PolicyName", "policynames"))
        if COLUMNS_CONFIG.get("devname"):
            extra_cols.append(("DevName", "devnames"))

        for local_ip, items in stats.items():
            lines = [
                "=" * 110,
                f"{direction.upper()} TRAFFIC for local IP: {local_ip}",
                "=" * 110,
                "",
                ]

            columns = [
                ("Remote IP", 15),
                ("Hostname", 30),
                ("Port", 6),
                ("Proto", 5),
            ]
            if show_connections:
                columns.append(("Connections", 11))
            for col, _ in extra_cols:
                columns.append((col, 15))

            head = "".join([f"{name:<{width}}  " for name, width in columns])
            sep = "-" * min(len(head), 140)
            lines.append(head)
            lines.append(sep)

            total_conns = 0
            uniq_ips = set()

            for (remote, port, proto), d in sorted(
                    items.items(), key=lambda x: -x[1]["count"]
            ):
                hostname = resolve_hostname(remote)
                total_conns += d["count"]
                uniq_ips.add(remote)

                row_parts = [
                    (remote, 15),
                    (hostname, 30),
                    (port, 6),
                    (proto, 5),
                ]
                if show_connections:
                    row_parts.append((str(d["count"]), 11))

                row = "".join([f"{val:<{width}}  " for val, width in row_parts])
                for _, field in extra_cols:
                    values = d.get(field) or set()
                    row += f"{','.join(sorted(values)) or '-':<15}  "
                lines.append(row)

            lines.append("")
            lines.append(f"Total unique remotes: {len(uniq_ips)}")
            lines.append(f"Total connections: {total_conns}")

            reports[(local_ip, direction)] = "\n".join(lines)

        return reports

    # ----------------------------------------------------------
    # POLICYID MODE — GLOBAL AGGREGATION
    # ----------------------------------------------------------
    def aggregate_by_policyid(self, logs, target_ips: List[str]):
        result: Dict[Tuple[str, str, str, str, str], Dict] = defaultdict(
            lambda: {
                "count": 0,
                "actions": set(),
                "apps": set(),
                "srcintfs": set(),
                "dstintfs": set(),
                "policynames": set(),
                "devnames": set(),
            }
        )

        target_set = set(target_ips) if target_ips else None

        for log in logs:
            srcip = log.get("srcip")
            dstip = log.get("dstip")
            if not srcip or not dstip:
                continue
            if srcip in self.exclude_ips or dstip in self.exclude_ips:
                continue
            if target_set and (srcip not in target_set and dstip not in target_set):
                continue

            dstport = str(log.get("dstport", "-"))
            proto = proto_to_name(log.get("proto"))
            policyid = str(log.get("policyid")) if log.get("policyid") is not None else "-"

            key = (srcip, dstip, dstport, proto, policyid)
            entry = result[key]
            entry["count"] += 1

            if log.get("smart_action"):
                entry["actions"].add(log["smart_action"])
            if log.get("app"):
                entry["apps"].add(log["app"])
            if log.get("srcintf"):
                entry["srcintfs"].add(log["srcintf"])
            if log.get("dstintf"):
                entry["dstintfs"].add(log["dstintf"])
            if log.get("policyname"):
                entry["policynames"].add(log["policyname"])
            if log.get("devname"):
                entry["devnames"].add(log["devname"])

        return result

    def build_policyid_report(self, stats, policyid: int) -> str:
        if not stats:
            return ""

        show_connections = COLUMNS_CONFIG.get("connections", True)

        extra_cols = []
        if COLUMNS_CONFIG.get("action"):
            extra_cols.append(("Action", "actions"))
        if COLUMNS_CONFIG.get("app"):
            extra_cols.append(("App", "apps"))
        if COLUMNS_CONFIG.get("srcintf"):
            extra_cols.append(("SrcIntf", "srcintfs"))
        if COLUMNS_CONFIG.get("dstintf"):
            extra_cols.append(("DstIntf", "dstintfs"))
        if COLUMNS_CONFIG.get("policyname"):
            extra_cols.append(("PolicyName", "policynames"))
        if COLUMNS_CONFIG.get("devname"):
            extra_cols.append(("DevName", "devnames"))

        lines = [
            "=" * 110,
            f"POLICYID ANALYSIS — policyid={policyid}",
            "=" * 110,
            "",
            ]

        columns = [
            ("SRC", 15),
            ("DST", 15),
            ("Port", 6),
            ("Proto", 5),
            ("PolicyID", 8),
        ]
        if show_connections:
            columns.append(("Count", 8))
        for col, _ in extra_cols:
            columns.append((col, 15))

        head = "".join([f"{name:<{width}}  " for name, width in columns])
        sep = "-" * min(len(head), 140)
        lines.append(head)
        lines.append(sep)

        total_conns = 0
        for (src, dst, port, proto, pol), d in sorted(
                stats.items(), key=lambda x: -x[1]["count"]
        ):
            total_conns += d["count"]
            row_parts = [
                (src, 15),
                (dst, 15),
                (port, 6),
                (proto, 5),
                (pol, 8),
            ]
            if show_connections:
                row_parts.append((str(d["count"]), 8))

            row = "".join([f"{val:<{width}}  " for val, width in row_parts])
            for _, field in extra_cols:
                values = d.get(field) or set()
                row += f"{','.join(sorted(values)) or '-':<15}  "
            lines.append(row)

        lines.append("")
        lines.append(f"Total entries: {total_conns}")
        return "\n".join(lines)


# ----------------------------------------------------------
# LOCAL SMART-ACTION FILTER
# ----------------------------------------------------------
def _filter_logs_by_smart_action(logs, smart_action: str):
    smart_action = (smart_action or "all").lower()

    if smart_action == "all":
        return logs
    if smart_action == "all-accept":
        return [
            x for x in logs
            if x.get("smart_action") == "all-accept" or x.get("action") == "accept"
        ]
    if smart_action == "deny":
        return [
            x for x in logs
            if x.get("smart_action") in ("all-deny", "deny") or x.get("action") == "deny"
        ]
    return logs


# ----------------------------------------------------------
# TIME RANGE SPLITTING
# ----------------------------------------------------------
def _split_time_range(start_time: str, end_time: str, max_hours: int):
    if not max_hours or max_hours <= 0:
        return [(start_time, end_time)]

    fmt = "%Y-%m-%d %H:%M:%S"
    try:
        start_dt = datetime.strptime(start_time, fmt)
        end_dt = datetime.strptime(end_time, fmt)
    except Exception:
        return [(start_time, end_time)]

    if start_dt >= end_dt:
        return [(start_time, end_time)]

    ranges = []
    delta = timedelta(hours=max_hours)
    cur = start_dt
    while cur < end_dt:
        seg_end = min(cur + delta, end_dt)
        ranges.append((cur.strftime(fmt), seg_end.strftime(fmt)))
        cur = seg_end
    return ranges


# ----------------------------------------------------------
# FAZ FILTERS
# ----------------------------------------------------------
def build_faz_filter(direction, target_ips, ports=None, exclude_ips=None):
    exclude_ips = exclude_ips or []

    if direction == "inbound":
        local_field = "dstip"
        remote_field = "srcip"
    else:
        local_field = "srcip"
        remote_field = "dstip"

    if len(target_ips) == 1:
        combined = f'({local_field}="{target_ips[0]}")'
    else:
        vals = ",".join([f'"{ip}"' for ip in target_ips])
        combined = f"({local_field} in [{vals}])"

    if FILTER_MODE == "faz":
        smart_expr = SMART_ACTION_MAP.get(SMART_ACTION)
        if smart_expr:
            combined += f" and ({smart_expr})"

    if ports:
        p = " or ".join([f'(dstport="{x}")' for x in ports])
        combined += f" and ({p})"

    for ip in exclude_ips:
        combined += f' and ({remote_field}!="{ip}")'

    return combined


def build_policy_faz_filter(policyid: int, target_ips: List[str], ports=None) -> str:
    parts = [f"(policyid={policyid})"]

    if FILTER_MODE == "faz":
        smart_expr = SMART_ACTION_MAP.get(SMART_ACTION)
        if smart_expr:
            parts.append(f"({smart_expr})")

    if target_ips:
        ip_exprs = []
        for ip in target_ips:
            ip_exprs.append(f'srcip="{ip}"')
            ip_exprs.append(f'dstip="{ip}"')
        parts.append("(" + " or ".join(ip_exprs) + ")")

    if ports:
        p = " or ".join([f'(dstport="{x}")' for x in ports])
        parts.append(f"({p})")

    return " and ".join(parts)


# ----------------------------------------------------------
# MAIN INTERFACE — inbound / outbound
# ----------------------------------------------------------
def analyze_logs(
        client,
        target_ips,
        direction,
        start_time,
        end_time,
        exclude_ips,
        batch_size=100,
        ports=None,
):
    filter_str = build_faz_filter(direction, target_ips, ports, exclude_ips)

    print(f"🔎 FILTER: {filter_str}")
    print(f"🕒 TIME RANGE: {start_time} → {end_time}")
    print(f"⚙ SMART_ACTION={SMART_ACTION}, FILTER_MODE={FILTER_MODE}")

    time_ranges = _split_time_range(start_time, end_time, MAX_TASK_HOURS)
    all_logs = []

    for seg_start, seg_end in time_ranges:
        print(f"⏱ Segment: {seg_start} → {seg_end}")

        tid = client.create_search_task(filter_str, seg_start, seg_end)
        if not tid:
            continue

        ok, matched = client.wait_for_task_completion(tid)
        if not ok or matched == 0:
            continue

        if MAX_MATCHED_LOGS_PER_TASK > 0 and matched > MAX_MATCHED_LOGS_PER_TASK:
            matched = MAX_MATCHED_LOGS_PER_TASK

        logs_segment = client.fetch_logs(tid, matched, batch_size)
        if logs_segment:
            all_logs.extend(logs_segment)

    if not all_logs:
        return {}

    if FILTER_MODE == "local":
        all_logs = _filter_logs_by_smart_action(all_logs, SMART_ACTION)

    analyzer = LogAnalyzer(exclude_ips)
    stats = analyzer.aggregate_by_local(all_logs, direction, target_ips)
    return analyzer.build_reports_per_local(stats, direction, target_ips)


# ----------------------------------------------------------
# MAIN INTERFACE — policyid mode
# ----------------------------------------------------------
def analyze_policyid_logs(
        client,
        target_ips,
        policyid,
        start_time,
        end_time,
        exclude_ips,
        batch_size=100,
        ports=None,
):
    filter_str = build_policy_faz_filter(policyid, target_ips, ports)

    print(f"🔎 FILTER: {filter_str}")
    print(f"🕒 TIME RANGE: {start_time} → {end_time}")
    print(f"⚙ SMART_ACTION={SMART_ACTION}, FILTER_MODE={FILTER_MODE}")

    time_ranges = _split_time_range(start_time, end_time, MAX_TASK_HOURS)
    all_logs = []

    for seg_start, seg_end in time_ranges:
        print(f"⏱ Segment: {seg_start} → {seg_end}")

        tid = client.create_search_task(filter_str, seg_start, seg_end)
        if not tid:
            continue

        ok, matched = client.wait_for_task_completion(tid)
        if not ok or matched == 0:
            continue

        if MAX_MATCHED_LOGS_PER_TASK > 0 and matched > MAX_MATCHED_LOGS_PER_TASK:
            matched = MAX_MATCHED_LOGS_PER_TASK

        logs_segment = client.fetch_logs(tid, matched, batch_size)
        if logs_segment:
            all_logs.extend(logs_segment)

    if not all_logs:
        return ""

    if FILTER_MODE == "local":
        all_logs = _filter_logs_by_smart_action(all_logs, SMART_ACTION)

    analyzer = LogAnalyzer(exclude_ips)
    stats = analyzer.aggregate_by_policyid(all_logs, target_ips)
    return analyzer.build_policyid_report(stats, policyid)
