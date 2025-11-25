from collections import defaultdict
from typing import Dict, List, Optional

from utils.network import resolve_hostname
from config import COLUMNS_CONFIG, SMART_ACTION, FILTER_MODE


# ------------------------------------------
# PROTOCOL NAMES
# ------------------------------------------
def proto_to_name(proto_id) -> str:
    try:
        return {6: "tcp", 17: "udp", 1: "icmp"}.get(int(proto_id), str(proto_id))
    except Exception:
        return "unknown"


# ------------------------------------------
# SMART ACTION MAP (правильный)
# ------------------------------------------
SMART_ACTION_MAP = {
    "all-accept": 'smart_action="all-accept"',
    "deny": 'smart_action="all-deny"',
    "dns-error": 'smart_action="dns-error"',
}


class LogAnalyzer:
    """Aggregates logs into structured per-local reports."""

    def __init__(self, exclude_ips: List[str]):
        self.exclude_ips = set(exclude_ips)

    # ----------------------------------------------------------
    # GROUP LOGS BY LOCAL → REMOTE (inbound/outbound)
    # ----------------------------------------------------------
    def aggregate_by_local(self, logs, direction, target_ips):
        if direction == "inbound":
            local_field = "dstip"
            remote_field = "srcip"
            port_field = "dstport"
        else:
            local_field = "srcip"
            remote_field = "dstip"
            port_field = "dstport"

        result = defaultdict(
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

            # Python-level exclude (вариант C)
            if remote_ip in self.exclude_ips:
                continue

            proto = proto_to_name(log.get("proto"))
            port = log.get(port_field, "-")
            key = (remote_ip, port, proto)
            entry = result[local_ip][key]

            entry["count"] += 1

            # поля
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
    # BUILD HUMAN-READABLE REPORT
    # ----------------------------------------------------------
    def build_reports_per_local(self, stats, direction, target_ips):
        reports = {}
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

            # Header
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

            # Sort by count descending
            for (remote, port, proto), d in sorted(items.items(), key=lambda x: -x[1]["count"]):
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
# FILTER MODE: LOCAL
# ----------------------------------------------------------
def _filter_logs_by_smart_action(logs, smart_action: str):
    if smart_action == "all":
        return logs

    if smart_action == "all-accept":
        return [x for x in logs if x.get("smart_action") == "all-accept"]

    if smart_action == "deny":
        return [x for x in logs if x.get("smart_action") == "all-deny"]

    if smart_action == "dns-error":
        return [x for x in logs if x.get("smart_action") == "dns-error"]

    return logs


# ----------------------------------------------------------
# BUILD FAZ FILTER (правильный smart_action)
# ----------------------------------------------------------
def build_faz_filter(
        direction: str,
        target_ips: List[str],
        ports: Optional[List[str]] = None,
        exclude_ips: Optional[List[str]] = None,
) -> str:

    exclude_ips = exclude_ips or []

    if direction == "inbound":
        local_field = "dstip"
        remote_field = "srcip"
    else:
        local_field = "srcip"
        remote_field = "dstip"

    # Base
    if len(target_ips) == 1:
        combined = f'({local_field} = "{target_ips[0]}")'
    else:
        vals = ",".join([f'"{ip}"' for ip in target_ips])
        combined = f"({local_field} in [{vals}])"

    # SMART ACTION on FAZ
    if FILTER_MODE == "faz":
        smart_expr = SMART_ACTION_MAP.get(SMART_ACTION)
        if smart_expr:
            combined += f" and ({smart_expr})"

    # Ports
    if ports:
        p = " or ".join([f'(dstport="{x}")' for x in ports])
        combined += f" and ({p})"

    # EXCLUDE on FAZ
    for ip in exclude_ips:
        combined += f' and ({remote_field}!="{ip}")'

    return combined


# ----------------------------------------------------------
# MAIN INTERFACE
# ----------------------------------------------------------
def analyze_logs(
        client,
        target_ips,
        direction,
        start_time,
        end_time,
        exclude_ips,
        batch_size=100,
        ports: Optional[List[str]] = None,
):

    filter_str = build_faz_filter(direction, target_ips, ports, exclude_ips)

    print(f"🔎 FILTER: {filter_str}")
    print(f"🕒 TIME RANGE: {start_time} → {end_time}")
    print(f"⚙ SMART_ACTION={SMART_ACTION}, FILTER_MODE={FILTER_MODE}")

    if ports:
        print(f"🎯 PORTS: {', '.join(ports)}")

    # Create FAZ task
    tid = client.create_search_task(filter_str, start_time, end_time)
    if not tid:
        print("❌ Failed to create search task")
        return {}

    ok, matched = client.wait_for_task_completion(tid)
    if not ok or matched == 0:
        print("⚠ No matching logs found.")
        return {}

    logs = client.fetch_logs(tid, matched, batch_size)
    if not logs:
        print("⚠ No logs retrieved.")
        return {}

    # Local filter
    if FILTER_MODE == "local":
        logs = _filter_logs_by_smart_action(logs, SMART_ACTION)

    analyzer = LogAnalyzer(exclude_ips)
    stats = analyzer.aggregate_by_local(logs, direction, target_ips)

    return analyzer.build_reports_per_local(stats, direction, target_ips)
