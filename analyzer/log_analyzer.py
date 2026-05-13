from collections import defaultdict
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta

from utils.network import resolve_hostname
from config import (
    COLUMNS_CONFIG,
    AGGREGATION_CONFIG,
    SMART_ACTION,
    FILTER_MODE,
    MAX_TASK_HOURS,
    MAX_MATCHED_LOGS_PER_TASK,
)


LOCAL_AGGREGATION_FIELDS = ("remote_ip", "port", "proto")
POLICYID_AGGREGATION_FIELDS = ("srcip", "dstip", "port", "proto", "policyid")
POLICYID_COLUMN_SPECS = {
    "srcip": ("Srcip", 15),
    "dstip": ("Dstip", 15),
    "port": ("Dstport", 7),
    "proto": ("Proto", 5),
    "policyid": ("PolicyID", 8),
}


def _config_bool(config: dict, key: str, default: bool = True) -> bool:
    value = config.get(key, default)
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "y", "on")
    return bool(value)


def _join_values(values) -> str:
    return ",".join(sorted(str(value) for value in values)) or "-"

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


# ------------------------------------------
# SAFE TIME RANGE SPLITTER (ШАГ 1)
# ------------------------------------------
def split_time_range_safe(start_time: str, end_time: str, max_hours: int):
    """
    Надёжно режет временной интервал на сегменты.
    Гарантированно НЕ возвращает один сегмент,
    если max_hours > 0 и даты валидны.
    """

    if not max_hours or max_hours <= 0:
        return [(start_time, end_time)]

    # нормализация 23:59:99 → 23:59:59
    if end_time.endswith(":99"):
        end_time = end_time[:-2] + "59"

    fmt = "%Y-%m-%d %H:%M:%S"
    start_dt = datetime.strptime(start_time, fmt)
    end_dt = datetime.strptime(end_time, fmt)

    segments = []
    delta = timedelta(hours=max_hours)
    cur = start_dt

    while cur < end_dt:
        seg_end = min(cur + delta, end_dt)
        segments.append(
            (cur.strftime(fmt), seg_end.strftime(fmt))
        )
        cur = seg_end

    return segments


class LogAnalyzer:
    """Aggregates logs into structured reports."""

    def __init__(self, exclude_ips: List[str], columns: dict = None, aggregation: dict = None):
        self.exclude_ips = set(exclude_ips)
        self.columns = columns if columns is not None else COLUMNS_CONFIG
        self.aggregation = dict(AGGREGATION_CONFIG)
        if aggregation:
            self.aggregation.update(aggregation)

    def _local_aggregation_fields(self) -> Tuple[str, ...]:
        return tuple(
            field for field in LOCAL_AGGREGATION_FIELDS
            if _config_bool(self.aggregation, field)
        )

    def _policyid_aggregation_fields(self) -> Tuple[str, ...]:
        return tuple(
            field for field in POLICYID_AGGREGATION_FIELDS
            if _config_bool(self.aggregation, field)
        )

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

        group_fields = self._local_aggregation_fields()
        target_set = set(target_ips)

        result: Dict[str, Dict[Tuple[str, ...], Dict]] = defaultdict(
            lambda: defaultdict(
                lambda: {
                    "count": 0,
                    "remote_ips": set(),
                    "actions": set(),
                    "policyids": set(),
                    "apps": set(),
                    "srcports": set(),
                    "srcintfs": set(),
                    "dstintfs": set(),
                    "policynames": set(),
                    "devnames": set(),
                    "smart_actions": set(),
                }
            )
        )

        for log in logs:
            local_ip = log.get(local_field)
            remote_ip = log.get(remote_field)

            if not local_ip or not remote_ip:
                continue
            if local_ip not in target_set:
                continue
            if remote_ip in self.exclude_ips:
                continue

            proto = proto_to_name(log.get("proto"))
            port = str(log.get(port_field, "-"))
            values = {
                "remote_ip": str(remote_ip),
                "port": port,
                "proto": proto,
            }
            key = tuple(values[field] for field in group_fields)
            entry = result[local_ip][key]

            entry["count"] += 1
            entry["remote_ips"].add(str(remote_ip))

            if log.get("smart_action"):
                entry["actions"].add(log["smart_action"])
            elif log.get("action"):
                entry["actions"].add(log["action"])
            # Smart Action: derive from FAZ raw fields
            # Priority: smart_action > utmaction > action
            sa = log.get("smart_action") or log.get("utmaction") or log.get("utm_action") or log.get("action") or log.get("utm_result")
            if sa:
                entry["smart_actions"].add(str(sa))
            if log.get("policyid") is not None:
                entry["policyids"].add(str(log["policyid"]))
            if log.get("app"):
                entry["apps"].add(log["app"])
            if log.get("srcport") is not None:
                entry["srcports"].add(str(log["srcport"]))
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
        show_connections = self.columns.get("connections", True)
        group_fields = self._local_aggregation_fields()

        extra_cols = []
        if self.columns.get("action"):
            extra_cols.append(("Action", "actions"))
        if self.columns.get("policyid"):
            extra_cols.append(("PolicyID", "policyids"))
        if self.columns.get("app"):
            extra_cols.append(("App", "apps"))
        if self.columns.get("srcport"):
            extra_cols.append(("Srcport", "srcports"))
        if self.columns.get("srcintf"):
            extra_cols.append(("SrcIntf", "srcintfs"))
        if self.columns.get("dstintf"):
            extra_cols.append(("DstIntf", "dstintfs"))
        if self.columns.get("policyname"):
            extra_cols.append(("PolicyName", "policynames"))
        if self.columns.get("devname"):
            extra_cols.append(("DevName", "devnames"))
        if self.columns.get("smart_action"):
            extra_cols.append(("SmartAction", "smart_actions"))

        for local_ip, items in stats.items():
            lines = [
                "=" * 110,
                f"{direction.upper()} TRAFFIC for local IP: {local_ip}",
                "=" * 110,
                "",
                ]

            columns = []
            if "remote_ip" in group_fields:
                columns.extend([
                    ("Remote IP", 15),
                    ("Hostname", 30),
                ])
            if "port" in group_fields:
                columns.append(("Dstport", 7))
            if "proto" in group_fields:
                columns.append(("Proto", 5))
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

            for key, d in sorted(
                    items.items(), key=lambda x: (-x[1]["count"], x[0])
            ):
                group_values = dict(zip(group_fields, key))
                total_conns += d["count"]
                uniq_ips.update(d.get("remote_ips", set()))

                row_parts = []
                if "remote_ip" in group_fields:
                    remote = group_values["remote_ip"]
                    row_parts.extend([
                        (remote, 15),
                        (resolve_hostname(remote), 30),
                    ])
                if "port" in group_fields:
                    row_parts.append((group_values["port"], 7))
                if "proto" in group_fields:
                    row_parts.append((group_values["proto"], 5))
                if show_connections:
                    row_parts.append((str(d["count"]), 11))

                row = "".join([f"{val:<{width}}  " for val, width in row_parts])
                for _, field in extra_cols:
                    values = d.get(field) or set()
                    row += f"{_join_values(values):<15}  "
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
        group_fields = self._policyid_aggregation_fields()

        result: Dict[Tuple[str, ...], Dict] = defaultdict(
            lambda: {
                "count": 0,
                "actions": set(),
                "policyids": set(),
                "apps": set(),
                "srcports": set(),
                "srcintfs": set(),
                "dstintfs": set(),
                "policynames": set(),
                "devnames": set(),
                "smart_actions": set(),
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

            values = {
                "srcip": str(srcip),
                "dstip": str(dstip),
                "port": dstport,
                "proto": proto,
                "policyid": policyid,
            }
            key = tuple(values[field] for field in group_fields)
            entry = result[key]
            entry["count"] += 1
            entry["policyids"].add(policyid)

            # Smart Action: derive from FAZ raw fields
            # Priority: smart_action > utmaction > action
            sa = log.get("smart_action") or log.get("utmaction") or log.get("utm_action") or log.get("action") or log.get("utm_result")
            if sa:
                entry["actions"].add(str(sa))
                entry["smart_actions"].add(str(sa))
            if log.get("app"):
                entry["apps"].add(log["app"])
            if log.get("srcport") is not None:
                entry["srcports"].add(str(log["srcport"]))
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

        show_connections = self.columns.get("connections", True)
        group_fields = self._policyid_aggregation_fields()

        extra_cols = []
        if self.columns.get("action"):
            extra_cols.append(("Action", "actions"))
        if self.columns.get("policyid") and "policyid" not in group_fields:
            extra_cols.append(("PolicyID", "policyids"))
        if self.columns.get("app"):
            extra_cols.append(("App", "apps"))
        if self.columns.get("srcport"):
            extra_cols.append(("Srcport", "srcports"))
        if self.columns.get("srcintf"):
            extra_cols.append(("SrcIntf", "srcintfs"))
        if self.columns.get("dstintf"):
            extra_cols.append(("DstIntf", "dstintfs"))
        if self.columns.get("policyname"):
            extra_cols.append(("PolicyName", "policynames"))
        if self.columns.get("devname"):
            extra_cols.append(("DevName", "devnames"))
        if self.columns.get("smart_action"):
            extra_cols.append(("SmartAction", "smart_actions"))

        lines = [
            "=" * 110,
            f"POLICYID ANALYSIS — policyid={policyid}",
            "=" * 110,
            "",
            ]

        columns = [POLICYID_COLUMN_SPECS[field] for field in group_fields]
        if show_connections:
            columns.append(("Count", 8))
        for col, _ in extra_cols:
            columns.append((col, 15))

        head = "".join([f"{name:<{width}}  " for name, width in columns])
        sep = "-" * min(len(head), 140)
        lines.append(head)
        lines.append(sep)

        total_conns = 0
        for key, d in sorted(
                stats.items(), key=lambda x: (-x[1]["count"], x[0])
        ):
            group_values = dict(zip(group_fields, key))
            total_conns += d["count"]
            row_parts = [
                (group_values[field], POLICYID_COLUMN_SPECS[field][1])
                for field in group_fields
            ]
            if show_connections:
                row_parts.append((str(d["count"]), 8))

            row = "".join([f"{val:<{width}}  " for val, width in row_parts])
            for _, field in extra_cols:
                values = d.get(field) or set()
                row += f"{_join_values(values):<15}  "
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
        columns=None,
        aggregation=None,
        progress=None,
):
    filter_str = build_faz_filter(direction, target_ips, ports, exclude_ips)

    if progress:
        progress(f"📡 {direction}: {len(target_ips)} IPs, {start_time} → {end_time}")

    time_ranges = split_time_range_safe(start_time, end_time, MAX_TASK_HOURS)
    all_logs = []

    for seg_start, seg_end in time_ranges:
        if progress:
            progress(f"⏱ {direction}: {seg_start} → {seg_end}")

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

    if progress:
        if all_logs:
            progress(f"✅ {direction}: {len(all_logs)} logs found")
        else:
            progress(f"⚠ {direction}: no logs in FAZ for this direction")

    if not all_logs:
        return {}

    if progress:
        progress(f"🧮 {direction}: aggregating {len(all_logs)} logs", ip=target_ips[0] if len(target_ips) == 1 else None)

    if FILTER_MODE == "local":
        all_logs = _filter_logs_by_smart_action(all_logs, SMART_ACTION)

    analyzer = LogAnalyzer(exclude_ips, columns=columns, aggregation=aggregation)
    stats = analyzer.aggregate_by_local(all_logs, direction, target_ips)
    if progress:
        progress(f"📝 {direction}: building report", ip=target_ips[0] if len(target_ips) == 1 else None)
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
        columns=None,
        aggregation=None,
        progress=None,
):
    filter_str = build_policy_faz_filter(policyid, target_ips, ports)

    print(f"🔎 FILTER: {filter_str}")
    print(f"🕒 TIME RANGE: {start_time} → {end_time}")
    print(f"⚙ SMART_ACTION={SMART_ACTION}, FILTER_MODE={FILTER_MODE}")

    time_ranges = split_time_range_safe(start_time, end_time, MAX_TASK_HOURS)
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

    if progress:
        progress(f"🧮 policyid={policyid}: aggregating {len(all_logs)} logs")

    if FILTER_MODE == "local":
        all_logs = _filter_logs_by_smart_action(all_logs, SMART_ACTION)

    analyzer = LogAnalyzer(exclude_ips, columns=columns, aggregation=aggregation)
    stats = analyzer.aggregate_by_policyid(all_logs, target_ips)
    if progress:
        progress(f"📝 policyid={policyid}: building report")
    return analyzer.build_policyid_report(stats, policyid)
