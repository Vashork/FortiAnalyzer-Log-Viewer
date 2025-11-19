from collections import defaultdict
from typing import Dict, List

from utils.network import resolve_hostname
from config import COLUMNS_CONFIG, SMART_ACTION, FILTER_MODE


def proto_to_name(proto_id) -> str:
    try:
        return {6: "tcp", 17: "udp", 1: "icmp"}.get(int(proto_id), str(proto_id))
    except Exception:
        return "unknown"


class LogAnalyzer:
    """Aggregates logs into structured report per local_ip."""

    def __init__(self, exclude_ips: List[str]):
        self.exclude_ips = set(exclude_ips)

    def aggregate_by_local(self, logs, direction, target_ips):
        """Group logs by local IP and summarize remote endpoints."""
        if direction == "inbound":
            local_field = "dstip"
            remote_field = "srcip"
            port_field = "dstport"
        else:
            local_field = "srcip"
            remote_field = "dstip"
            port_field = "dstport"

        # result[local_ip][(remote, port, proto)] = {...}
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
            proto = proto_to_name(log.get("proto"))
            port = log.get(port_field, "-")

            if not local_ip or not remote_ip:
                continue
            if remote_ip in self.exclude_ips:
                continue
            if local_ip not in target_ips:
                continue

            key = (remote_ip, port, proto)
            entry = result[local_ip][key]
            entry["count"] += 1

            # Дополнительные поля для колонок
            action = log.get("action")
            if action:
                entry["actions"].add(action)

            policyid = log.get("policyid")
            if policyid is not None:
                entry["policyids"].add(str(policyid))

            app = log.get("app")
            if app:
                entry["apps"].add(app)

            srcintf = log.get("srcintf")
            if srcintf:
                entry["srcintfs"].add(srcintf)

            dstintf = log.get("dstintf")
            if dstintf:
                entry["dstintfs"].add(dstintf)

            policyname = log.get("policyname")
            if policyname:
                entry["policynames"].add(policyname)

            devname = log.get("devname")
            if devname:
                entry["devnames"].add(devname)

        return result

    def build_reports_per_local(self, stats, direction, target_ips):
        """Generate text reports for inbound/outbound traffic per target IP."""
        reports = {}

        # Подготовим список доп. колонок на основе COLUMNS_CONFIG
        extra_columns = []
        if COLUMNS_CONFIG.get("action"):
            extra_columns.append(("Action", "actions"))
        if COLUMNS_CONFIG.get("policyid"):
            extra_columns.append(("PolicyID", "policyids"))
        if COLUMNS_CONFIG.get("app"):
            extra_columns.append(("App", "apps"))
        if COLUMNS_CONFIG.get("srcintf"):
            extra_columns.append(("SrcIntf", "srcintfs"))
        if COLUMNS_CONFIG.get("dstintf"):
            extra_columns.append(("DstIntf", "dstintfs"))
        if COLUMNS_CONFIG.get("policyname"):
            extra_columns.append(("PolicyName", "policynames"))
        if COLUMNS_CONFIG.get("devname"):
            extra_columns.append(("DevName", "devnames"))

        for local_ip, entries in stats.items():
            lines = []

            # Заголовок
            header = [
                "=" * 110,
                f"{direction.upper()} TRAFFIC for local IP: {local_ip}",
                "=" * 110,
                "",
                ]

            # Базовая шапка таблицы
            base_header = (
                f"{'Remote IP':<15}  "
                f"{'Hostname':<30}  "
                f"{'Port':<6}  "
                f"{'Proto':<5}  "
                f"{'Connections':<11}"
            )

            # Добавляем доп. колонки в шапку
            for col_name, _ in extra_columns:
                base_header += f"  {col_name:<15}"

            separator = "-" * min(len(base_header), 140)

            header.append(base_header)
            header.append(separator)
            lines.extend(header)

            total_conns = 0
            unique_ips = set()

            # Сортируем по убыванию count
            for (remote, port, proto), d in sorted(
                    entries.items(), key=lambda x: -x[1]["count"]
            ):
                count = d["count"]
                total_conns += count
                unique_ips.add(remote)
                hostname = resolve_hostname(remote)

                line = (
                    f"{remote:<15}  "
                    f"{hostname:<30}  "
                    f"{port:<6}  "
                    f"{proto:<5}  "
                    f"{count:<11}"
                )

                # Доп. колонки — join множеств через запятую
                for _, key in extra_columns:
                    values = d.get(key) or set()
                    if values:
                        cell = ",".join(sorted(values))
                    else:
                        cell = "-"
                    line += f"  {cell:<15}"

                lines.append(line)

            lines.append("")
            lines.append(f"Total unique remotes: {len(unique_ips)}")
            lines.append(f"Total connections: {total_conns}")

            reports[(local_ip, direction)] = "\n".join(lines)

        return reports


def build_faz_filter(direction: str, target_ips: List[str]) -> str:
    """
    Builds a FortiAnalyzer-compatible filter:
      - For 1 IP:  srcip = "A.B.C.D"
      - For many:  srcip in ["A","B","C"]

    Здесь же, если FILTER_MODE=FAZ и SMART_ACTION != all,
    добавляем фильтр по полю action.
    """
    if direction == "inbound":
        field = "dstip"
    else:
        field = "srcip"

    # Базовый IP-фильтр
    if len(target_ips) == 1:
        ip = target_ips[0]
        base_filter = f'({field} = "{ip}")'
    else:
        quoted = ",".join(f'"{ip}"' for ip in target_ips)
        base_filter = f"({field} in [{quoted}])"

    # Smart-фильтрация на стороне FAZ
    if FILTER_MODE == "faz":
        action_part = None
        if SMART_ACTION == "deny":
            action_part = '(action="deny")'
        elif SMART_ACTION == "all-accept":
            action_part = '(action="accept")'

        if action_part:
            return f"{base_filter} and {action_part}"

    # Иначе — только IP
    return base_filter


def _filter_logs_by_smart_action(logs, smart_action: str):
    """Локальная фильтрация логов по полю action (если FILTER_MODE=LOCAL)."""
    if smart_action == "all":
        return logs

    target_action = None
    if smart_action == "deny":
        target_action = "deny"
    elif smart_action == "all-accept":
        target_action = "accept"

    if not target_action:
        return logs

    filtered = [log for log in logs if log.get("action") == target_action]
    return filtered


def analyze_logs(
        client,
        target_ips,
        direction,
        start_time,
        end_time,
        exclude_ips,
        batch_size=100,
):
    """Full FAZ log analysis pipeline."""

    # 1. Build correct FortiAnalyzer filter
    filter_str = build_faz_filter(direction, target_ips)

    print(f"🔎 FILTER: {filter_str}")
    print(f"🕒 TIME RANGE: {start_time} → {end_time}")
    print(f"⚙️ SMART_ACTION={SMART_ACTION}, FILTER_MODE={FILTER_MODE}")

    # 2. Create search task
    task_id = client.create_search_task(filter_str, start_time, end_time)
    if not task_id:
        print("❌ Failed to create search task in FAZ")
        return {}

    # 3. Wait for task
    ok, matched = client.wait_for_task_completion(task_id)
    if not ok:
        print("❌ FAZ task did not complete")
        return {}

    if matched == 0:
        print("⚠️ No matching logs found.")
        return {}

    # 4. Fetch logs
    logs = client.fetch_logs(task_id, matched, batch_size=batch_size)
    if not logs:
        print("⚠️ No logs retrieved from FAZ.")
        return {}

    print(f"📊 Retrieved {len(logs)} raw logs")

    # 4.1. Локальная фильтрация по action, если выбрано FILTER_MODE=LOCAL
    if FILTER_MODE == "local":
        before = len(logs)
        logs = _filter_logs_by_smart_action(logs, SMART_ACTION)
        print(f"🔧 Local smart_action='{SMART_ACTION}': {before} → {len(logs)} logs")
        if not logs:
            print("⚠️ No logs left after local smart_action filter.")
            return {}

    print(f"📊 Analyzing {len(logs)} logs after filtering")

    analyzer = LogAnalyzer(exclude_ips)
    stats = analyzer.aggregate_by_local(logs, direction, target_ips)

    if not stats:
        print("⚠️ Stats empty after aggregation.")
        return {}

    return analyzer.build_reports_per_local(stats, direction, target_ips)
