from collections import defaultdict
from typing import Dict, List

from utils.network import resolve_hostname


def proto_to_name(proto_id) -> str:
    try:
        return {6: "tcp", 17: "udp", 1: "icmp"}.get(int(proto_id), str(proto_id))
    except:
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

        result = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

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
            result[local_ip][key]["count"] += 1

        return result

    def build_reports_per_local(self, stats, direction, target_ips):
        """Generate text reports for inbound/outbound traffic per target IP."""
        reports = {}

        for local_ip, entries in stats.items():
            lines = []

            header = (
                f"{'=' * 110}\n"
                f"{direction.upper()} TRAFFIC for local IP: {local_ip}\n"
                f"{'=' * 110}\n\n"
                f"{'Remote IP':<15}  {'Hostname':<30}  {'Port':<6}  {'Proto':<5}  {'Connections'}\n"
                f"{'-' * 110}"
            )
            lines.append(header)

            total_conns = 0
            unique_ips = set()

            for (remote, port, proto), d in sorted(
                    entries.items(), key=lambda x: -x[1]["count"]
            ):
                count = d["count"]
                total_conns += count
                unique_ips.add(remote)
                hostname = resolve_hostname(remote)
                lines.append(
                    f"{remote:<15}  {hostname:<30}  {port:<6}  {proto:<5}  {count}"
                )

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
    """

    if direction == "inbound":
        field = "dstip"
    else:
        field = "srcip"

    # Одиночный IP — всегда = "ip"
    if len(target_ips) == 1:
        ip = target_ips[0]
        return f'({field} = "{ip}")'

    # Несколько IP — список
    quoted = ",".join(f'"{ip}"' for ip in target_ips)
    return f'({field} in [{quoted}])'


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

    print(f"📊 Analyzing {len(logs)} logs")

    analyzer = LogAnalyzer(exclude_ips)
    stats = analyzer.aggregate_by_local(logs, direction, target_ips)

    if not stats:
        print("⚠️ Stats empty after aggregation.")
        return {}

    return analyzer.build_reports_per_local(stats, direction, target_ips)
