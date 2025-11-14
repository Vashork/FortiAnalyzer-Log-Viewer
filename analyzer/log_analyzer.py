from collections import defaultdict
from typing import Dict, List, Tuple
from utils.network import resolve_hostname


def proto_to_name(proto_id: str) -> str:
    """Convert protocol number to name (e.g., '6' -> 'tcp')"""
    try:
        proto_num = int(proto_id)
        if proto_num == 6:
            return "tcp"
        elif proto_num == 17:
            return "udp"
        elif proto_num == 1:
            return "icmp"
        else:
            return str(proto_num)
    except (ValueError, TypeError):
        return "unknown"


class LogAnalyzer:
    def __init__(self, exclude_ips: List[str] = None):
        self.exclude_ips = set(exclude_ips) if exclude_ips else set()
        if self.exclude_ips:
            print(f"🚫 Will exclude {len(self.exclude_ips)} IP addresses from statistics")

    def aggregate_traffic(self, logs: List[Dict], direction: str) -> Dict[str, Dict[Tuple[str, str], int]]:
        """
        Aggregate by remote IP, dstport, and proto.
        For both directions, we care about: who -> dstport/proto (service being accessed)
        """
        stats = defaultdict(lambda: defaultdict(int))
        excluded_count = 0

        # Для обоих направлений: нас интересует dstip, dstport, proto
        for log in logs:
            dst_ip = log.get('dstip', 'Unknown')
            dst_port = log.get('dstport', 'Unknown')
            proto = log.get('proto', 'Unknown')
            src_ip = log.get('srcip', 'Unknown')

            # Определяем "remote" IP в зависимости от направления:
            # - OUTBOUND: remote = dstip
            # - INBOUND:  remote = srcip (потому что dstip — это ваша машина)
            if direction == "outbound":
                remote_ip = dst_ip
                target_ip = src_ip  # ваша машина
            else:  # inbound
                remote_ip = src_ip
                target_ip = dst_ip  # ваша машина

            # Исключаем по remote IP (входящий) или по dst IP (исходящий)?
            # Поскольку вы передаёте exclude_ips как "ваши машинные IP", то исключать нужно по target_ip
            # Но чтобы не ломать текущую логику — оставим исключение по remote_ip
            # (обычно exclude_ips — это внутренние сервисы, которые вы не хотите видеть как "remote")
            if remote_ip in self.exclude_ips:
                excluded_count += 1
                continue

            if remote_ip != 'Unknown' and dst_port != 'Unknown' and proto != 'Unknown':
                key = (str(dst_port), proto_to_name(proto))
                stats[remote_ip][key] += 1

        if excluded_count > 0:
            print(f"🚫 Excluded {excluded_count} connections to filtered IPs")
        return dict(stats)

    def format_results(self, stats: Dict[str, Dict[Tuple[str, str], int]], direction: str) -> str:
        title = "OUTBOUND TRAFFIC" if direction == "outbound" else "INBOUND TRAFFIC"
        output = []
        output.append("=" * 110)
        output.append(f"FORTIANALYZER {title}")
        output.append("=" * 110)
        output.append("")

        output.append(f"{'Remote IP':<15} {'Hostname':<30} {'DstPort':<8} {'Proto':<6} {'Connections':<11}")
        output.append("-" * 110)

        entries = []
        for remote_ip, port_proto_stats in stats.items():
            hostname = resolve_hostname(remote_ip)
            for (dst_port, proto), count in port_proto_stats.items():
                entries.append((remote_ip, hostname, dst_port, proto, count))

        # Сортировка по количеству соединений (убывание)
        entries.sort(key=lambda x: x[4], reverse=True)

        for remote_ip, hostname, dst_port, proto, count in entries:
            hostname_display = hostname[:29] if len(hostname) > 29 else hostname
            output.append(f"{remote_ip:<15} {hostname_display:<30} {dst_port:<8} {proto:<6} {count:<11}")

        output.append("")
        total_unique = len(stats)
        total_connections = sum(sum(stats.values()) for stats in stats.values())
        output.append(f"Total unique remotes: {total_unique}")
        output.append(f"Total connections: {total_connections}")

        return "\n".join(output)