# analyzer/log_analyzer.py

from collections import defaultdict
from typing import Dict, List, Tuple, Iterable, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.network import resolve_hostname


def proto_to_name(proto_id) -> str:
    """Convert protocol number or string to readable name."""
    try:
        proto_num = int(proto_id)
    except (TypeError, ValueError):
        return "unknown"

    if proto_num == 6:
        return "tcp"
    if proto_num == 17:
        return "udp"
    if proto_num == 1:
        return "icmp"
    return str(proto_num)


def normalize_proto_for_filter(proto: str) -> str:
    """
    Преобразует tcp/udp/icmp в числовое значение для фильтра FortiAnalyzer.
    Если пришёл уже номер (6/17/1) — отдаём как есть.
    """
    if proto is None:
        return ""

    p = str(proto).strip().lower()
    if not p:
        return ""

    mapping = {
        "tcp": "6",
        "udp": "17",
        "icmp": "1",
    }

    # tcp/udp/icmp -> номер
    if p in mapping:
        return mapping[p]

    # иначе считаем, что нам уже дали номер
    return p


class LogAnalyzer:
    """Aggregates FortiAnalyzer traffic logs into:
       local_ip -> remote_ip -> (port, proto) -> count.
    """

    def __init__(self, exclude_ips: Iterable[str] = None):
        self.exclude_ips = set(exclude_ips or [])
        if self.exclude_ips:
            print(f"🚫 Will exclude {len(self.exclude_ips)} IPs from remote results")

    def aggregate_by_local(
            self,
            logs: List[Dict],
            direction: str,
            target_ips: Iterable[str] = None,
    ) -> Dict[str, Dict[str, Dict[Tuple[str, str], int]]]:
        """
        Собирает статистику в структуру:
          { local_ip: { remote_ip: { (dst_port, proto): count } } }
        """
        stats: Dict[str, Dict[str, Dict[Tuple[str, str], int]]] = defaultdict(
            lambda: defaultdict(lambda: defaultdict(int))
        )
        excluded_count = 0
        target_set = set(target_ips) if target_ips else None

        for log in logs:
            dst = log.get("dstip")
            src = log.get("srcip")
            dst_port_raw = log.get("dstport", "Unknown")
            proto_raw = log.get("proto", "Unknown")

            dst_port = "Unknown" if not dst_port_raw else str(dst_port_raw)
            proto = proto_to_name(proto_raw)

            if direction == "outbound":
                local_ip = src
                remote_ip = dst
            else:  # inbound
                local_ip = dst
                remote_ip = src

            if not local_ip or not remote_ip:
                continue

            if target_set and local_ip not in target_set:
                continue

            if remote_ip in self.exclude_ips:
                excluded_count += 1
                continue

            if dst_port != "Unknown" and proto != "unknown":
                stats[local_ip][remote_ip][(dst_port, proto)] += 1

        if excluded_count > 0:
            print(f"🚫 Excluded {excluded_count} remote connections due to filter")

        return stats

    def _resolve_all_hostnames(self, remote_stats: Dict[str, Dict[Tuple[str, str], int]]) -> Dict[str, str]:
        """
        Параллельно резолвит PTR для всех remote_ip.
        Возвращает dict: ip -> hostname_or_ip.
        """
        remote_ips = list(remote_stats.keys())
        hostname_map: Dict[str, str] = {}

        if not remote_ips:
            return hostname_map

        print(f"🔁 Resolving hostnames for {len(remote_ips)} remote IPs...")

        max_workers = min(32, len(remote_ips))

        def worker(ip: str) -> Tuple[str, str]:
            try:
                return ip, resolve_hostname(ip)
            except Exception:
                # На всякий случай, хотя resolve_hostname уже перехватывает ошибки
                return ip, ip

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(worker, ip): ip for ip in remote_ips}
            for fut in as_completed(futures):
                ip, hostname = fut.result()
                hostname_map[ip] = hostname

        print("🔁 Hostname resolution done.")
        return hostname_map

    def _format_one(
            self,
            local_ip: str,
            remote_stats: Dict[str, Dict[Tuple[str, str], int]],
            direction: str,
    ) -> str:
        title = "OUTBOUND TRAFFIC" if direction == "outbound" else "INBOUND TRAFFIC"

        out: List[str] = []
        out.append("=" * 110)
        out.append(f"{title} for local IP: {local_ip}")
        out.append("=" * 110)
        out.append("")
        out.append(
            f"{'Remote IP':<15} {'Hostname':<30} {'DstPort':<8} {'Proto':<6} {'Connections':<11}"
        )
        out.append("-" * 110)

        # 🔥 Быстрый параллельный PTR-резолвинг
        hostname_map = self._resolve_all_hostnames(remote_stats)

        entries = []
        total = 0

        for remote_ip, port_map in remote_stats.items():
            hostname = hostname_map.get(remote_ip, remote_ip)
            for (port, proto), count in port_map.items():
                total += count
                entries.append((remote_ip, hostname, port, proto, count))

        # Сортируем по количеству соединений
        entries.sort(key=lambda x: x[4], reverse=True)

        for remote_ip, hostname, port, proto, count in entries:
            hn = hostname[:29] if len(hostname) > 29 else hostname
            out.append(f"{remote_ip:<15} {hn:<30} {port:<8} {proto:<6} {count:<11}")

        out.append("")
        out.append(f"Total unique remotes: {len(remote_stats)}")
        out.append(f"Total connections: {total}")
        out.append("")

        return "\n".join(out)

    def build_reports_per_local(
            self,
            stats: Dict[str, Dict[str, Dict[Tuple[str, str], int]]],
            direction: str,
    ) -> Dict[str, str]:
        reports: Dict[str, str] = {}
        for local_ip, remote_map in stats.items():
            reports[local_ip] = self._format_one(local_ip, remote_map, direction)
        return reports


def _build_ip_filter(field: str, target_ips: List[str]) -> str:
    """
    Собирает часть фильтра по IP:
      srcip = X OR srcip = Y ...
    При желании можно потом расширить до агрегирования CIDR.
    """
    if not target_ips:
        raise ValueError("Empty target_ips")

    if len(target_ips) == 1:
        return f"{field} = {target_ips[0]}"

    parts = [f"({field} = {ip})" for ip in target_ips]
    return " OR ".join(parts)


def analyze_logs(
        client,
        target_ips: List[str],
        direction: str,
        start_time: str,
        end_time: str,
        exclude_ips: Iterable[str] = None,
        batch_size: int = 100,
        dst_port: Optional[str] = None,
        proto: Optional[str] = None,
        extra_filter: Optional[str] = None,
) -> Dict[str, str]:
    """
    Высокоуровневая функция:
      1) строит фильтр (dstip/srcip = ... + доп. условия)
      2) создаёт задачу на FAZ
      3) ждёт завершения
      4) забирает логи
      5) агрегирует и формирует отчёты по local_ip

    Доп. параметры:
      - dst_port: '3389' или '3389,443'
      - proto: 'tcp'/'udp'/'icmp' или номер ('6','17','1')
      - extra_filter: произвольный кусок фильтра FAZ, который будет AND'иться.
    """
    if not target_ips:
        raise ValueError("Empty target_ips")

    # -------- Формирование фильтра для FAZ ----------

    field = "srcip" if direction == "outbound" else "dstip"
    clauses = []

    # IP-условие
    ip_clause = _build_ip_filter(field, target_ips)
    clauses.append(ip_clause)

    # Фильтр по порту (dstport)
    if dst_port:
        ports = [p.strip() for p in str(dst_port).split(",") if p.strip()]
        if ports:
            if len(ports) == 1:
                clauses.append(f"dstport = {ports[0]}")
            else:
                port_expr = " OR ".join(f"(dstport = {p})" for p in ports)
                clauses.append(port_expr)

    # Фильтр по протоколу
    if proto:
        p_val = normalize_proto_for_filter(proto)
        if p_val:
            clauses.append(f"proto = {p_val}")

    # Произвольный дополнительный фильтр (advanced)
    if extra_filter:
        clauses.append(extra_filter)

    # Собираем общий фильтр
    filter_str = " AND ".join(f"({c})" for c in clauses)

    print(f"🔍 Using filter: {filter_str}")
    print(f"🕒 Time range: {start_time} → {end_time}")

    # 1. Создаём задачу
    task_id = client.create_search_task(filter_str, start_time, end_time)
    if not task_id:
        raise RuntimeError("Failed to create search task")

    # 2. Ждём выполнения
    success, total_logs = client.wait_for_task_completion(task_id)
    if not success or total_logs == 0:
        print("⚠️ No matching logs found.")
        return {}

    # 3. Забираем логи
    logs = client.fetch_logs(task_id, total_logs, batch_size=batch_size)
    if not logs:
        print("⚠️ No logs retrieved.")
        return {}

    print(f"📊 Analyzing {len(logs)} log entries...")

    # 4. Агрегируем
    analyzer = LogAnalyzer(exclude_ips=exclude_ips)
    stats = analyzer.aggregate_by_local(logs, direction=direction, target_ips=target_ips)
    if not stats:
        print("⚠️ No stats produced after aggregation.")
        return {}

    # 5. Формируем отчёты по каждому local_ip
    return analyzer.build_reports_per_local(stats, direction=direction)
