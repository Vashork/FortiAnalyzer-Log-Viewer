"""
Time Range Analyzer — дробление сессий по времени.

Вместо дробления по IP (где каждый воркер = один IP),
каждый воркер получает свой временной диапазон и обрабатывает
ВСЕ target_ips в своём диапазоне.

Логика:
1. Разбиваем общий временной диапазон на сегменты (по max_task_hours)
2. Распределяем сегменты по воркерам (round-robin)
3. Каждый воркер обрабатывает свои сегменты
4. Результаты агрегируем по направлению
"""

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from client.faz_client import FortiAnalyzerClient
from analyzer.log_analyzer import (
    LogAnalyzer,
    build_faz_filter,
    build_policy_faz_filter,
    _filter_logs_by_smart_action,
)
from config import (
    SMART_ACTION,
    FILTER_MODE,
    MAX_TASK_HOURS,
    MAX_MATCHED_LOGS_PER_TASK,
)


def split_time_range_safe(start_time: str, end_time: str, max_hours: int) -> List[Tuple[str, str]]:
    """Режет временной интервал на сегменты по max_hours."""
    if not max_hours or max_hours <= 0:
        return [(start_time, end_time)]

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
        segments.append((cur.strftime(fmt), seg_end.strftime(fmt)))
        cur = seg_end

    return segments


def distribute_segments(segments: List[Tuple[str, str]], num_workers: int) -> List[List[Tuple[str, str]]]:
    """
    Распределяет временные сегменты по воркерам round-robin.
    Возвращает список списков — для каждого воркера свои сегменты.
    """
    workers_segments = [[] for _ in range(num_workers)]
    for i, seg in enumerate(segments):
        worker_idx = i % num_workers
        workers_segments[worker_idx].append(seg)
    return workers_segments


def fetch_logs_for_segments(
    client: FortiAnalyzerClient,
    filter_str: str,
    segments: List[Tuple[str, str]],
    batch_size: int,
    target_ips: List[str],
    progress=None,
    worker_label: str = "",
    cancel_check=None,  # callable() -> bool
) -> List[dict]:
    """
    Для данного воркера: обрабатывает все назначенные временные сегменты.
    Возвращает список всех найденных логов.
    """
    all_logs = []
    total_segments = len(segments)
    ips_str = ", ".join(target_ips[:5])
    if len(target_ips) > 5:
        ips_str += f" (+{len(target_ips) - 5} more)"

    for seg_idx, (seg_start, seg_end) in enumerate(segments, 1):
        # Проверяем отмену перед каждым сегментом
        if cancel_check and cancel_check():
            if progress:
                progress(f"  ⏹ Cancelled", ip=worker_label)
            return all_logs

        if progress:
            progress(f"[{seg_idx}/{total_segments}] ⏱ {seg_start} → {seg_end}", ip=worker_label)
            progress(f"  🔍 IPs: {ips_str}", ip=worker_label)

        if progress:
            progress(f"  📡 Creating FAZ search task...", ip=worker_label)

        tid = client.create_search_task(filter_str, seg_start, seg_end)
        if not tid:
            if progress:
                progress(f"  ⚠ Task creation failed or cancelled", ip=worker_label)
            continue

        if progress:
            progress(f"  ⏳ Waiting for FAZ (task: {tid})...", ip=worker_label)

        # wait_for_task_completion и fetch_logs теперь сами проверяют cancel_check
        ok, matched = client.wait_for_task_completion(tid)
        if cancel_check and cancel_check():
            if progress:
                progress(f"  ⏹ Cancelled", ip=worker_label)
            return all_logs
        if not ok or matched == 0:
            if progress:
                progress(f"  ⚠ No logs found in this segment", ip=worker_label)
            continue

        if MAX_MATCHED_LOGS_PER_TASK > 0 and matched > MAX_MATCHED_LOGS_PER_TASK:
            matched = MAX_MATCHED_LOGS_PER_TASK

        if progress:
            progress(f"  ✅ Found {matched} logs, fetching...", ip=worker_label)

        logs_segment = client.fetch_logs(tid, matched, batch_size)
        if logs_segment:
            all_logs.extend(logs_segment)
            if progress:
                progress(f"  📥 Fetched {len(logs_segment)} logs (total: {len(all_logs)})", ip=worker_label)
        else:
            if progress:
                progress(f"  ⚠ Failed to fetch logs or cancelled", ip=worker_label)

    return all_logs


def analyze_logs_time_split(
    main_client: FortiAnalyzerClient,
    target_ips: List[str],
    direction: str,
    start_time: str,
    end_time: str,
    exclude_ips: List[str],
    batch_size: int,
    ports: Optional[List[str]],
    columns: dict,
    num_workers: int,
    progress=None,
    cancel_check=None,  # callable() -> bool
) -> Dict[Tuple[str, str], str]:
    """
    Основной интерфейс для дробления по времени (direction mode).

    Логика:
    1. Режем время на сегменты
    2. Распределяем по воркерам
    3. Каждый воркер обрабатывает свои сегменты
    4. Агрегируем результаты
    """
    filter_str = build_faz_filter(direction, target_ips, ports, exclude_ips)

    if progress:
        ips_str = ", ".join(target_ips[:5])
        if len(target_ips) > 5:
            ips_str += f" (+{len(target_ips) - 5} more)"
        progress(f"📡 {direction}: {len(target_ips)} IPs, {start_time} → {end_time}")
        progress(f"  🔍 IPs: {ips_str}")
        progress(f"⏱ Time-split mode: {num_workers} workers")

    # 1. Режем время
    segments = split_time_range_safe(start_time, end_time, MAX_TASK_HOURS)
    if progress:
        seg_display = " | ".join([f"{s[0].split(' ')[1]}→{s[1].split(' ')[1]}" for s in segments])
        progress(f"  🕐 {len(segments)} segments: {seg_display}")

    # 2. Распределяем по воркерам
    workers_segments = distribute_segments(segments, num_workers)

    # 3. Каждый воркер обрабатывает свои сегменты
    all_logs_by_worker: Dict[int, List[dict]] = {}

    def worker_task(worker_id: int, segs: List[Tuple[str, str]]) -> Tuple[int, List[dict]]:
        label = f"W{worker_id}"
        total_time_ranges = " + ".join([f"{s[0].split(' ')[1]}→{s[1].split(' ')[1]}" for s in segs])
        if progress:
            progress(f"▶ {label}: {len(segs)} segments [{total_time_ranges}]", ip=label)
            progress(f"  🔍 Searching IPs: {ips_str}", ip=label)

        w_client = FortiAnalyzerClient(
            url=main_client.url, username=main_client.username, password=main_client.password,
            cancel_check=cancel_check,
        )
        if not w_client.login():
            if progress:
                progress(f"  ❌ {label}: FAZ login failed", ip=label)
            return worker_id, []

        try:
            logs = fetch_logs_for_segments(
                w_client, filter_str, segs, batch_size,
                target_ips=target_ips,
                progress=progress, worker_label=label,
                cancel_check=cancel_check,
            )
            total = len(logs)
            if progress:
                progress(f"  ✅ {label}: complete ({total} logs)", ip=label)
            return worker_id, logs
        finally:
            w_client.logout()

    futures_map = {}
    with ThreadPoolExecutor(max_workers=num_workers) as ex:
        for i, segs in enumerate(workers_segments):
            if segs:  # только если есть сегменты для этого воркера
                future = ex.submit(worker_task, i, segs)
                futures_map[future] = i

    for future in as_completed(futures_map):
        worker_id = futures_map[future]
        try:
            wid, logs = future.result()
            all_logs_by_worker[wid] = logs
        except Exception as e:
            if progress:
                progress(f"❌ Worker {worker_id} error: {e}")

    # 4. Агрегируем все логи
    all_logs = []
    for wid in sorted(all_logs_by_worker.keys()):
        all_logs.extend(all_logs_by_worker[wid])

    if progress:
        if all_logs:
            progress(f"✅ {direction}: {len(all_logs)} total logs from {len(all_logs_by_worker)} workers")
        else:
            progress(f"⚠ {direction}: no logs found")

    if not all_logs:
        return {}

    if FILTER_MODE == "local":
        all_logs = _filter_logs_by_smart_action(all_logs, SMART_ACTION)

    analyzer = LogAnalyzer(exclude_ips, columns=columns)
    stats = analyzer.aggregate_by_local(all_logs, direction, target_ips)
    return analyzer.build_reports_per_local(stats, direction, target_ips)


def analyze_policyid_logs_time_split(
    main_client: FortiAnalyzerClient,
    target_ips: List[str],
    policyid: int,
    start_time: str,
    end_time: str,
    exclude_ips: List[str],
    batch_size: int,
    ports: Optional[List[str]],
    columns: dict,
    num_workers: int,
    progress=None,
    cancel_check=None,  # callable() -> bool
) -> str:
    """
    Основной интерфейс для дробления по времени (policyid mode).
    """
    filter_str = build_policy_faz_filter(policyid, target_ips, ports)

    if progress:
        progress(f"🔎 PolicyID={policyid}: time-split, {num_workers} workers")

    segments = split_time_range_safe(start_time, end_time, MAX_TASK_HOURS)
    if progress:
        progress(f"⏱ Split into {len(segments)} time segments")

    workers_segments = distribute_segments(segments, num_workers)

    all_logs_by_worker: Dict[int, List[dict]] = {}

    def worker_task(worker_id: int, segs: List[Tuple[str, str]]) -> Tuple[int, List[dict]]:
        label = f"W{worker_id}[policy]"
        total_time_ranges = " | ".join([f"{s[0]} → {s[1]}" for s in segs])
        if progress:
            progress(f"▶ {label}: {len(segs)} segments")
            progress(f"  🕐 Ranges: {total_time_ranges}")

        w_client = FortiAnalyzerClient(
            url=main_client.url, username=main_client.username, password=main_client.password,
            cancel_check=cancel_check,
        )
        if not w_client.login():
            if progress:
                progress(f"  ❌ {label}: FAZ login failed")
            return worker_id, []

        try:
            logs = fetch_logs_for_segments(
                w_client, filter_str, segs, batch_size,
                target_ips=target_ips,
                progress=progress, worker_label=label,
                cancel_check=cancel_check,
            )
            if progress:
                progress(f"  ✅ {label}: complete ({len(logs)} logs total)")
            return worker_id, logs
        finally:
            w_client.logout()

    futures_map = {}
    with ThreadPoolExecutor(max_workers=num_workers) as ex:
        for i, segs in enumerate(workers_segments):
            if segs:
                future = ex.submit(worker_task, i, segs)
                futures_map[future] = i

    for future in as_completed(futures_map):
        worker_id = futures_map[future]
        try:
            wid, logs = future.result()
            all_logs_by_worker[wid] = logs
        except Exception as e:
            if progress:
                progress(f"❌ Worker {worker_id} error: {e}")

    all_logs = []
    for wid in sorted(all_logs_by_worker.keys()):
        all_logs.extend(all_logs_by_worker[wid])

    if not all_logs:
        return ""

    if FILTER_MODE == "local":
        all_logs = _filter_logs_by_smart_action(all_logs, SMART_ACTION)

    analyzer = LogAnalyzer(exclude_ips, columns=columns)
    stats = analyzer.aggregate_by_policyid(all_logs, target_ips)
    return analyzer.build_policyid_report(stats, policyid)
