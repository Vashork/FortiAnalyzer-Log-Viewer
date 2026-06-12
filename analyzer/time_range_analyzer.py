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
from typing import Dict, List, Optional, Tuple

from client.faz_client import FortiAnalyzerClient
from analyzer.log_analyzer import (
    LogAnalyzer,
    build_faz_filter,
    build_policy_faz_filter,
    _filter_logs_by_smart_action,
    _iter_fetch_log_batches,
    split_time_range_safe,
)
from config import (
    SMART_ACTION,
    FILTER_MODE,
    MAX_TASK_HOURS,
    MAX_MATCHED_LOGS_PER_TASK,
)


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


def fetch_local_stats_for_segments(
    client: FortiAnalyzerClient,
    filter_str: str,
    segments: List[Tuple[str, str]],
    batch_size: int,
    target_ips: List[str],
    direction: str,
    analyzer: LogAnalyzer,
    progress=None,
    worker_label: str = "",
    cancel_check=None,
    smart_action: Optional[str] = None,
    filter_mode: Optional[str] = None,
):
    """
    Fetch assigned time segments and aggregate direction-mode stats batch-wise.
    This avoids keeping all raw logs for the worker in memory.
    """
    effective_smart_action = SMART_ACTION if smart_action is None else smart_action
    effective_filter_mode = FILTER_MODE if filter_mode is None else filter_mode
    stats = None
    total_logs = 0
    total_segments = len(segments)
    ips_str = ", ".join(target_ips[:5])
    if len(target_ips) > 5:
        ips_str += f" (+{len(target_ips) - 5} more)"

    for seg_idx, (seg_start, seg_end) in enumerate(segments, 1):
        if cancel_check and cancel_check():
            if progress:
                progress("  ⏹ Cancelled", ip=worker_label)
            return stats, total_logs

        if progress:
            progress(f"[{seg_idx}/{total_segments}] ⏱ {seg_start} → {seg_end}", ip=worker_label)
            progress(f"  🔍 IPs: {ips_str}", ip=worker_label)
            progress("  📡 Creating FAZ search task...", ip=worker_label)

        tid = client.create_search_task(filter_str, seg_start, seg_end)
        if not tid:
            if progress:
                progress("  ⚠ Task creation failed or cancelled", ip=worker_label)
            continue

        if progress:
            progress(f"  ⏳ Waiting for FAZ (task: {tid})...", ip=worker_label)

        ok, matched = client.wait_for_task_completion(tid)
        if cancel_check and cancel_check():
            if progress:
                progress("  ⏹ Cancelled", ip=worker_label)
            return stats, total_logs
        if not ok or matched == 0:
            if progress:
                progress("  ⚠ No logs found in this segment", ip=worker_label)
            continue

        if MAX_MATCHED_LOGS_PER_TASK > 0 and matched > MAX_MATCHED_LOGS_PER_TASK:
            matched = MAX_MATCHED_LOGS_PER_TASK

        if progress:
            progress(f"  ✅ Found {matched} logs, fetching...", ip=worker_label)

        for logs_batch in _iter_fetch_log_batches(client, tid, matched, batch_size):
            if effective_filter_mode == "local":
                logs_batch = _filter_logs_by_smart_action(logs_batch, effective_smart_action)
            if not logs_batch:
                continue
            total_logs += len(logs_batch)
            stats = analyzer.aggregate_by_local(logs_batch, direction, target_ips, result=stats)
            if progress:
                progress(f"  📥 Aggregated {len(logs_batch)} logs (total: {total_logs})", ip=worker_label)

    return stats, total_logs


def _merge_local_stats(target, source) -> None:
    for local_ip, source_items in source.items():
        target_items = target[local_ip]
        for key, source_entry in source_items.items():
            target_entry = target_items[key]
            target_entry["count"] += source_entry.get("count", 0)
            for field, value in source_entry.items():
                if field == "count":
                    continue
                if isinstance(value, set):
                    target_entry.setdefault(field, set()).update(value)


def _run_worker_local_stats(
    main_client: FortiAnalyzerClient,
    filter_str: str,
    workers_segments: List[List[Tuple[str, str]]],
    target_ips: List[str],
    direction: str,
    exclude_ips: List[str],
    columns: dict,
    aggregation: Optional[dict],
    batch_size: int,
    num_workers: int,
    progress=None,
    cancel_check=None,
    worker_label_prefix: str = "W",
    smart_action: Optional[str] = None,
    filter_mode: Optional[str] = None,
):
    """
    Direction-mode worker pattern: each worker aggregates batches locally and
    returns stats instead of raw logs.
    """
    stats_by_worker = {}
    ips_str = ", ".join(target_ips[:5])
    if len(target_ips) > 5:
        ips_str += f" (+{len(target_ips) - 5} more)"

    def worker_task(worker_id: int, segs: List[Tuple[str, str]]):
        label = f"{worker_label_prefix}{worker_id}"
        total_time_ranges = " + ".join([f"{s[0].split(' ')[1]}→{s[1].split(' ')[1]}" for s in segs])
        if progress:
            progress(f"▶ {label}: {len(segs)} segments [{total_time_ranges}]", ip=label)
            progress(f"  🔍 Searching IPs: {ips_str}", ip=label)

        w_client = FortiAnalyzerClient(
            url=main_client.url, username=main_client.username, password=main_client.password,
            cancel_check=cancel_check,
            **main_client.transport_kwargs(),
        )
        if not w_client.login():
            if progress:
                progress(f"  ❌ {label}: FAZ login failed", ip=label)
            return worker_id, None, 0

        try:
            analyzer = LogAnalyzer(exclude_ips, columns=columns, aggregation=aggregation)
            stats, total_logs = fetch_local_stats_for_segments(
                w_client,
                filter_str,
                segs,
                batch_size,
                target_ips=target_ips,
                direction=direction,
                analyzer=analyzer,
                progress=progress,
                worker_label=label,
                cancel_check=cancel_check,
                smart_action=smart_action,
                filter_mode=filter_mode,
            )
            if progress:
                progress(f"  ✅ {label}: complete ({total_logs} logs)", ip=label)
            return worker_id, stats, total_logs
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
            wid, stats, total_logs = future.result()
            stats_by_worker[wid] = (stats, total_logs)
        except Exception as e:
            if progress:
                progress(f"❌ Worker {worker_id} error: {e}")

    return stats_by_worker


def _merge_policy_stats(target, source) -> None:
    for key, source_entry in source.items():
        target_entry = target[key]
        target_entry["count"] += source_entry.get("count", 0)
        for field, value in source_entry.items():
            if field == "count":
                continue
            if isinstance(value, set):
                target_entry.setdefault(field, set()).update(value)


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
    aggregation: Optional[dict] = None,
    progress=None,
    cancel_check=None,  # callable() -> bool
    smart_action: Optional[str] = None,
    filter_mode: Optional[str] = None,
) -> Dict[Tuple[str, str], str]:
    """
    Основной интерфейс для дробления по времени (direction mode).
    """
    effective_smart_action = SMART_ACTION if smart_action is None else smart_action
    effective_filter_mode = FILTER_MODE if filter_mode is None else filter_mode
    filter_str = build_faz_filter(direction, target_ips, ports, exclude_ips, smart_action=effective_smart_action, filter_mode=effective_filter_mode)

    if progress:
        ips_str = ", ".join(target_ips[:5])
        if len(target_ips) > 5:
            ips_str += f" (+{len(target_ips) - 5} more)"
        progress(f"📡 {direction}: {len(target_ips)} IPs, {start_time} → {end_time}")
        progress(f"  🔍 IPs: {ips_str}")
        progress(f"⏱ Time-split mode: {num_workers} workers")

    segments = split_time_range_safe(start_time, end_time, MAX_TASK_HOURS)
    if progress:
        seg_display = " | ".join([f"{s[0].split(' ')[1]}→{s[1].split(' ')[1]}" for s in segments])
        progress(f"  🕐 {len(segments)} segments: {seg_display}")

    workers_segments = distribute_segments(segments, num_workers)

    stats_by_worker = _run_worker_local_stats(
        main_client=main_client,
        filter_str=filter_str,
        workers_segments=workers_segments,
        target_ips=target_ips,
        direction=direction,
        exclude_ips=exclude_ips,
        columns=columns,
        aggregation=aggregation,
        batch_size=batch_size,
        num_workers=num_workers,
        progress=progress,
        cancel_check=cancel_check,
        smart_action=effective_smart_action,
        filter_mode=effective_filter_mode,
        worker_label_prefix="W",
    )

    analyzer = LogAnalyzer(exclude_ips, columns=columns, aggregation=aggregation)
    merged_stats = analyzer._new_local_stats()
    total = 0
    for wid in sorted(stats_by_worker.keys()):
        worker_stats, worker_total = stats_by_worker[wid]
        if worker_stats:
            _merge_local_stats(merged_stats, worker_stats)
        total += worker_total

    if progress:
        if total:
            progress(f"✅ {direction}: {total} total logs from {len(stats_by_worker)} workers")
        else:
            progress(f"⚠ {direction}: no logs found")

    if not total:
        return {}

    return analyzer.build_reports_per_local(merged_stats, direction, target_ips)


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
    aggregation: Optional[dict] = None,
    progress=None,
    cancel_check=None,  # callable() -> bool
    smart_action: Optional[str] = None,
    filter_mode: Optional[str] = None,
) -> str:
    """
    Основной интерфейс для дробления по времени (policyid mode).
    """
    effective_smart_action = SMART_ACTION if smart_action is None else smart_action
    effective_filter_mode = FILTER_MODE if filter_mode is None else filter_mode
    filter_str = build_policy_faz_filter(policyid, target_ips, ports, smart_action=effective_smart_action, filter_mode=effective_filter_mode)

    if progress:
        progress(f"🔎 PolicyID={policyid}: time-split, {num_workers} workers")

    segments = split_time_range_safe(start_time, end_time, MAX_TASK_HOURS)
    if progress:
        progress(f"⏱ Split into {len(segments)} time segments")

    workers_segments = distribute_segments(segments, num_workers)

    def worker_task(worker_id: int, segs: List[Tuple[str, str]]):
        label = f"W{worker_id}"
        total_time_ranges = " | ".join([f"{s[0]} → {s[1]}" for s in segs])
        if progress:
            progress(f"▶ {label}[policy]: {len(segs)} segments")
            progress(f"  🕐 Ranges: {total_time_ranges}")

        w_client = FortiAnalyzerClient(
            url=main_client.url, username=main_client.username, password=main_client.password,
            cancel_check=cancel_check,
            **main_client.transport_kwargs(),
        )
        if not w_client.login():
            if progress:
                progress(f"  ❌ {label}: FAZ login failed")
            return worker_id, None, 0

        try:
            analyzer = LogAnalyzer(exclude_ips, columns=columns, aggregation=aggregation)
            stats = None
            total_logs = 0

            for seg_idx, (seg_start, seg_end) in enumerate(segs, 1):
                if cancel_check and cancel_check():
                    if progress:
                        progress(f"  ⏹ Cancelled", ip=label)
                    return worker_id, stats, total_logs

                if progress:
                    progress(f"[{seg_idx}/{len(segs)}] ⏱ {seg_start} → {seg_end}", ip=label)

                tid = w_client.create_search_task(filter_str, seg_start, seg_end)
                if not tid:
                    continue

                ok, matched = w_client.wait_for_task_completion(tid)
                if not ok or matched == 0:
                    continue

                if MAX_MATCHED_LOGS_PER_TASK > 0 and matched > MAX_MATCHED_LOGS_PER_TASK:
                    matched = MAX_MATCHED_LOGS_PER_TASK

                for logs_batch in _iter_fetch_log_batches(w_client, tid, matched, batch_size):
                    if effective_filter_mode == "local":
                        logs_batch = _filter_logs_by_smart_action(logs_batch, effective_smart_action)
                    if not logs_batch:
                        continue
                    total_logs += len(logs_batch)
                    stats = analyzer.aggregate_by_policyid(logs_batch, target_ips, result=stats)

            if progress:
                progress(f"  ✅ {label}[policy]: complete ({total_logs} logs total)")
            return worker_id, stats, total_logs
        finally:
            w_client.logout()

    analyzer = LogAnalyzer(exclude_ips, columns=columns, aggregation=aggregation)
    merged_stats = analyzer._new_policyid_stats()
    total_logs = 0
    futures_map = {}
    with ThreadPoolExecutor(max_workers=num_workers) as ex:
        for i, segs in enumerate(workers_segments):
            if segs:
                future = ex.submit(worker_task, i, segs)
                futures_map[future] = i

    for future in as_completed(futures_map):
        worker_id = futures_map[future]
        try:
            _, stats, worker_logs = future.result()
            if stats:
                _merge_policy_stats(merged_stats, stats)
            total_logs += worker_logs
        except Exception as e:
            if progress:
                progress(f"❌ Worker {worker_id} error: {e}")

    if not total_logs:
        return ""

    return analyzer.build_policyid_report(merged_stats, policyid)
