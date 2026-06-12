import csv
import io
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from queue import Empty, Queue
from threading import Lock
from typing import Callable, Optional

from analyzer.log_analyzer import analyze_logs, analyze_policyid_logs, split_time_range_safe
from analyzer.time_range_analyzer import analyze_policyid_logs_time_split
from client.faz_client import FortiAnalyzerClient
from config import (
    COLUMNS_CONFIG,
    EMPTY_BATCH_LIMIT,
    INTERNAL_IPS_FILE,
    MACHINES_FILE,
    get_dynamic_batch_size,
    get_dynamic_max_task_hours,
    get_dynamic_workers,
    get_results_dir_path,
    get_dynamic_split_mode,
    reload_env,
)
from utils.network import load_machines
from utils.output import save_results


EventCallback = Callable[[dict], None]
CancelCheck = Callable[[], bool]


class AnalysisCancelled(Exception):
    pass


@dataclass(frozen=True)
class WorkerRef:
    worker_id: str
    label: str
    slot_key: str
    direction: str
    target_ip: Optional[str] = None
    policy_id: Optional[int] = None

    def payload(self) -> dict:
        payload = {
            "worker_id": self.worker_id,
            "label": self.label,
            "slot_key": self.slot_key,
            "direction": self.direction,
        }
        if self.target_ip:
            payload["target_ip"] = self.target_ip
        if self.policy_id is not None:
            payload["policy_id"] = self.policy_id
        return payload


class SchedulerEmitter:
    def __init__(self, emit: EventCallback):
        self._emit = emit

    def event(self, event_type: str, **payload):
        self._emit({"type": event_type, **payload})

    def job_started(self, **payload):
        self.event("job_started", **payload)

    def worker_started(self, worker: WorkerRef, message: Optional[str] = None):
        payload = worker.payload()
        if message:
            payload["message"] = message
        self.event("worker_started", **payload)

    def worker_finished(self, worker: WorkerRef, message: Optional[str] = None):
        payload = worker.payload()
        if message:
            payload["message"] = message
        self.event("worker_finished", **payload)

    def message(self, message: str, worker: Optional[WorkerRef] = None, stage: Optional[str] = None):
        payload = {"message": message}
        if stage:
            payload["stage"] = stage
        if worker:
            payload.update(worker.payload())
        self.event("message", **payload)

    def segment_started(self, worker: WorkerRef, segment_start: str, segment_end: str, message: str):
        payload = worker.payload()
        payload.update({
            "segment_start": segment_start,
            "segment_end": segment_end,
            "message": message,
        })
        self.event("segment_started", **payload)

    def fetch_progress(self, worker: WorkerRef, fetched: int, total: int, pct: int):
        payload = worker.payload()
        payload.update({
            "fetched": fetched,
            "total": total,
            "pct": pct,
            "message": f"Fetched {fetched}/{total} logs ({pct}%)",
        })
        self.event("fetch_progress", **payload)

    def aggregation_started(self, worker: WorkerRef, logs_count: int, message: str):
        payload = worker.payload()
        payload.update({"logs_count": logs_count, "message": message})
        self.event("aggregation_started", **payload)

    def report_started(self, worker: WorkerRef, message: str):
        payload = worker.payload()
        payload["message"] = message
        self.event("report_started", **payload)

    def logout_started(self, worker: WorkerRef, message: str = "Logging out from FAZ"):
        payload = worker.payload()
        payload["message"] = message
        self.event("logout_started", **payload)

    def logout_finished(self, worker: WorkerRef, message: str = "Logged out from FAZ"):
        payload = worker.payload()
        payload["message"] = message
        self.event("logout_finished", **payload)


def _normalize_exact_datetime(value: Optional[str]) -> Optional[str]:
    if not value:
        return value
    value = value.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"):
        try:
            dt = datetime.strptime(value, fmt)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return value


def _load_internal_ips() -> set[str]:
    internal_file = Path(INTERNAL_IPS_FILE)
    if internal_file.exists():
        return set(load_machines(str(internal_file)))
    return set()


def _expand_targets(targets) -> list[str]:
    import ipaddress

    ips = []
    for target in targets:
        try:
            if "/" in target.ip:
                network = ipaddress.IPv4Network(target.ip, strict=False)
                ips.extend([str(ip) for ip in network])
            elif target.mask and target.mask != "/32":
                network = ipaddress.IPv4Network(f"{target.ip}{target.mask}", strict=False)
                ips.extend([str(ip) for ip in network])
            else:
                ipaddress.IPv4Address(target.ip)
                ips.append(target.ip)
        except Exception:
            continue
    return ips


def _text_to_csv(text: str) -> str:
    if not text or text.strip() == "NO DATA":
        return "NO DATA"

    lines = text.strip().split("\n")
    csv_output = io.StringIO()
    writer = csv.writer(csv_output)
    header_written = False

    for line in lines:
        if line.startswith("=") or line.startswith("-") or not line.strip():
            continue
        if line.startswith("Total "):
            writer.writerow([line.strip()])
            continue

        parts = [p.strip() for p in line.split("  ") if p.strip()]
        if not parts:
            continue

        if not header_written:
            writer.writerow(parts)
            header_written = True
        else:
            writer.writerow(parts)

    return csv_output.getvalue()


def _append_history_simple(text: str, start_time: str, end_time: str, cmd: str, filename: str, state_json: str = None):
    history_path = get_results_dir_path() / "history.txt"
    history_path.parent.mkdir(parents=True, exist_ok=True)

    header = (
        f"\n=== {datetime.now():%Y-%m-%d %H:%M:%S} ===\n"
        f"CMD: {cmd}\n"
        f"TIME: {start_time} -> {end_time}\n"
        f"SMART_ACTION={os.getenv('SMART_ACTION', 'all')} | FILTER_MODE={os.getenv('FILTER_MODE', 'faz')}\n"
        f"FILE: {filename}\n"
    )
    if state_json:
        header += f"STATE_JSON: {state_json}\n"
    header += f"{'-' * 60}\n"

    with open(history_path, "a", encoding="utf-8") as f:
        f.write(header)
        f.write(text.rstrip() + "\n")


def _save_result(text, emitter: SchedulerEmitter, results_dir, name_prefix, start_time, end_time, cmd_label,
                 output_format, worker: Optional[WorkerRef] = None, state_json: Optional[str] = None):
    files = []
    result_data = {}

    txt_file = results_dir / f"{name_prefix}.txt"
    save_results(text, txt_file)
    _append_history_simple(text, start_time, end_time, cmd_label, txt_file.name, state_json=state_json)
    files.append({"name": txt_file.name, "path": txt_file.name})
    result_data[f"{name_prefix}.txt"] = text

    if output_format in ("csv", "both"):
        csv_text = _text_to_csv(text)
        csv_file = results_dir / f"{name_prefix}.csv"
        csv_file.write_text(csv_text, encoding="utf-8")
        files.append({"name": csv_file.name, "path": csv_file.name})
        result_data[f"{name_prefix}.csv"] = csv_text

    emitter.message(f"Saved result: {name_prefix}.{output_format}", worker=worker, stage="save")
    return files, result_data


def _build_state_json(request, policy_id: Optional[int] = None) -> str:
    return json.dumps({
        "time_mode": request.time_mode,
        "time_value": request.time_value,
        "start_time": request.start_time,
        "end_time": request.end_time,
        "analysis_mode": request.analysis_mode,
        "direction": request.direction,
        "policyid": policy_id if policy_id is not None else request.policyid,
        "policyids": request.policyids,
        "output_format": request.output_format,
        "smart_action": request.smart_action,
        "use_machines_file": request.use_machines_file,
        "targets": [t.model_dump() for t in request.targets],
        "exclude_internal": request.exclude_internal,
        "proto_enabled": request.proto_enabled,
        "ports": request.ports,
        "columns": request.columns,
        "aggregation": request.aggregation,
    }, ensure_ascii=False)


def _make_progress_callback(emitter: SchedulerEmitter, worker: WorkerRef):
    segment_re = re.compile(r"^\S+\s+[^:]+:\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+→\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})$")
    aggreg_re = re.compile(r"aggregating\s+(\d+)\s+logs", re.IGNORECASE)

    def progress(message: str, ip: str = None):
        match = segment_re.match(message.strip())
        if match:
            emitter.segment_started(worker, match.group(1), match.group(2), message)
            return

        aggreg_match = aggreg_re.search(message)
        if aggreg_match:
            emitter.aggregation_started(worker, int(aggreg_match.group(1)), message)
            return

        if "building report" in message.lower():
            emitter.report_started(worker, message)
            return

        emitter.message(message, worker=worker)

    return progress


def _patch_faz_client_for_events(client: FortiAnalyzerClient, emitter: SchedulerEmitter, worker: WorkerRef,
                                 cancel_check: CancelCheck):
    original_create = client.create_search_task
    original_fetch = client.fetch_logs

    def _drop_active_task(task_id):
        if task_id in client._active_tasks:
            client._active_tasks.remove(task_id)

    def patched_create(filter_str, start, end):
        if cancel_check and cancel_check():
            return None
        result = original_create(filter_str, start, end)
        if result:
            emitter.message(f"Created search task: {result}", worker=worker, stage="search")
        return result

    def patched_wait(task_id, max_wait=300):
        start_ts = time.time()
        last_progress = -1
        last_poll_ts = 0
        poll_interval = 1

        emitter.message("Waiting for FAZ to process search task...", worker=worker, stage="wait")

        while time.time() - start_ts < max_wait:
            if cancel_check and cancel_check():
                emitter.message("Cancelled by user", worker=worker, stage="cancel")
                client.cancel_search_task(task_id)
                _drop_active_task(task_id)
                return False, 0

            now = time.time()
            if now - last_poll_ts < poll_interval:
                time.sleep(0.3)
                continue
            last_poll_ts = now

            payload = {
                "id": "123456789",
                "jsonrpc": "2.0",
                "method": "get",
                "params": [{"apiver": 3, "url": f"/logview/adom/root/logsearch/count/{task_id}"}],
                "session": client.session,
            }
            try:
                result = client._post(payload)
                raw = client._normalize_result(result)
                status_code = raw.get("status", {}).get("code", -1)
                matched = raw.get("matched-logs", 0)
                progress_value = raw.get("progress-percent", 0)

                if progress_value != last_progress:
                    emitter.message(f"Progress: {progress_value}% (matched: {matched})", worker=worker, stage="wait")
                    last_progress = progress_value

                if status_code == 0 and progress_value == 100:
                    _drop_active_task(task_id)
                    emitter.message(f"Task completed. Found {matched} logs", worker=worker, stage="wait")
                    return True, matched

                if status_code in (0, 1):
                    continue

                emitter.message(f"Task failed with status code: {status_code}", worker=worker, stage="error")
                _drop_active_task(task_id)
                return False, 0
            except Exception as exc:
                emitter.message(f"Status check error, retrying: {exc}", worker=worker, stage="warn")
                time.sleep(3)

        emitter.message("Task did not complete within allowed time", worker=worker, stage="warn")
        _drop_active_task(task_id)
        return False, 0

    def patched_iter_fetch(task_id, total, batch=100):
        offset = 0
        incomplete_retry_limit = 3

        while offset < total:
            if cancel_check and cancel_check():
                emitter.message(f"Cancelled (fetched {offset}/{total})", worker=worker, stage="cancel")
                client.cancel_search_task(task_id)
                _drop_active_task(task_id)
                return

            payload = {
                "id": "123456789",
                "jsonrpc": "2.0",
                "method": "get",
                "params": [{"apiver": 3, "limit": batch, "offset": offset, "url": f"/logview/adom/root/logsearch/{task_id}"}],
                "session": client.session,
            }

            empty_retry = 0
            incomplete_retry = 0
            while True:
                if cancel_check and cancel_check():
                    emitter.message(f"Cancelled (fetched {offset}/{total})", worker=worker, stage="cancel")
                    client.cancel_search_task(task_id)
                    _drop_active_task(task_id)
                    return

                try:
                    resp = client._post(payload)
                    data = client._normalize_result(resp).get("data", [])
                except Exception as exc:
                    empty_retry += 1
                    if empty_retry <= EMPTY_BATCH_LIMIT:
                        emitter.message(
                            f"Fetch error at offset {offset}, retry {empty_retry}/{EMPTY_BATCH_LIMIT}: {exc}",
                            worker=worker,
                            stage="warn",
                        )
                        time.sleep(3)
                        continue
                    emitter.message(f"Fetch aborted at offset {offset}: {exc}", worker=worker, stage="error")
                    _drop_active_task(task_id)
                    return

                if not data:
                    empty_retry += 1
                    if empty_retry <= EMPTY_BATCH_LIMIT:
                        emitter.message(
                            f"Empty batch at offset {offset}, retry {empty_retry}/{EMPTY_BATCH_LIMIT}",
                            worker=worker,
                            stage="warn",
                        )
                        time.sleep(3)
                        continue
                    emitter.message(f"No data at offset {offset} after retries", worker=worker, stage="warn")
                    _drop_active_task(task_id)
                    return

                if len(data) < batch and (total - offset) > len(data):
                    incomplete_retry += 1
                    if incomplete_retry <= incomplete_retry_limit:
                        emitter.message(
                            f"Incomplete batch at offset {offset}: got {len(data)}, retry {incomplete_retry}/{incomplete_retry_limit}",
                            worker=worker,
                            stage="warn",
                        )
                        time.sleep(3)
                        continue

                offset += len(data)
                pct = int(offset / total * 100) if total else 100
                emitter.fetch_progress(worker, offset, total, pct)
                yield data
                break

        _drop_active_task(task_id)

    def patched_fetch(task_id, total, batch=100):
        all_logs = []
        for logs_batch in patched_iter_fetch(task_id, total, batch):
            all_logs.extend(logs_batch)
        return all_logs

    client.create_search_task = patched_create
    client.wait_for_task_completion = patched_wait
    client.iter_fetch_logs = patched_iter_fetch
    client.fetch_logs = patched_fetch


def _run_faz_search(worker: WorkerRef, emitter: SchedulerEmitter, cancel_check: CancelCheck, *,
                    target_ips, exclude_ips, start_time, end_time, batch_size, ports,
                    direction=None, policyid=None, columns=None, aggregation=None):
    client = FortiAnalyzerClient.from_env(cancel_check=cancel_check)
    if not client.login():
        return None

    progress = _make_progress_callback(emitter, worker)
    try:
        _patch_faz_client_for_events(client, emitter, worker, cancel_check)
        if policyid is not None:
            return analyze_policyid_logs(
                client=client,
                target_ips=target_ips,
                policyid=policyid,
                start_time=start_time,
                end_time=end_time,
                exclude_ips=exclude_ips,
                batch_size=batch_size,
                ports=ports,
                columns=columns,
                aggregation=aggregation,
                progress=progress,
            )
        return analyze_logs(
            client=client,
            target_ips=target_ips,
            direction=direction,
            start_time=start_time,
            end_time=end_time,
            exclude_ips=exclude_ips,
            batch_size=batch_size,
            ports=ports,
            columns=columns,
            aggregation=aggregation,
            progress=progress,
        )
    finally:
        emitter.logout_started(worker)
        client.logout()
        emitter.logout_finished(worker)


def _collect_request_context(request):
    reload_env()

    if request.time_mode == "exact" and request.start_time and request.end_time:
        start_time = _normalize_exact_datetime(request.start_time)
        end_time = _normalize_exact_datetime(request.end_time)
    else:
        hours = request.time_value * 24 if request.time_mode == "days" else request.time_value
        end_dt = datetime.now()
        start_dt = end_dt - timedelta(hours=hours)
        start_time = start_dt.strftime("%Y-%m-%d %H:%M:%S")
        end_time = end_dt.strftime("%Y-%m-%d %H:%M:%S")

    target_ips = []
    if request.use_machines_file:
        machines_path = Path(MACHINES_FILE)
        if machines_path.exists():
            target_ips = load_machines(str(machines_path))
        else:
            raise ValueError("machines.txt not found in resources/")
    else:
        target_ips = _expand_targets(request.targets) if request.targets else []

    exclude_ips = _load_internal_ips() if request.exclude_internal else set()
    target_ips = [ip for ip in target_ips if ip not in exclude_ips]
    ports = [p.strip() for p in request.ports.split(",") if p.strip()] if request.proto_enabled else None

    if request.columns:
        import config
        for key, value in request.columns.items():
            if key in config.COLUMNS_CONFIG:
                config.COLUMNS_CONFIG[key] = value

    import config
    config.SMART_ACTION = request.smart_action.lower()

    return start_time, end_time, target_ips, exclude_ips, ports


def _run_policyid(request, emitter: SchedulerEmitter, cancel_check: CancelCheck,
                  start_time: str, end_time: str, target_ips: list[str], exclude_ips: set[str], ports):
    policy_ids = request.policyids or ([request.policyid] if request.policyid is not None else [])
    if not policy_ids:
        raise ValueError("No policy IDs provided")

    split_mode = get_dynamic_split_mode()
    workers = request.workers or get_dynamic_workers()
    results_dir = get_results_dir_path()
    results_dir.mkdir(parents=True, exist_ok=True)

    all_files = []
    all_texts = {}
    policy_texts = {}

    if split_mode == "time" and workers > 1:
        for policy_id in policy_ids:
            if cancel_check():
                raise AnalysisCancelled("Analysis cancelled by user")

            emitter.message(f"PolicyID mode: policyid={policy_id} (time-split, {workers} workers)", stage="job")
            for w_id in range(workers):
                worker = WorkerRef(worker_id=f"W{w_id}", label=f"W{w_id}", slot_key=f"W{w_id}", direction="policy")
                emitter.worker_started(worker, message=f"Time-split worker for policyid={policy_id}")

            main_client = FortiAnalyzerClient.from_env()
            text = analyze_policyid_logs_time_split(
                main_client=main_client,
                target_ips=target_ips,
                policyid=policy_id,
                start_time=start_time,
                end_time=end_time,
                exclude_ips=list(exclude_ips),
                batch_size=get_dynamic_batch_size(),
                ports=ports,
                columns=request.columns,
                num_workers=workers,
                aggregation=request.aggregation,
                progress=lambda message, ip=None: emitter.message(
                    message,
                    worker=WorkerRef(worker_id=ip or "policy", label=ip or "policy", slot_key=ip or "policy", direction="policy"),
                ),
                cancel_check=cancel_check,
            )

            for w_id in range(workers):
                worker = WorkerRef(worker_id=f"W{w_id}", label=f"W{w_id}", slot_key=f"W{w_id}", direction="policy")
                emitter.worker_finished(worker, message=f"Finished policyid={policy_id}")

            policy_texts[policy_id] = text
    elif workers > 1 and len(policy_ids) > 1:
        emitter.message(f"Parallel policy mode: {workers} workers, {len(policy_ids)} policy IDs", stage="job")

        def process_policy(policy_id):
            worker = WorkerRef(
                worker_id=f"P{policy_id}",
                label=f"P{policy_id}",
                slot_key=f"P{policy_id}",
                direction="policy",
                policy_id=policy_id,
            )
            emitter.worker_started(worker, message=f"Starting policyid={policy_id}")
            try:
                text = _run_faz_search(
                    worker,
                    emitter,
                    cancel_check,
                    target_ips=target_ips,
                    exclude_ips=list(exclude_ips),
                    start_time=start_time,
                    end_time=end_time,
                    batch_size=get_dynamic_batch_size(),
                    ports=ports,
                    policyid=policy_id,
                    columns=request.columns,
                    aggregation=request.aggregation,
                )
                if text is None:
                    raise RuntimeError("FAZ login failed")
                return policy_id, text
            finally:
                emitter.worker_finished(worker, message=f"Finished policyid={policy_id}")

        futures_map = {}
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for policy_id in policy_ids:
                future = ex.submit(process_policy, policy_id)
                futures_map[future] = policy_id

            for future in as_completed(futures_map):
                policy_id = futures_map[future]
                policy_texts[policy_id] = future.result()[1]
    else:
        for policy_id in policy_ids:
            if cancel_check():
                raise AnalysisCancelled("Analysis cancelled by user")

            worker = WorkerRef(
                worker_id=f"P{policy_id}",
                label=f"P{policy_id}",
                slot_key=f"P{policy_id}",
                direction="policy",
                policy_id=policy_id,
            )
            emitter.worker_started(worker, message=f"PolicyID mode: policyid={policy_id}")
            try:
                text = _run_faz_search(
                    worker,
                    emitter,
                    cancel_check,
                    target_ips=target_ips,
                    exclude_ips=list(exclude_ips),
                    start_time=start_time,
                    end_time=end_time,
                    batch_size=get_dynamic_batch_size(),
                    ports=ports,
                    policyid=policy_id,
                    columns=request.columns,
                    aggregation=request.aggregation,
                )
                if text is None:
                    raise RuntimeError("FAZ login failed")
                policy_texts[policy_id] = text
            finally:
                emitter.worker_finished(worker, message=f"Finished policyid={policy_id}")

    for policy_id in policy_ids:
        text = str(policy_texts.get(policy_id) or "").strip() or "NO DATA"
        text = f"{text}\n" if text == "NO DATA" else str(policy_texts.get(policy_id) or "")
        files, texts = _save_result(
            text,
            emitter,
            results_dir,
            f"policy_{policy_id}",
            start_time,
            end_time,
            f"policyid={policy_id}",
            request.output_format,
            worker=WorkerRef(
                worker_id=f"P{policy_id}",
                label=f"P{policy_id}",
                slot_key=f"P{policy_id}",
                direction="policy",
                policy_id=policy_id,
            ),
            state_json=_build_state_json(request, policy_id=policy_id),
        )
        all_files.extend(files)
        all_texts.update(texts)

    return {"files": all_files, "texts": all_texts}


def _run_direction_time_split_by_ip(request, emitter: SchedulerEmitter, cancel_check: CancelCheck,
                                    start_time: str, end_time: str, target_ips: list[str], exclude_ips: set[str], ports):
    directions = ["inbound", "outbound"] if request.direction == "all" else [request.direction]
    workers = min(request.workers or get_dynamic_workers(), max(1, len(target_ips)))
    results_dir = get_results_dir_path()
    results_dir.mkdir(parents=True, exist_ok=True)

    direction_text = {direction: [] for direction in directions}
    per_ip_results = {}
    collect_lock = Lock()
    queue = Queue()
    for ip in target_ips:
        queue.put(ip)

    emitter.message(
        f"Time-split mode: {workers} workers, {len(target_ips)} IPs. Each worker completes a whole IP before taking the next one.",
        stage="job",
    )

    def worker_loop(worker_index: int):
        worker = WorkerRef(worker_id=f"W{worker_index}", label=f"W{worker_index}", slot_key=f"W{worker_index}", direction="time-split")
        emitter.worker_started(worker, message="Worker ready")
        try:
            while not cancel_check():
                try:
                    ip = queue.get_nowait()
                except Empty:
                    break

                emitter.message(f"Assigned IP {ip}", worker=worker, stage="assignment")
                for direction in directions:
                    if cancel_check():
                        break
                    task_worker = WorkerRef(
                        worker_id=worker.worker_id,
                        label=worker.label,
                        slot_key=worker.slot_key,
                        direction=direction,
                        target_ip=ip,
                    )
                    emitter.message(f"Starting {ip} [{direction}]", worker=task_worker, stage="assignment")
                    report_dict = _run_faz_search(
                        task_worker,
                        emitter,
                        cancel_check,
                        target_ips=[ip],
                        exclude_ips=list(exclude_ips),
                        start_time=start_time,
                        end_time=end_time,
                        batch_size=get_dynamic_batch_size(),
                        ports=ports,
                        direction=direction,
                        columns=request.columns,
                        aggregation=request.aggregation,
                    ) or {}

                    with collect_lock:
                        for (_, dir_key), text in report_dict.items():
                            if text.strip():
                                direction_text[dir_key].append(text)
                                per_ip_results.setdefault(ip, {})[dir_key] = text
                queue.task_done()
        finally:
            emitter.worker_finished(worker, message="Worker finished")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(worker_loop, index) for index in range(workers)]
        for future in as_completed(futures):
            future.result()

    all_files = []
    all_texts = {}
    state_json_str = _build_state_json(request)
    for direction in directions:
        final_text = "\n\n".join(direction_text[direction]) if direction_text[direction] else "NO DATA\n"
        files, texts = _save_result(
            final_text,
            emitter,
            results_dir,
            direction,
            start_time,
            end_time,
            f"direction={direction}",
            request.output_format,
            state_json=state_json_str,
        )
        all_files.extend(files)
        all_texts.update(texts)

    if per_ip_results and all(len(value) > 0 for value in per_ip_results.values()):
        all_texts["per_ip"] = per_ip_results

    return {"files": all_files, "texts": all_texts}


def _run_direction(request, emitter: SchedulerEmitter, cancel_check: CancelCheck,
                   start_time: str, end_time: str, target_ips: list[str], exclude_ips: set[str], ports):
    if not target_ips:
        raise ValueError("No target IPs after expansion and exclusion")

    split_mode = get_dynamic_split_mode()
    workers = request.workers or get_dynamic_workers()
    time_segments = split_time_range_safe(start_time, end_time, get_dynamic_max_task_hours())
    if split_mode == "time" and workers > 1 and len(time_segments) > 1:
        return _run_direction_time_split_by_ip(
            request,
            emitter,
            cancel_check,
            start_time,
            end_time,
            target_ips,
            exclude_ips,
            ports,
        )

    directions = ["inbound", "outbound"] if request.direction == "all" else [request.direction]
    results_dir = get_results_dir_path()
    results_dir.mkdir(parents=True, exist_ok=True)
    direction_text = {direction: [] for direction in directions}
    per_ip_results = {}
    state_json_str = _build_state_json(request)

    if workers > 1 and len(target_ips) > 1:
        collect_lock = Lock()
        emitter.message(f"Parallel mode: {workers} workers, {len(target_ips)} IPs", stage="job")

        def process_ip(ip, direction):
            worker = WorkerRef(worker_id=f"{ip}:{direction}", label=ip, slot_key=ip, direction=direction, target_ip=ip)
            emitter.worker_started(worker, message=f"Starting {ip} [{direction}]")
            try:
                report_dict = _run_faz_search(
                    worker,
                    emitter,
                    cancel_check,
                    target_ips=[ip],
                    exclude_ips=list(exclude_ips),
                    start_time=start_time,
                    end_time=end_time,
                    batch_size=get_dynamic_batch_size(),
                    ports=ports,
                    direction=direction,
                    columns=request.columns,
                    aggregation=request.aggregation,
                ) or {}
                with collect_lock:
                    for (_, dir_key), text in report_dict.items():
                        if text.strip():
                            direction_text[dir_key].append(text)
                            per_ip_results.setdefault(ip, {})[dir_key] = text
            finally:
                emitter.worker_finished(worker, message=f"Finished {ip} [{direction}]")

        futures_map = {}
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for direction in directions:
                for ip in target_ips:
                    future = ex.submit(process_ip, ip, direction)
                    futures_map[future] = (ip, direction)
            for future in as_completed(futures_map):
                future.result()
    else:
        for direction in directions:
            emitter.message(f"Direction: {direction}", stage="job")
            for ip in target_ips:
                if cancel_check():
                    raise AnalysisCancelled("Analysis cancelled by user")
                worker = WorkerRef(worker_id=f"{ip}:{direction}", label=ip, slot_key=ip, direction=direction, target_ip=ip)
                emitter.worker_started(worker, message=f"Starting {ip} [{direction}]")
                try:
                    report_dict = _run_faz_search(
                        worker,
                        emitter,
                        cancel_check,
                        target_ips=[ip],
                        exclude_ips=list(exclude_ips),
                        start_time=start_time,
                        end_time=end_time,
                        batch_size=get_dynamic_batch_size(),
                        ports=ports,
                        direction=direction,
                        columns=request.columns,
                        aggregation=request.aggregation,
                    ) or {}
                    for (_, dir_key), text in report_dict.items():
                        if text.strip():
                            direction_text[dir_key].append(text)
                            per_ip_results.setdefault(ip, {})[dir_key] = text
                finally:
                    emitter.worker_finished(worker, message=f"Finished {ip} [{direction}]")

    all_files = []
    all_texts = {}
    for direction in directions:
        final_text = "\n\n".join(direction_text[direction]) if direction_text[direction] else "NO DATA\n"
        files, texts = _save_result(
            final_text,
            emitter,
            results_dir,
            direction,
            start_time,
            end_time,
            f"direction={direction}",
            request.output_format,
            state_json=state_json_str,
        )
        all_files.extend(files)
        all_texts.update(texts)

    if per_ip_results and all(len(value) > 0 for value in per_ip_results.values()):
        all_texts["per_ip"] = per_ip_results

    return {"files": all_files, "texts": all_texts}


def run_analysis_request(request, emit: EventCallback, cancel_check: CancelCheck):
    emitter = SchedulerEmitter(emit)
    start_time, end_time, target_ips, exclude_ips, ports = _collect_request_context(request)

    emitter.job_started(
        analysis_mode=request.analysis_mode,
        start_time=start_time,
        end_time=end_time,
        workers=request.workers or get_dynamic_workers(),
        split_mode=get_dynamic_split_mode(),
        targets_count=len(target_ips),
        policyids=request.policyids or ([request.policyid] if request.policyid is not None else []),
        message=f"Analyzing: {start_time} -> {end_time}",
    )

    if request.use_machines_file:
        emitter.message(f"Loaded {len(target_ips)} targets from machines.txt", stage="job")

    if request.analysis_mode == "policyid":
        return _run_policyid(request, emitter, cancel_check, start_time, end_time, target_ips, exclude_ips, ports)

    return _run_direction(request, emitter, cancel_check, start_time, end_time, target_ips, exclude_ips, ports)
