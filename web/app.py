"""FastAPI web-СЃРµСЂРІРµСЂ РґР»СЏ falogviewerv2 (falv2)."""

import os
import sys
import json
import csv
import io
import logging
import asyncio
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Р”РѕР±Р°РІР»СЏРµРј РєРѕСЂРµРЅСЊ РїСЂРѕРµРєС‚Р° РІ path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config import (
    MACHINES_FILE,
    INTERNAL_IPS_FILE,
    PORTS_FILE,
    LOGS_DIR,
    RESULTS_DIR,
    COLUMNS_CONFIG,
    get_dynamic_workers,
    get_dynamic_batch_size,
    get_dynamic_max_task_hours,
    get_dynamic_max_matched_logs,
    reload_env,
    ensure_directories,
    validate_config,
)
from utils.network import load_machines, load_ports
from client.faz_client import FortiAnalyzerClient
from analyzer.log_analyzer import analyze_logs, analyze_policyid_logs

# ========================
# Р›РѕРіРёСЂРѕРІР°РЅРёРµ РІРµР±-СЃРµСЂРІРµСЂР°
# ========================

ensure_directories()

log_file = Path(LOGS_DIR) / "web_server.log"

# Р¤РѕСЂРјР°С‚С‚РµСЂ РґР»СЏ РІСЃРµС… Р»РѕРіРѕРІ
file_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

# File handler вЂ” Р’РЎР• Р»РѕРіРё (РЅР°С€ РєРѕРґ + uvicorn)
file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
file_handler.setFormatter(file_formatter)
file_handler.setLevel(logging.INFO)

# Stream handler вЂ” С‚РѕР»СЊРєРѕ РІ РєРѕРЅСЃРѕР»СЊ
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(file_formatter)
stream_handler.setLevel(logging.INFO)

# РќР°С€ logger
logger = logging.getLogger("falv2.web")
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# РџРµСЂРµС…РІР°С‚С‹РІР°РµРј uvicorn Р»РѕРіРё РІ С„Р°Р№Р»
for uv_logger_name in ("uvicorn", "uvicorn.access", "uvicorn.error", "uvicorn.asgi"):
    uv_logger = logging.getLogger(uv_logger_name)
    uv_logger.addHandler(file_handler)
    uv_logger.setLevel(logging.INFO)


# ========================
# Pydantic РјРѕРґРµР»Рё
# ========================

class TargetHost(BaseModel):
    ip: str
    mask: str = "/32"


class AnalysisRequest(BaseModel):
    time_mode: str = "hours"
    time_value: int = 24
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    analysis_mode: str = "direction"
    direction: str = "all"
    exclude_internal: bool = True
    use_machines_file: bool = True
    targets: List[TargetHost] = []
    policyid: Optional[int] = None
    proto_enabled: bool = False
    ports: str = ""
    smart_action: str = "all"
    columns: Optional[dict] = None
    workers: Optional[int] = None
    output_format: str = "txt"  # txt | csv | both


class SettingsUpdate(BaseModel):
    faz_url: Optional[str] = None
    faz_username: Optional[str] = None
    faz_password: Optional[str] = None
    batch_size: Optional[int] = None
    smart_action: Optional[str] = None
    results_dir: Optional[str] = None
    max_task_hours: Optional[int] = None
    max_matched_logs: Optional[int] = None
    max_workers: Optional[int] = None
    columns: Optional[dict] = None
    output_format: Optional[str] = None


# ========================
# РҐРµР»РїРµСЂС‹
# ========================

def load_internal_ips() -> set:
    internal_file = Path(INTERNAL_IPS_FILE)
    if internal_file.exists():
        return set(load_machines(str(internal_file)))
    return set()


def expand_targets(targets: List[TargetHost]) -> List[str]:
    import ipaddress
    ips = []
    for t in targets:
        try:
            if "/" in t.ip:
                network = ipaddress.IPv4Network(t.ip, strict=False)
                ips.extend([str(ip) for ip in network])
            elif t.mask and t.mask != "/32":
                cidr = f"{t.ip}{t.mask}"
                network = ipaddress.IPv4Network(cidr, strict=False)
                ips.extend([str(ip) for ip in network])
            else:
                ipaddress.IPv4Address(t.ip)
                ips.append(t.ip)
        except Exception as e:
            logger.warning(f"Invalid target {t.ip}{t.mask}: {e}")
    return ips


def parse_history() -> List[dict]:
    history_path = Path(RESULTS_DIR) / "history.txt"
    if not history_path.exists():
        return []

    entries = []
    with open(history_path, "r", encoding="utf-8") as f:
        content = f.read()

    blocks = content.split("\n=== ")
    for block in blocks[1:]:
        lines = block.strip().split("\n")
        if not lines:
            continue

        entry = {
            "timestamp": "",
            "cmd": "",
            "time_range": "",
            "smart_action": "",
            "filter_mode": "",
            "file": "",
            "has_inbound": False,
            "has_outbound": False,
            "has_policy": False,
            "direction": "",
            "exclude_used": False,
            "policyid": "",
            "summary_lines": [],
        }

        for line in lines:
            if line.startswith("=== "):
                entry["timestamp"] = line.strip("= ")
            elif line.startswith("CMD:"):
                entry["cmd"] = line[4:].strip()
            elif line.startswith("TIME:"):
                entry["time_range"] = line[5:].strip()
            elif line.startswith("SMART_ACTION="):
                parts = line.split("|")
                entry["smart_action"] = parts[0].split("=")[1].strip() if "=" in parts[0] else ""
                if len(parts) > 1 and "FILTER_MODE=" in parts[1]:
                    entry["filter_mode"] = parts[1].split("=")[1].strip()
            elif line.startswith("FILE:"):
                entry["file"] = line[5:].strip()

        # РџР°СЂСЃРёРј РЅР°РїСЂР°РІР»РµРЅРёРµ Рё policyid РёР· CMD
        cmd = entry["cmd"]
        if "policyid=" in cmd:
            entry["has_policy"] = True
            import re
            m = re.search(r'policyid=(\d+)', cmd)
            if m:
                entry["policyid"] = m.group(1)
        elif "direction=" in cmd:
            dir_match = cmd.split("direction=")
            if len(dir_match) > 1:
                entry["direction"] = dir_match[1].split()[0].split("&")[0].strip()

        if "exclude" in cmd.lower() or "internal" in cmd.lower():
            entry["exclude_used"] = True

        # РЎРѕР±РёСЂР°РµРј РёС‚РѕРіРѕРІС‹Рµ СЃС‚СЂРѕРєРё
        for line in lines:
            if line.startswith("Total "):
                entry["summary_lines"].append(line.strip())

        if "POLICYID" in block:
            entry["has_policy"] = True
        if "INBOUND" in block:
            entry["has_inbound"] = True
        if "OUTBOUND" in block:
            entry["has_outbound"] = True

        entries.append(entry)

    return list(reversed(entries))


def _sanitize_env_value(val: str) -> str:
    """Экранирует спецсимволы для безопасной записи в .env."""
    val = val.replace("\n", "").replace("\r", "")
    # Если значение содержит #, =, пробелы или кавычки — оборачиваем в кавычки
    if any(c in val for c in ("#", "=", " ", '"', "'")):
        val = '"' + val.replace('"', '\\"') + '"'
    return val


def update_env_file(updates: dict):
    env_path = PROJECT_ROOT / ".env"
    if not env_path.exists():
        return

    lines = env_path.read_text(encoding="utf-8").splitlines()
    new_lines = []

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            new_lines.append(line)
            continue

        key = stripped.split("=")[0]
        if key in updates:
            val = _sanitize_env_value(str(updates[key]))
            comment = ""
            if "#" in line:
                comment = "  " + line.split("#", 1)[1]
            new_lines.append(f"{key}={val}{comment}")
        else:
            new_lines.append(line)

    env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    reload_env()
    logger.info(f"Settings updated: {list(updates.keys())}")


def text_to_csv(text: str) -> str:
    """РљРѕРЅРІРµСЂС‚РёСЂСѓРµС‚ С‚РµРєСЃС‚РѕРІС‹Р№ РѕС‚С‡С‘С‚ РІ CSV."""
    if not text or text.strip() == "NO DATA":
        return "NO DATA"

    lines = text.strip().split("\n")
    csv_output = io.StringIO()
    writer = csv.writer(csv_output)

    header_written = False
    for line in lines:
        # РџСЂРѕРїСѓСЃРєР°РµРј СЂР°Р·РґРµР»РёС‚РµР»Рё Рё Р·Р°РіРѕР»РѕРІРєРё СЃРµРєС†РёР№
        if line.startswith("=") or line.startswith("-") or not line.strip():
            continue
        if line.startswith("Total "):
            writer.writerow([line.strip()])
            continue

        # Р Р°Р·РґРµР»СЏРµРј РїРѕ РґРІРѕР№РЅС‹Рј РїСЂРѕР±РµР»Р°Рј (РєР°Рє РІ РѕС‚С‡С‘С‚Рµ)
        parts = [p.strip() for p in line.split("  ") if p.strip()]
        if not parts:
            continue

        if not header_written:
            writer.writerow(parts)
            header_written = True
        else:
            writer.writerow(parts)

    return csv_output.getvalue()


def append_history_simple(text: str, start_time: str, end_time: str, cmd: str, filename: str):
    history_path = Path(RESULTS_DIR) / "history.txt"
    history_path.parent.mkdir(parents=True, exist_ok=True)

    header = (
        f"\n=== {datetime.now():%Y-%m-%d %H:%M:%S} ===\n"
        f"CMD: {cmd}\n"
        f"TIME: {start_time} в†’ {end_time}\n"
        f"SMART_ACTION={os.getenv("SMART_ACTION", "all")} | FILTER_MODE={os.getenv("FILTER_MODE", "faz")}\n"
        f"FILE: {filename}\n"
        f"{'-' * 60}\n"
    )

    with open(history_path, "a", encoding="utf-8") as f:
        f.write(header)
        f.write(text.rstrip() + "\n")


# ========================
# SSE РїСЂРѕРіСЂРµСЃСЃ
# ========================

_analyze_semaphore = asyncio.Semaphore(2)
_progress_queues: dict[str, asyncio.Queue] = {}


async def run_analysis_in_thread(request: AnalysisRequest, request_id: str):
    loop = asyncio.get_event_loop()
    queue = asyncio.Queue()
    _progress_queues[request_id] = queue

    def progress(msg: str, ip: str = None):
        loop.call_soon_threadsafe(queue.put_nowait, {"type": "progress", "message": msg, "ip": ip})

    def worker_start(ip: str, direction: str):
        loop.call_soon_threadsafe(queue.put_nowait, {"type": "worker_start", "ip": ip, "direction": direction})

    def worker_done_event(ip: str, direction: str):
        loop.call_soon_threadsafe(queue.put_nowait, {"type": "worker_done", "ip": ip, "direction": direction})

    def done(result: dict):
        loop.call_soon_threadsafe(queue.put_nowait, {"type": "done", "result": result})

    def error(msg: str):
        loop.call_soon_threadsafe(queue.put_nowait, {"type": "error", "message": msg, "ip": None})

    def run():
        try:
            reload_env()

            if request.time_mode == "exact" and request.start_time and request.end_time:
                start_time = request.start_time
                end_time = request.end_time
            else:
                hours = request.time_value * 24 if request.time_mode == "days" else request.time_value
                end_dt = datetime.now()
                start_dt = end_dt - timedelta(hours=hours)
                start_time = start_dt.strftime("%Y-%m-%d %H:%M:%S")
                end_time = end_dt.strftime("%Y-%m-%d %H:%M:%S")

            progress(f"Analyzing: {start_time} в†’ {end_time}")

            target_ips = []
            if request.use_machines_file:
                machines_path = Path(MACHINES_FILE)
                if machines_path.exists():
                    target_ips = load_machines(str(machines_path))
                    progress(f"Loaded {len(target_ips)} targets from machines.txt")
                else:
                    error("machines.txt not found in resources/")
                    return
            else:
                target_ips = expand_targets(request.targets) if request.targets else []

            exclude_ips = load_internal_ips() if request.exclude_internal else set()
            target_ips = [ip for ip in target_ips if ip not in exclude_ips]

            if not target_ips and request.analysis_mode != "policyid":
                error("No target IPs after expansion and exclusion")
                return

            ports = [p.strip() for p in request.ports.split(",") if p.strip()] if request.proto_enabled else None

            if request.columns:
                import config
                for k, v in request.columns.items():
                    if k in config.COLUMNS_CONFIG:
                        config.COLUMNS_CONFIG[k] = v

            import config
            config.SMART_ACTION = request.smart_action.lower()

            results_dir = Path(RESULTS_DIR)
            results_dir.mkdir(parents=True, exist_ok=True)

            if request.analysis_mode == "policyid" and request.policyid is not None:
                progress(f"PolicyID mode: policyid={request.policyid}")
                text = _faz_search_wrapper(
                    progress=progress,
                    faz_url=os.getenv("FORTIANALYZER_URL"),
                    faz_user=os.getenv("FORTIANALYZER_USERNAME"),
                    faz_pass=os.getenv("FORTIANALYZER_PASSWORD"),
                    target_ips=target_ips,
                    exclude_ips=list(exclude_ips),
                    start_time=start_time, end_time=end_time,
                    batch_size=get_dynamic_batch_size(), ports=ports,
                    policyid=request.policyid, columns=request.columns,
                )
                if text is None:
                    error("FAZ login failed")
                    return
                if not str(text).strip():
                    text = "NO DATA\n"
                text = str(text)

                _save_result(text, progress, results_dir, f"policy_{request.policyid}",
                               start_time, end_time, f"policyid={request.policyid}",
                               request.output_format)
                done({"files": [{"name": f"policy_{request.policyid}.txt", "path": f"policy_{request.policyid}.txt"}],
                      "texts": {"txt": text}})
            else:
                directions = ["inbound", "outbound"] if request.direction == "all" else [request.direction]
                workers = request.workers or get_dynamic_workers()

                direction_text = {d: [] for d in directions}
                per_ip_results = {}

                if workers > 1 and len(target_ips) > 1:
                    from concurrent.futures import ThreadPoolExecutor, as_completed
                    import threading
                    _ip_lock = threading.Lock()
                    progress(f"Parallel mode: {workers} workers, {len(target_ips)} IPs")


                    def process_ip(ip, direction):
                        worker_start(ip, direction)
                        progress(f"▶ Starting: {ip} [{direction}]", ip=ip)
                        report_dict = _faz_search_wrapper(
                            progress=progress,
                            faz_url=os.getenv("FORTIANALYZER_URL"),
                            faz_user=os.getenv("FORTIANALYZER_USERNAME"),
                            faz_pass=os.getenv("FORTIANALYZER_PASSWORD"),
                            target_ips=[ip],
                            exclude_ips=list(exclude_ips),
                            start_time=start_time, end_time=end_time,
                            batch_size=get_dynamic_batch_size(), ports=ports,
                            direction=direction, columns=request.columns,
                        )
                        if report_dict:
                            for (_, dir_key), txt in (report_dict or {}).items():
                                if txt.strip():
                                    direction_text[dir_key].append(txt)
                                    # Сохраняем per-IP результат (thread-safe)
                                    with _ip_lock:
                                        if ip not in per_ip_results:
                                            per_ip_results[ip] = {}
                                        per_ip_results[ip][dir_key] = txt
                        progress(f"✓ Done: {ip} [{direction}]", ip=ip)
                        worker_done_event(ip, direction)
                        return direction_text[dir_key] if direction else []

                    futures_map = {}
                    with ThreadPoolExecutor(max_workers=workers) as ex:
                        for direction in directions:
                            for ip in target_ips:
                                future = ex.submit(process_ip, ip, direction)
                                futures_map[future] = (ip, direction)

                    for future in as_completed(futures_map):
                        ip, direction = futures_map[future]
                        try:
                            future.result()  # результаты уже добавлены в direction_text и per_ip_results
                        except Exception as e:
                            progress(f"Error for {ip}: {e}")
                else:
                    for direction in directions:
                        progress(f"▶ Direction: {direction}")
                        for ip in target_ips:
                            worker_start(ip, direction)
                            progress(f"  ▶ Starting: {ip}", ip=ip)
                            report_dict = _faz_search_wrapper(
                                progress=progress,
                                faz_url=os.getenv("FORTIANALYZER_URL"),
                                faz_user=os.getenv("FORTIANALYZER_USERNAME"),
                                faz_pass=os.getenv("FORTIANALYZER_PASSWORD"),
                                target_ips=[ip],
                                exclude_ips=list(exclude_ips),
                                start_time=start_time, end_time=end_time,
                                batch_size=get_dynamic_batch_size(), ports=ports,
                                direction=direction,
                            )
                            for (_, dir_key), txt in (report_dict or {}).items():
                                if txt.strip():
                                    direction_text[dir_key].append(txt)
                            progress(f"  ✓ Done: {ip}", ip=ip)
                            worker_done_event(ip, direction)

                all_files = []
                all_texts = {}
                for direction in directions:
                    final_text = "\n\n".join(direction_text[direction]) if direction_text[direction] else "NO DATA\n"
                    files, texts = _save_result(final_text, progress, results_dir, direction,
                                   start_time, end_time, f"direction={direction}",
                                   request.output_format)
                    all_files.extend(files)
                    all_texts.update(texts)
                # Only include per_ip if we actually have per-IP results (parallel mode)
                # Send per_ip only if parallel mode populated it with actual data
                if per_ip_results and len(per_ip_results) >= 1 and all(len(v) > 0 for v in per_ip_results.values()):
                    all_texts["per_ip"] = per_ip_results
                done({"files": all_files, "texts": all_texts})

        except Exception as e:
            import traceback
            logger.exception("Analysis error")
            error(f"Error: {e}\n{traceback.format_exc()}")

    thread = threading.Thread(target=run, daemon=True)
    thread.start()


def _save_result(text, progress, results_dir, name_prefix,
                   start_time, end_time, cmd_label, output_format, ip=None):
    """Сохраняет результат (txt + опционально csv), пишет историю, шлёт done."""
    from utils.output import save_results

    files = []
    result_data = {}

    txt_file = results_dir / f"{name_prefix}.txt"
    save_results(text, txt_file)
    append_history_simple(text, start_time, end_time, cmd_label, txt_file.name)
    files.append({"name": txt_file.name, "path": txt_file.name})
    result_data[f"{name_prefix}.txt"] = text

    if output_format in ("csv", "both"):
        csv_text = text_to_csv(text)
        csv_file = results_dir / f"{name_prefix}.csv"
        csv_file.write_text(csv_text, encoding="utf-8")
        files.append({"name": csv_file.name, "path": csv_file.name})
        result_data[f"{name_prefix}.csv"] = csv_text

    if progress:
        progress(f"💾 Saved: {name_prefix}.{output_format}", ip=ip)
    return files, result_data


def _faz_search_wrapper(progress, faz_url, faz_user, faz_pass,
                        target_ips, exclude_ips, start_time, end_time,
                        batch_size, ports, direction=None, policyid=None, columns=None):
    """
    Общий паттерн FAZ search: login → patch → analyze → logout.
    direction — для direction mode, policyid — для policyid mode.
    Возвращает (text или dict с результатами).
    """
    client = FortiAnalyzerClient(
        url=faz_url, username=faz_user, password=faz_pass,
    )
    if not client.login():
        return None
    try:
        ip_label = target_ips[0] if target_ips and direction else ""
        _patch_faz_for_sse(client, progress, ip_label=ip_label)

        if policyid is not None:
            return analyze_policyid_logs(
                client=client, target_ips=target_ips, policyid=policyid,
                start_time=start_time, end_time=end_time, exclude_ips=exclude_ips,
                batch_size=batch_size, ports=ports, columns=columns,
            )
        else:
            return analyze_logs(
                client=client, target_ips=target_ips, direction=direction,
                start_time=start_time, end_time=end_time, exclude_ips=exclude_ips,
                batch_size=batch_size, ports=ports, columns=columns,
            )
    finally:
        client.logout()



def _patch_faz_for_sse(client: FortiAnalyzerClient, progress, ip_label: str = ""):
    """Патчим методы FAZ-клиента для SSE прогресса. ip_label - IP воркера."""
    import time
    original_create = client.create_search_task
    original_wait = client.wait_for_task_completion
    original_fetch = client.fetch_logs

    def patched_create(filter_str, start, end):
        result = original_create(filter_str, start, end)
        if result:
            progress(f"Created search task: {result}", ip=ip_label)
        return result

    import time

    def patched_wait(task_id, max_wait=300):
        start_ts = time.time()
        last_progress_val = -1
        last_poll_ts = 0
        poll_interval = 1  # опрашиваем каждую секунду для плавного SSE

        # Первое сообщение — сразу после создания таска
        progress("Waiting for FAZ to process search task...", ip=ip_label)

        while time.time() - start_ts < max_wait:
            # Шлём "heartbeat" каждые poll_interval секунд даже если прогресс не изменился
            now = time.time()
            if now - last_poll_ts < poll_interval:
                time.sleep(0.3)
                continue
            last_poll_ts = now

            payload = {
                "id": "123456789", "jsonrpc": "2.0", "method": "get",
                "params": [{"apiver": 3, "url": f"/logview/adom/root/logsearch/count/{task_id}"}],
                "session": client.session,
            }
            try:
                result = client._post(payload)
                raw = result.get("result", {})
                status_code = raw.get("status", {}).get("code", -1)
                matched = raw.get("matched-logs", 0)
                prog = raw.get("progress-percent", 0)

                if prog != last_progress_val:
                    progress(f"Progress: {prog}%", ip=ip_label)
                    last_progress_val = prog
                else:
                    # heartbeat — показать, что мы всё ещё ждём
                    progress(f"Waiting... {prog}% | matched: {matched}", ip=ip_label)

                if status_code == 0 and prog == 100:
                    progress(f"✅ Task completed. Found {matched} logs", ip=ip_label)
                    return True, matched
                if status_code in (0, 1):
                    continue
                progress(f"⚠ Task failed with status code: {status_code}", ip=ip_label)
                return False, 0
            except Exception as e:
                progress(f"⚠ Status check error, retrying: {e}", ip=ip_label)
                time.sleep(3)
        progress("⚠ Task did not complete within allowed time", ip=ip_label)
        return False, 0

    def patched_fetch(task_id, total, batch=100):
        progress(f"📥 Fetching logs (matched={total}, batch={batch})...", ip=ip_label)
        all_logs = []
        offset = 0
        while offset < total:
            payload = {
                "id": "123456789", "jsonrpc": "2.0", "method": "get",
                "params": [{"apiver": 3, "limit": batch, "offset": offset,
                             "url": f"/logview/adom/root/logsearch/{task_id}"}],
                "session": client.session,
            }
            try:
                resp = client._post(payload)
                data = resp.get("result", {}).get("data", [])
            except Exception:
                break
            if not data:
                break
            all_logs.extend(data)
            offset += len(data)
            pct = int(offset / total * 100) if total else 100
            progress(f"📥 Fetched {len(all_logs)}/{total} logs ({pct}%)", ip=ip_label)
        return all_logs

    client.create_search_task = patched_create
    client.wait_for_task_completion = patched_wait
    client.fetch_logs = patched_fetch

@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_directories()
    logger.info("falv2 web server started")
    yield
    logger.info("falv2 web server stopped")


app = FastAPI(title="falv2 Web UI", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).parent / "static"
TEMPLATES_DIR = Path(__file__).parent / "templates"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
async def index():
    return FileResponse(TEMPLATES_DIR / "index.html")


# ========================
# API endpoints
# ========================

@app.post("/api/analyze/stream")
async def analyze_stream(request: AnalysisRequest):
    validate_config()

    # Rate limiting
    if _analyze_semaphore.locked():
        raise HTTPException(status_code=429, detail="Too many concurrent analyses (max 2)")

    import uuid
    request_id = str(uuid.uuid4())

    async with _analyze_semaphore:
        await run_analysis_in_thread(request, request_id)
        queue = _progress_queues.get(request_id, asyncio.Queue())

    async def event_generator():
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=120)
                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                if event.get("type") in ("done", "error"):
                    # Cleanup
                    _progress_queues.pop(request_id, None)
                    break
            except asyncio.TimeoutError:
                yield f"data: {json.dumps({'type': 'timeout'}, ensure_ascii=False)}\n\n"
                break

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/results")
async def list_results():
    results_dir = Path(RESULTS_DIR)
    if not results_dir.exists():
        return {"files": []}
    files = []
    for f in sorted(results_dir.rglob("*"), key=lambda x: x.stat().st_mtime, reverse=True):
        if not f.is_file() or f.name == "history.txt":
            continue
        stat = f.stat()
        rel = f.relative_to(results_dir)
        files.append({
            "name": f.name,
            "path": str(rel).replace("\\", "/"),
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        })
    return {"files": files}


@app.get("/api/results/{file_path:path}")
async def get_result(file_path: str):
    results_dir = Path(RESULTS_DIR)
    full_path = (results_dir / file_path).resolve()
    try:
        full_path.relative_to(results_dir.resolve())
    except ValueError:
        raise HTTPException(status_code=403, detail="Access denied")
    if not full_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return {"content": full_path.read_text(encoding="utf-8"), "name": full_path.name}


@app.get("/api/results/download/{file_path:path}")
async def download_result(file_path: str):
    results_dir = Path(RESULTS_DIR)
    full_path = (results_dir / file_path).resolve()
    try:
        full_path.relative_to(results_dir.resolve())
    except ValueError:
        raise HTTPException(status_code=403, detail="Access denied")
    if not full_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(str(full_path), filename=full_path.name)


@app.get("/api/resources/machines")
async def get_machines():
    """Загрузить IPs из machines.txt."""
    machines_path = Path(MACHINES_FILE)
    if not machines_path.exists():
        return {"ips": []}
    ips = load_machines(str(machines_path))
    return {"ips": ips, "count": len(ips)}


@app.get("/api/resources/internal")
async def get_internal_ips():
    """Загрузить IPs для исключения из internal_ips.txt."""
    if not Path(INTERNAL_IPS_FILE).exists():
        return {"ips": []}
    ips = load_machines(str(INTERNAL_IPS_FILE))
    return {"ips": ips, "count": len(ips)}


@app.get("/api/history")
async def get_history():
    return {"entries": parse_history()}


@app.get("/api/settings")
async def get_settings():
    reload_env()
    return {
        "faz_url": os.getenv("FORTIANALYZER_URL") or "",
        "faz_username": os.getenv("FORTIANALYZER_USERNAME") or "",
        "faz_password": "********" if os.getenv("FORTIANALYZER_PASSWORD") else "",
        "batch_size": get_dynamic_batch_size(),
        "smart_action": os.getenv("SMART_ACTION", "all"),
        "results_dir": RESULTS_DIR,
        "max_task_hours": get_dynamic_max_task_hours(),
        "max_matched_logs": get_dynamic_max_matched_logs(),
        "max_workers": get_dynamic_workers(),
        "columns": COLUMNS_CONFIG,
    }


@app.put("/api/settings")
async def update_settings(data: SettingsUpdate):
    updates = {}
    if data.faz_url is not None:
        updates["FORTIANALYZER_URL"] = data.faz_url
    if data.faz_username is not None:
        updates["FORTIANALYZER_USERNAME"] = data.faz_username
    if data.faz_password is not None and data.faz_password != "********":
        updates["FORTIANALYZER_PASSWORD"] = data.faz_password
    if data.batch_size is not None:
        updates["BATCH_SIZE"] = str(data.batch_size)
    if data.smart_action is not None:
        updates["SMART_ACTION"] = data.smart_action
    if data.results_dir is not None:
        updates["RESULTS_DIR"] = data.results_dir
    if data.max_task_hours is not None:
        updates["MAX_TASK_HOURS"] = str(data.max_task_hours)
    if data.max_matched_logs is not None:
        updates["MAX_MATCHED_LOGS_PER_TASK"] = str(data.max_matched_logs)
    if data.max_workers is not None:
        updates["MAX_WORKERS"] = str(data.max_workers)
    if data.columns:
        for k, v in data.columns.items():
            updates[f"COLUMN_{k.upper()}"] = str(v).lower()
    if updates:
        update_env_file(updates)
    return {"status": "ok", "updated": len(updates)}


if __name__ == "__main__":
    import uvicorn
    import logging.config

    # РљРѕРЅС„РёРіСѓСЂР°С†РёСЏ uvicorn logging вЂ” РёСЃРїРѕР»СЊР·СѓРµРј РЅР°С€ file_handler
    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            },
        },
        "handlers": {
            "file": {
                "class": "logging.FileHandler",
                "filename": str(log_file),
                "formatter": "default",
                "encoding": "utf-8",
            },
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "default",
                "stream": sys.stdout,
            },
        },
        "loggers": {
            "uvicorn": {"handlers": ["file", "console"], "level": "INFO", "propagate": False},
            "uvicorn.error": {"handlers": ["file", "console"], "level": "INFO", "propagate": False},
            "uvicorn.access": {"handlers": ["file", "console"], "level": "INFO", "propagate": False},
            "uvicorn.asgi": {"handlers": ["file", "console"], "level": "INFO", "propagate": False},
            "falv2.web": {"handlers": ["file", "console"], "level": "INFO", "propagate": False},
        },
    }
    logging.config.dictConfig(logging_config)

    uvicorn.run(app, host="127.0.0.1", port=8500, log_config=None)


