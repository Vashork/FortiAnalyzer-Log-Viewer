"""FastAPI web-СЃРµСЂРІРµСЂ РґР»СЏ falogviewerv2 (falv2)."""

import os
import sys
import json
import logging
import asyncio
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

# Р”РѕР±Р°РІР»СЏРµРј РєРѕСЂРµРЅСЊ РїСЂРѕРµРєС‚Р° РІ path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config import (
    MACHINES_FILE,
    INTERNAL_IPS_FILE,
    LOGS_DIR,
    RESULTS_DIR,
    COLUMNS_CONFIG,
    AGGREGATION_CONFIG,
    get_dynamic_workers,
    get_dynamic_batch_size,
    get_dynamic_max_task_hours,
    get_dynamic_max_matched_logs,
    get_dynamic_split_mode,
    get_dynamic_reverse_dns_enabled,
    reload_env,
    ensure_directories,
    validate_config,
)
from utils.network import load_machines
from web.analysis_scheduler import AnalysisCancelled, run_analysis_request

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
    policyids: Optional[List[int]] = None
    proto_enabled: bool = False
    ports: str = ""
    smart_action: str = "all"
    columns: Optional[dict] = None
    aggregation: Optional[dict] = None
    workers: Optional[int] = None
    output_format: str = "txt"  # txt | csv | both

    @field_validator("policyids", mode="before")
    @classmethod
    def normalize_policyids(cls, value):
        if value in (None, "", []):
            return None
        if isinstance(value, int):
            return [value]
        if isinstance(value, str):
            parts = [p.strip() for p in value.split(",") if p.strip()]
            if not parts:
                return None
            return [int(p) for p in parts]
        if isinstance(value, list):
            normalized = []
            for item in value:
                if item in (None, ""):
                    continue
                normalized.append(int(item))
            return normalized or None
        raise ValueError("policyids must be a list of integers or comma-separated string")


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
    session_split_mode: Optional[str] = None  # "ip" или "time"
    disable_reverse_dns: Optional[bool] = None
    columns: Optional[dict] = None
    aggregation: Optional[dict] = None
    output_format: Optional[str] = None


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
            "state": None,  # Полное состояние запроса
        }

        for line in lines:
            if line.startswith("=== "):
                entry["timestamp"] = line.strip("= ")
            elif line.startswith("CMD:"):
                entry["cmd"] = line[4:].strip()
            elif line.startswith("TIME:"):
                entry["time_range"] = line[5:].strip()
            elif line.startswith("STATE_JSON:"):
                state_str = line[11:].strip()
                if state_str:
                    try:
                        entry["state"] = json.loads(state_str)
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse state JSON: {state_str}")
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
    applied_keys = set()

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
            applied_keys.add(key)
        else:
            new_lines.append(line)

    for key, value in updates.items():
        if key in applied_keys:
            continue
        val = _sanitize_env_value(str(value))
        new_lines.append(f"{key}={val}")

    env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    reload_env()
    logger.info(f"Settings updated: {list(updates.keys())}")

# ========================
# SSE РїСЂРѕРіСЂРµСЃСЃ
# ========================

_analyze_semaphore = asyncio.Semaphore(2)
_progress_queues: dict[str, asyncio.Queue] = {}
_cancel_flags: dict[str, bool] = {}  # request_id -> True если отменено


async def run_analysis_in_thread(request: AnalysisRequest, request_id: str):
    loop = asyncio.get_event_loop()
    queue = asyncio.Queue()
    _progress_queues[request_id] = queue
    _cancel_flags[request_id] = False  # флаг отмены

    def emit(event: dict):
        loop.call_soon_threadsafe(queue.put_nowait, event)

    def done(result: dict):
        _cancel_flags.pop(request_id, None)  # cleanup
        loop.call_soon_threadsafe(queue.put_nowait, {"type": "done", "result": result})

    def cancelled(message: str):
        _cancel_flags.pop(request_id, None)
        loop.call_soon_threadsafe(queue.put_nowait, {"type": "cancelled", "message": message})

    def error(msg: str):
        _cancel_flags.pop(request_id, None)  # cleanup
        loop.call_soon_threadsafe(queue.put_nowait, {"type": "error", "message": msg, "ip": None})

    def is_cancelled() -> bool:
        return _cancel_flags.get(request_id, False)

    def run():
        try:
            result = run_analysis_request(request, emit=emit, cancel_check=is_cancelled)
            done(result)
        except AnalysisCancelled as exc:
            cancelled(str(exc))
        except Exception as e:
            import traceback
            logger.exception("Analysis error")
            error(f"Error: {e}\n{traceback.format_exc()}")

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

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
        # Отправляем request_id первым сообщением
        yield f"data: {json.dumps({'type': 'request_id', 'request_id': request_id}, ensure_ascii=False)}\n\n"
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=120)
                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                if event.get("type") in ("done", "error", "cancelled"):
                    # Cleanup
                    _progress_queues.pop(request_id, None)
                    break
            except asyncio.TimeoutError:
                yield f"data: {json.dumps({'type': 'timeout'}, ensure_ascii=False)}\n\n"
                continue

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/analyze/cancel/{request_id}")
async def cancel_analysis(request_id: str):
    """Отменить текущий анализ."""
    if request_id in _cancel_flags:
        _cancel_flags[request_id] = True
        return {"status": "cancelled", "request_id": request_id}
    raise HTTPException(status_code=404, detail="Analysis not found")


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
        "session_split_mode": get_dynamic_split_mode(),
        "disable_reverse_dns": not get_dynamic_reverse_dns_enabled(),
        "columns": COLUMNS_CONFIG,
        "aggregation": AGGREGATION_CONFIG,
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
    if data.session_split_mode is not None:
        val = data.session_split_mode.strip().lower()
        if val in ("ip", "time"):
            updates["SESSION_SPLIT_MODE"] = val
    if data.disable_reverse_dns is not None:
        updates["DISABLE_REVERSE_DNS"] = str(bool(data.disable_reverse_dns)).lower()
    if data.columns:
        for k, v in data.columns.items():
            updates[f"COLUMN_{k.upper()}"] = str(v).lower()
    if data.aggregation:
        for k, v in data.aggregation.items():
            updates[f"AGGREGATE_{k.upper()}"] = str(v).lower()
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
