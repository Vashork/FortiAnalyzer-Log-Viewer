import os
import sys
import json
import logging
import asyncio
import threading
import ipaddress
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Literal
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator, model_validator

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
    get_results_dir_path,
    reload_env,
    validate_config,
)
from utils.network import clear_hostname_cache, configure_reverse_dns, load_machines
from web.analysis_scheduler import AnalysisCancelled, run_analysis_request
from web.job_registry import JobRegistry

# ========================
# Р›РѕРіРёСЂРѕРІР°РЅРёРµ РІРµР±-СЃРµСЂРІРµСЂР°
# ========================

# Create logs directory before configuring file logging. Results directory is created
# through _ensure_web_directories() after the project-root safety check.
Path(LOGS_DIR).mkdir(parents=True, exist_ok=True)

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

MAX_WEB_WORKERS_LIMIT = int(os.getenv("MAX_WEB_WORKERS_LIMIT", "32"))
MAX_TIME_HOURS_LIMIT = int(os.getenv("MAX_TIME_HOURS_LIMIT", "8760"))
MAX_TIME_DAYS_LIMIT = int(os.getenv("MAX_TIME_DAYS_LIMIT", "365"))
MAX_POLICY_IDS_LIMIT = int(os.getenv("MAX_POLICY_IDS_LIMIT", "100"))
MAX_TARGETS_LIMIT = int(os.getenv("MAX_TARGETS_LIMIT", "1024"))
MAX_EXPANDED_TARGETS_LIMIT = int(os.getenv("MAX_EXPANDED_TARGETS_LIMIT", "4096"))
MAX_RESULT_PREVIEW_BYTES = int(os.getenv("MAX_RESULT_PREVIEW_BYTES", "1048576"))
DEFAULT_CORS_ORIGINS = "http://127.0.0.1:8500,http://localhost:8500"


def _parse_cors_origins(value: str | None = None) -> list[str]:
    raw_value = value if value is not None else os.getenv("WEB_CORS_ALLOW_ORIGINS", DEFAULT_CORS_ORIGINS)
    origins = [origin.strip() for origin in raw_value.split(",") if origin.strip()]
    return [origin for origin in origins if origin != "*"]


def _project_controlled_path(path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(PROJECT_ROOT.resolve())
    except ValueError as exc:
        raise ValueError("path must stay inside the project directory") from exc
    return resolved


def _validate_results_dir_value(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("results_dir cannot be empty")
    results_path = Path(value)
    if results_path.is_absolute():
        raise ValueError("results_dir must be a relative path inside the project directory")
    _project_controlled_path(PROJECT_ROOT / results_path)
    return value


def _ensure_web_directories():
    _project_controlled_path(get_results_dir_path()).mkdir(parents=True, exist_ok=True)
    Path(LOGS_DIR).mkdir(parents=True, exist_ok=True)
    (PROJECT_ROOT / "resources").mkdir(parents=True, exist_ok=True)


class TargetHost(BaseModel):
    ip: str
    mask: str = "/32"

    @field_validator("ip")
    @classmethod
    def validate_ip_or_network(cls, value: str) -> str:
        value = value.strip()
        try:
            if "/" in value:
                ipaddress.IPv4Network(value, strict=False)
            else:
                ipaddress.IPv4Address(value)
        except ValueError as exc:
            raise ValueError("target ip must be an IPv4 address or CIDR network") from exc
        return value

    @field_validator("mask")
    @classmethod
    def validate_mask(cls, value: str) -> str:
        value = value.strip()
        if not value.startswith("/"):
            raise ValueError("mask must use CIDR notation, e.g. /32")
        try:
            prefix = int(value[1:])
        except ValueError as exc:
            raise ValueError("mask must use CIDR notation, e.g. /32") from exc
        if prefix < 0 or prefix > 32:
            raise ValueError("mask prefix must be between /0 and /32")
        return value

    def expanded_count(self) -> int:
        if "/" in self.ip:
            return ipaddress.IPv4Network(self.ip, strict=False).num_addresses
        if self.mask != "/32":
            return ipaddress.IPv4Network(f"{self.ip}{self.mask}", strict=False).num_addresses
        return 1


class AnalysisRequest(BaseModel):
    time_mode: Literal["hours", "days", "exact"] = "hours"
    time_value: int = 24
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    analysis_mode: Literal["direction", "policyid"] = "direction"
    direction: Literal["inbound", "outbound", "all"] = "all"
    exclude_internal: bool = True
    use_machines_file: bool = True
    targets: List[TargetHost] = Field(default_factory=list)
    policyid: Optional[int] = None
    policyids: Optional[List[int]] = None
    proto_enabled: bool = False
    ports: str = ""
    smart_action: Literal["all", "deny", "all-accept"] = "all"
    columns: Optional[dict] = None
    aggregation: Optional[dict] = None
    workers: Optional[int] = None
    output_format: Literal["txt", "csv", "both"] = "txt"  # txt | csv | both

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

    @model_validator(mode="after")
    def validate_limits(self):
        if self.time_value <= 0:
            raise ValueError("time_value must be positive")
        if self.time_mode == "hours" and self.time_value > MAX_TIME_HOURS_LIMIT:
            raise ValueError(f"time_value hours must be <= {MAX_TIME_HOURS_LIMIT}")
        if self.time_mode == "days" and self.time_value > MAX_TIME_DAYS_LIMIT:
            raise ValueError(f"time_value days must be <= {MAX_TIME_DAYS_LIMIT}")
        if self.time_mode == "exact" and not (self.start_time and self.end_time):
            raise ValueError("exact time mode requires start_time and end_time")

        if self.workers is not None and not (1 <= self.workers <= MAX_WEB_WORKERS_LIMIT):
            raise ValueError(f"workers must be between 1 and {MAX_WEB_WORKERS_LIMIT}")

        if self.policyid is not None and self.policyid <= 0:
            raise ValueError("policyid must be positive")
        if self.policyids:
            if len(self.policyids) > MAX_POLICY_IDS_LIMIT:
                raise ValueError(f"policyids cannot contain more than {MAX_POLICY_IDS_LIMIT} items")
            if any(policy_id <= 0 for policy_id in self.policyids):
                raise ValueError("policyids must be positive")

        if self.proto_enabled or self.ports.strip():
            for raw_port in self.ports.split(","):
                raw_port = raw_port.strip()
                if not raw_port:
                    continue
                try:
                    port = int(raw_port)
                except ValueError as exc:
                    raise ValueError("ports must be comma-separated integers") from exc
                if port < 1 or port > 65535:
                    raise ValueError("ports must be between 1 and 65535")

        if not self.use_machines_file:
            if len(self.targets) > MAX_TARGETS_LIMIT:
                raise ValueError(f"targets cannot contain more than {MAX_TARGETS_LIMIT} entries")
            expanded_targets = sum(target.expanded_count() for target in self.targets)
            if expanded_targets > MAX_EXPANDED_TARGETS_LIMIT:
                raise ValueError(
                    f"expanded targets cannot exceed {MAX_EXPANDED_TARGETS_LIMIT} IP addresses"
                )
        return self


class SettingsUpdate(BaseModel):
    faz_url: Optional[str] = None
    faz_username: Optional[str] = None
    faz_password: Optional[str] = None
    batch_size: Optional[int] = None
    smart_action: Optional[Literal["all", "deny", "all-accept"]] = None
    results_dir: Optional[str] = None
    max_task_hours: Optional[int] = None
    max_matched_logs: Optional[int] = None
    max_workers: Optional[int] = None
    session_split_mode: Optional[Literal["ip", "time"]] = None
    disable_reverse_dns: Optional[bool] = None
    columns: Optional[dict] = None
    aggregation: Optional[dict] = None
    output_format: Optional[Literal["txt", "csv", "both"]] = None

    @field_validator("results_dir")
    @classmethod
    def validate_results_dir(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        return _validate_results_dir_value(value)

    @model_validator(mode="after")
    def validate_settings_limits(self):
        if self.batch_size is not None and not (1 <= self.batch_size <= 100000):
            raise ValueError("batch_size must be between 1 and 100000")
        if self.max_task_hours is not None and not (1 <= self.max_task_hours <= MAX_TIME_HOURS_LIMIT):
            raise ValueError(f"max_task_hours must be between 1 and {MAX_TIME_HOURS_LIMIT}")
        if self.max_matched_logs is not None and not (0 <= self.max_matched_logs <= 10000000):
            raise ValueError("max_matched_logs must be between 0 and 10000000")
        if self.max_workers is not None and not (1 <= self.max_workers <= MAX_WEB_WORKERS_LIMIT):
            raise ValueError(f"max_workers must be between 1 and {MAX_WEB_WORKERS_LIMIT}")
        return self


def parse_history() -> List[dict]:
    history_path = get_results_dir_path() / "history.txt"
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

        first_line = lines[0].strip()
        if first_line.endswith("==="):
            entry["timestamp"] = first_line[:-3].strip()

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
                comment = "  #" + line.split("#", 1)[1]
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

MAX_ACTIVE_ANALYSIS_JOBS = int(os.getenv("MAX_ACTIVE_ANALYSIS_JOBS", "2"))
_job_registry = JobRegistry(max_active=MAX_ACTIVE_ANALYSIS_JOBS)
_progress_queues: dict[str, asyncio.Queue] = {}


async def run_analysis_in_thread(request: AnalysisRequest, request_id: str):
    loop = asyncio.get_event_loop()
    queue = asyncio.Queue()
    _progress_queues[request_id] = queue

    def emit(event: dict):
        loop.call_soon_threadsafe(queue.put_nowait, event)

    def done(result: dict):
        loop.call_soon_threadsafe(queue.put_nowait, {"type": "done", "result": result})

    def cancelled(message: str):
        loop.call_soon_threadsafe(queue.put_nowait, {"type": "cancelled", "message": message})

    def error(msg: str):
        loop.call_soon_threadsafe(queue.put_nowait, {"type": "error", "message": msg, "ip": None})

    def is_cancelled() -> bool:
        return _job_registry.is_cancelled(request_id)

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
    try:
        _ensure_web_directories()
    except ValueError as exc:
        logger.error("Invalid RESULTS_DIR: %s", exc)
        raise
    logger.info("falv2 web server started")
    yield
    logger.info("falv2 web server stopped")


app = FastAPI(title="falv2 Web UI", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_parse_cors_origins(),
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


@app.get("/favicon.ico")
async def favicon():
    return FileResponse(STATIC_DIR / "favicon.svg", media_type="image/svg+xml")


# ========================
# API endpoints
# ========================

@app.post("/api/analyze/stream")
async def analyze_stream(request: AnalysisRequest):
    validate_config()

    import uuid
    request_id = str(uuid.uuid4())
    if not _job_registry.start(request_id):
        raise HTTPException(
            status_code=429,
            detail=f"Too many concurrent analyses (max {MAX_ACTIVE_ANALYSIS_JOBS})",
        )

    await run_analysis_in_thread(request, request_id)
    queue = _progress_queues.get(request_id, asyncio.Queue())

    async def event_generator():
        try:
            # Отправляем request_id первым сообщением
            yield f"data: {json.dumps({'type': 'request_id', 'request_id': request_id}, ensure_ascii=False)}\n\n"
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=120)
                    yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                    if event.get("type") in ("done", "error", "cancelled"):
                        break
                except asyncio.TimeoutError:
                    yield f"data: {json.dumps({'type': 'timeout'}, ensure_ascii=False)}\n\n"
                    continue
        finally:
            _progress_queues.pop(request_id, None)
            _job_registry.finish(request_id)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/analyze/cancel/{request_id}")
async def cancel_analysis(request_id: str):
    """Отменить текущий анализ."""
    if _job_registry.cancel(request_id):
        return {"status": "cancelled", "request_id": request_id}
    raise HTTPException(status_code=404, detail="Analysis not found")


@app.get("/api/results")
async def list_results():
    results_dir = _results_dir_path()
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


def _resolve_result_path(file_path: str) -> Path:
    results_dir = _results_dir_path()
    full_path = (results_dir / file_path).resolve()
    try:
        full_path.relative_to(results_dir)
    except ValueError:
        raise HTTPException(status_code=403, detail="Access denied")
    if not full_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return full_path


def _results_dir_path() -> Path:
    try:
        return _project_controlled_path(get_results_dir_path())
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


def _read_result_preview(path: Path) -> dict:
    size = path.stat().st_size
    read_limit = max(0, MAX_RESULT_PREVIEW_BYTES)
    with open(path, "rb") as f:
        raw_content = f.read(read_limit + 1)
    truncated = len(raw_content) > read_limit or size > read_limit
    if truncated:
        raw_content = raw_content[:read_limit]
    return {
        "content": raw_content.decode("utf-8", errors="replace"),
        "name": path.name,
        "truncated": truncated,
        "size": size,
        "preview_limit": read_limit,
    }


def _open_in_explorer(path: Path, select: bool = False):
    if os.name != "nt":
        raise HTTPException(status_code=400, detail="Explorer reveal is only supported on Windows")

    import subprocess

    if select:
        subprocess.Popen(["explorer.exe", "/select,", str(path)])
    else:
        subprocess.Popen(["explorer.exe", str(path)])


@app.get("/api/results/download/{file_path:path}")
async def download_result(file_path: str):
    full_path = _resolve_result_path(file_path)
    return FileResponse(str(full_path), filename=full_path.name)


@app.post("/api/results/reveal/{file_path:path}")
async def reveal_result(file_path: str):
    full_path = _resolve_result_path(file_path)
    _open_in_explorer(full_path, select=True)
    return {
        "status": "ok",
        "message": "Opened Explorer on the server PC",
        "path": str(full_path),
    }


@app.post("/api/results/reveal")
async def reveal_results_dir():
    results_dir = _results_dir_path()
    if not results_dir.exists():
        raise HTTPException(status_code=404, detail="Results directory not found")
    _open_in_explorer(results_dir)
    return {
        "status": "ok",
        "message": "Opened results directory on the server PC",
        "path": str(results_dir),
    }


@app.get("/api/results/{file_path:path}")
async def get_result(file_path: str):
    full_path = _resolve_result_path(file_path)
    return _read_result_preview(full_path)


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
    clear_dns_cache = False
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
        updates["SESSION_SPLIT_MODE"] = data.session_split_mode
    if data.disable_reverse_dns is not None:
        updates["DISABLE_REVERSE_DNS"] = str(bool(data.disable_reverse_dns)).lower()
        clear_dns_cache = True
    if data.columns:
        for k, v in data.columns.items():
            updates[f"COLUMN_{k.upper()}"] = str(v).lower()
    if data.aggregation:
        for k, v in data.aggregation.items():
            updates[f"AGGREGATE_{k.upper()}"] = str(v).lower()
    if updates:
        update_env_file(updates)
        if clear_dns_cache:
            clear_hostname_cache()
            configure_reverse_dns(not bool(data.disable_reverse_dns))
            logger.info("Reverse DNS cache cleared after settings update")
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
