import os
from pathlib import Path
from dotenv import load_dotenv

# Корень проекта
PROJECT_ROOT = Path(__file__).parent

# Пути к ресурсам
RESOURCES_DIR = str(PROJECT_ROOT / "resources")
MACHINES_FILE = str(PROJECT_ROOT / "resources" / "machines.txt")
INTERNAL_IPS_FILE = str(PROJECT_ROOT / "resources" / "internal_ips.txt")
PORTS_FILE = str(PROJECT_ROOT / "resources" / "ports.txt")

# Директория логов
LOGS_DIR = str(PROJECT_ROOT / "logs")

load_dotenv()


def reload_env():
    """Перечитать .env без перезапуска сервера."""
    env_path = PROJECT_ROOT / ".env"
    if env_path.exists():
        load_dotenv(env_path, override=True)


# FortiAnalyzer credentials
FORTIANALYZER_URL = os.getenv("FORTIANALYZER_URL")
FORTIANALYZER_USERNAME = os.getenv("FORTIANALYZER_USERNAME")
FORTIANALYZER_PASSWORD = os.getenv("FORTIANALYZER_PASSWORD")

# Default search intervals
DEFAULT_TIME_RANGE_HOURS = int(os.getenv("DEFAULT_TIME_RANGE_HOURS", 24))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", 100))

# Output directory
RESULTS_DIR = os.getenv("RESULTS_DIR", "results")

# Performance tuning
MAX_WORKERS = int(os.getenv("MAX_WORKERS", 1))

# Лимит подряд идущих пустых батчей при fetch_logs
EMPTY_BATCH_LIMIT = int(os.getenv("EMPTY_BATCH_LIMIT", 5))


def _get_bool(name: str, default: str = "false") -> bool:
    """Чтение булевых флагов из .env (true/false/yes/no/1/0)."""
    val = os.getenv(name, default)
    if val is None:
        return False
    return val.strip().lower() in ("1", "true", "yes", "y", "on")


# Smart-фильтрация по полю action/smart_action
SMART_ACTION = os.getenv("SMART_ACTION", "all").strip().lower()
if SMART_ACTION not in ("all", "deny", "all-accept"):
    SMART_ACTION = "all-accept"

# Где применять smart_action: "faz" (в FAZ) или "local" (в Python)
FILTER_MODE = os.getenv("FILTER_MODE", "FAZ").strip().lower()
if FILTER_MODE not in ("faz", "local"):
    FILTER_MODE = "faz"

# Конфигурация колонок для отчёта
COLUMNS_CONFIG = {
    "connections": _get_bool("COLUMN_CONNECTIONS", "true"),
    "action": _get_bool("COLUMN_ACTION", "false"),
    "policyid": _get_bool("COLUMN_POLICYID", "false"),
    "app": _get_bool("COLUMN_APP", "false"),
    "srcintf": _get_bool("COLUMN_SRCINTF", "false"),
    "dstintf": _get_bool("COLUMN_DSTINTF", "false"),
    "policyname": _get_bool("COLUMN_POLICYNAME", "false"),
    "devname": _get_bool("COLUMN_DEVNAME", "false"),
}

# Максимальная длительность одного FAZ-search task в часах.
MAX_TASK_HOURS = int(os.getenv("MAX_TASK_HOURS", "4"))

# Максимальное количество логов, которые мы готовы вытянуть для одного task.
MAX_MATCHED_LOGS_PER_TASK = int(os.getenv("MAX_MATCHED_LOGS_PER_TASK", "200000"))

# Адаптивное ограничение воркеров
ADAPTIVE_WORKER_THRESHOLD_HOURS = int(os.getenv("ADAPTIVE_WORKER_THRESHOLD_HOURS", "24"))


def get_dynamic_workers() -> int:
    """Динамическое чтение текущего значения MAX_WORKERS из .env."""
    reload_env()
    return int(os.getenv("MAX_WORKERS", 1))


def get_dynamic_batch_size() -> int:
    """Динамическое чтение BATCH_SIZE из .env."""
    reload_env()
    return int(os.getenv("BATCH_SIZE", 100))


def get_dynamic_max_task_hours() -> int:
    """Динамическое чтение MAX_TASK_HOURS из .env."""
    reload_env()
    return int(os.getenv("MAX_TASK_HOURS", 4))


def get_dynamic_max_matched_logs() -> int:
    """Динамическое чтение MAX_MATCHED_LOGS_PER_TASK из .env."""
    reload_env()
    return int(os.getenv("MAX_MATCHED_LOGS_PER_TASK", 200000))


def ensure_directories():
    """Создать необходимые директории если их нет."""
    Path(RESULTS_DIR).mkdir(parents=True, exist_ok=True)
    Path(LOGS_DIR).mkdir(parents=True, exist_ok=True)
    Path(RESOURCES_DIR).mkdir(parents=True, exist_ok=True)


def validate_config():
    reload_env()
    url = os.getenv("FORTIANALYZER_URL")
    user = os.getenv("FORTIANALYZER_USERNAME")
    pwd = os.getenv("FORTIANALYZER_PASSWORD")
    if not all([url, user, pwd]):
        raise ValueError(
            "Missing required .env variables: "
            "FORTIANALYZER_URL, FORTIANALYZER_USERNAME, FORTIANALYZER_PASSWORD"
        )
