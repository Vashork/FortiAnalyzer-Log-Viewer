import os
from datetime import datetime, timedelta  # сейчас не используется, оставим на будущее
from dotenv import load_dotenv

load_dotenv()

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
    # по умолчанию — только "чистые" accept'ы
    SMART_ACTION = "all-accept"

# Где применять smart_action: "faz" (в FAZ) или "local" (в Python)
FILTER_MODE = os.getenv("FILTER_MODE", "FAZ").strip().lower()
if FILTER_MODE not in ("faz", "local"):
    FILTER_MODE = "faz"

# Конфигурация колонок для отчёта
COLUMNS_CONFIG = {
    # Главная колонка количества соединений
    "connections": _get_bool("COLUMN_CONNECTIONS", "true"),

    # Дополнительные колонки
    "action": _get_bool("COLUMN_ACTION", "false"),
    "policyid": _get_bool("COLUMN_POLICYID", "false"),
    "app": _get_bool("COLUMN_APP", "false"),
    "srcintf": _get_bool("COLUMN_SRCINTF", "false"),
    "dstintf": _get_bool("COLUMN_DSTINTF", "false"),
    "policyname": _get_bool("COLUMN_POLICYNAME", "false"),
    "devname": _get_bool("COLUMN_DEVNAME", "false"),
    # нижние флаги пока зарезервированы под детализированный вывод сырых логов
    # "srcip": _get_bool("COLUMN_SRCIP", "false"),
    # "dstip": _get_bool("COLUMN_DSTIP", "false"),
    # "srcport": _get_bool("COLUMN_SRCPORT", "false"),
    # "dstport": _get_bool("COLUMN_DSTPORT", "false"),
    # "proto": _get_bool("COLUMN_PROTO", "false"),
}

# Максимальная длительность одного FAZ-search task в часах.
# Если 0 → нарезка по времени отключена.
MAX_TASK_HOURS = int(os.getenv("MAX_TASK_HOURS", "4"))

# Максимальное количество логов, которые мы готовы вытянуть для одного task.
# Если 0 → без лимита (может быть тяжело для FAZ).
MAX_MATCHED_LOGS_PER_TASK = int(os.getenv("MAX_MATCHED_LOGS_PER_TASK", "200000"))

# Если общее временное окно (start→end) >= этого порога (часов),
# то принудительно уменьшаем число воркеров до 1, чтобы не душить FAZ.
# Если 0 → адаптивное ограничение выключено.
ADAPTIVE_WORKER_THRESHOLD_HOURS = int(os.getenv("ADAPTIVE_WORKER_THRESHOLD_HOURS", "24"))


def validate_config():
    if not all([FORTIANALYZER_URL, FORTIANALYZER_USERNAME, FORTIANALYZER_PASSWORD]):
        raise ValueError(
            "Missing required .env variables: "
            "FORTIANALYZER_URL, FORTIANALYZER_USERNAME, FORTIANALYZER_PASSWORD"
        )
