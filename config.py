import os
from datetime import datetime, timedelta
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
MAX_WORKERS = int(os.getenv("MAX_WORKERS", 2))

def validate_config():
    if not all([FORTIANALYZER_URL, FORTIANALYZER_USERNAME, FORTIANALYZER_PASSWORD]):
        raise ValueError(
            "Missing required .env variables: "
            "FORTIANALYZER_URL, FORTIANALYZER_USERNAME, FORTIANALYZER_PASSWORD"
        )
