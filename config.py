import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

FORTIANALYZER_URL = os.getenv("FORTIANALYZER_URL")
FORTIANALYZER_USERNAME = os.getenv("FORTIANALYZER_USERNAME")
FORTIANALYZER_PASSWORD = os.getenv("FORTIANALYZER_PASSWORD")
DEFAULT_TIME_RANGE_HOURS = int(os.getenv("DEFAULT_TIME_RANGE_HOURS", 24))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", 100))


def validate_config():
    if not all([FORTIANALYZER_URL, FORTIANALYZER_USERNAME, FORTIANALYZER_PASSWORD]):
        raise ValueError(
            "Missing required .env variables: "
            "FORTIANALYZER_URL, FORTIANALYZER_USERNAME, FORTIANALYZER_PASSWORD"
        )