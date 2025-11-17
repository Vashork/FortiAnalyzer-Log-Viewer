# utils/output.py

import os
from pathlib import Path
from typing import Dict


def save_results(text: str, path: str | Path) -> None:
    """
    Saves a single text report to the given file path.
    'text' MUST be a string.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        f.write(text)

    print(f"💾 Saved results to: {path.resolve()}")
