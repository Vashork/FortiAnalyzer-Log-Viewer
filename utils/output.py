from pathlib import Path


def save_results(text: str, path: Path) -> None:
    """
    Сохраняет текст в указанный файл, создавая директорию при необходимости.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
