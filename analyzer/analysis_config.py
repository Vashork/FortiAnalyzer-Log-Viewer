from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Optional


@dataclass(frozen=True)
class AnalysisConfig:
    """Immutable per-analysis configuration snapshot.

    Web requests must pass an instance of this instead of mutating module-level
    config globals. Mapping fields are copied on creation and wrapped in
    MappingProxyType so later request/UI dict mutations cannot leak into a
    running analysis.
    """

    smart_action: str
    filter_mode: str
    columns: Mapping[str, bool]
    aggregation: Mapping[str, bool]

    @classmethod
    def from_request(cls, request, filter_mode: str = "faz") -> "AnalysisConfig":
        return cls(
            smart_action=_normalize_smart_action(getattr(request, "smart_action", "all")),
            filter_mode=_normalize_filter_mode(filter_mode),
            columns=MappingProxyType(dict(getattr(request, "columns", None) or {})),
            aggregation=MappingProxyType(dict(getattr(request, "aggregation", None) or {})),
        )


def _normalize_smart_action(value: Optional[str]) -> str:
    normalized = (value or "all").strip().lower()
    return normalized if normalized in ("all", "deny", "all-accept") else "all"


def _normalize_filter_mode(value: Optional[str]) -> str:
    normalized = (value or "faz").strip().lower()
    return normalized if normalized in ("faz", "local") else "faz"
