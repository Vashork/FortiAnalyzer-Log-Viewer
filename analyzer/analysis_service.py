from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from analyzer.log_analyzer import analyze_logs, analyze_policyid_logs
from client.faz_client import FortiAnalyzerClient
from config import BATCH_SIZE, MAX_WORKERS, TARGET_GROUP_SIZE
from utils.batching import group_target_ips
from utils.output import save_results


ClientFactory = Callable[[], Any]
ProgressCallback = Callable[[str], None]
HistoryCallback = Callable[[str, str, str, str, str], None]


@dataclass(frozen=True)
class AnalysisServiceConfig:
    """Runtime knobs shared by CLI and future Web orchestration adapters."""

    batch_size: int = BATCH_SIZE
    max_workers: int = MAX_WORKERS
    target_group_size: int = TARGET_GROUP_SIZE


@dataclass(frozen=True)
class AnalysisRunContext:
    start_time: str
    end_time: str
    target_ips: list[str]
    exclude_ips: set[str] = field(default_factory=set)
    ports: Optional[list[str]] = None
    cmd: str = ""


@dataclass(frozen=True)
class AnalysisRunOptions:
    columns: Any = None
    aggregation: Any = None
    progress: Optional[Callable[..., None]] = None
    smart_action: Optional[str] = None
    filter_mode: Optional[str] = None


@dataclass(frozen=True)
class SavedResult:
    name: str
    path: Path
    text: str


@dataclass(frozen=True)
class AnalysisServiceResult:
    files: list[SavedResult]
    texts: dict[str, str]


class AnalysisService:
    """Shared orchestration for FAZ direction/policy analyses.

    The service keeps the analyzer/client invocation rules in one place. CLI uses
    it directly today; Web can incrementally move to this service through a thin
    adapter without changing its request/response contracts.
    """

    def __init__(
        self,
        *,
        client_factory: ClientFactory = FortiAnalyzerClient.from_env,
        config: Optional[AnalysisServiceConfig] = None,
        progress: Optional[ProgressCallback] = None,
    ):
        self.client_factory = client_factory
        self.config = config or AnalysisServiceConfig()
        self.progress = progress or (lambda _message: None)

    def _log(self, message: str) -> None:
        self.progress(message)

    def run_direction_group(
        self,
        *,
        ip_group: list[str],
        direction: str,
        context: AnalysisRunContext,
        options: Optional[AnalysisRunOptions] = None,
    ) -> dict:
        options = options or AnalysisRunOptions()
        client = self.client_factory()
        if not client.login():
            raise RuntimeError("FAZ login failed")

        try:
            return analyze_logs(
                client=client,
                target_ips=ip_group,
                direction=direction,
                start_time=context.start_time,
                end_time=context.end_time,
                exclude_ips=list(context.exclude_ips),
                batch_size=self.config.batch_size,
                ports=context.ports,
                columns=options.columns,
                aggregation=options.aggregation,
                progress=options.progress,
                smart_action=options.smart_action,
                filter_mode=options.filter_mode,
            )
        finally:
            client.logout()

    def run_policyid_text(
        self,
        *,
        context: AnalysisRunContext,
        policyid: int,
        options: Optional[AnalysisRunOptions] = None,
    ) -> str:
        options = options or AnalysisRunOptions()
        client = self.client_factory()
        if not client.login():
            raise RuntimeError("FAZ login failed")

        try:
            return analyze_policyid_logs(
                client=client,
                target_ips=context.target_ips,
                policyid=policyid,
                start_time=context.start_time,
                end_time=context.end_time,
                exclude_ips=list(context.exclude_ips),
                batch_size=self.config.batch_size,
                ports=context.ports,
                columns=options.columns,
                aggregation=options.aggregation,
                progress=options.progress,
                smart_action=options.smart_action,
                filter_mode=options.filter_mode,
            )
        finally:
            client.logout()

    def run_direction(
        self,
        *,
        context: AnalysisRunContext,
        directions: Iterable[str],
        results_dir: Path,
        history_callback: Optional[HistoryCallback] = None,
        workers: Optional[int] = None,
    ) -> AnalysisServiceResult:
        directions = list(directions)
        target_groups = group_target_ips(context.target_ips, self.config.target_group_size)
        worker_count = workers or self.config.max_workers
        self._log(
            f"Target groups: {len(target_groups)} "
            f"(TARGET_GROUP_SIZE={max(1, self.config.target_group_size)})"
        )

        direction_text = {direction: [] for direction in directions}
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = []
            for direction in directions:
                for ip_group in target_groups:
                    futures.append(
                        executor.submit(
                            self.run_direction_group,
                            ip_group=ip_group,
                            direction=direction,
                            context=context,
                        )
                    )

            for future in as_completed(futures):
                reports = future.result() or {}
                for (_, direction), text in reports.items():
                    if text.strip():
                        direction_text[direction].append(text)

        return self._save_direction_results(
            direction_text=direction_text,
            context=context,
            results_dir=results_dir,
            history_callback=history_callback,
        )

    def run_policyid(
        self,
        *,
        context: AnalysisRunContext,
        policyid: int,
        results_dir: Path,
        history_callback: Optional[HistoryCallback] = None,
    ) -> AnalysisServiceResult:
        text = self.run_policyid_text(context=context, policyid=policyid)

        text = text if text.strip() else "NO DATA\n"
        outfile = results_dir / f"policy_{policyid}.txt"
        return self._save_text(
            text=text,
            name=f"policy_{policyid}",
            outfile=outfile,
            context=context,
            history_callback=history_callback,
            history_cmd=f"policyid={policyid}",
        )

    def _save_direction_results(
        self,
        *,
        direction_text: dict[str, list[str]],
        context: AnalysisRunContext,
        results_dir: Path,
        history_callback: Optional[HistoryCallback],
    ) -> AnalysisServiceResult:
        files: list[SavedResult] = []
        texts: dict[str, str] = {}
        for direction, chunks in direction_text.items():
            text = "\n\n".join(chunks) if chunks else "NO DATA\n"
            outfile = results_dir / f"{direction}.txt"
            result = self._save_text(
                text=text,
                name=direction,
                outfile=outfile,
                context=context,
                history_callback=history_callback,
                history_cmd=f"direction={direction}",
            )
            files.extend(result.files)
            texts.update(result.texts)
        return AnalysisServiceResult(files=files, texts=texts)

    def _save_text(
        self,
        *,
        text: str,
        name: str,
        outfile: Path,
        context: AnalysisRunContext,
        history_callback: Optional[HistoryCallback],
        history_cmd: str,
    ) -> AnalysisServiceResult:
        outfile.parent.mkdir(parents=True, exist_ok=True)
        save_results(text, outfile)
        if history_callback:
            history_callback(text, context.start_time, context.end_time, context.cmd or history_cmd, outfile.name)
        saved = SavedResult(name=name, path=outfile, text=text)
        return AnalysisServiceResult(files=[saved], texts={name: text})
