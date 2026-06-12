from dataclasses import dataclass
from threading import Lock
from time import time


@dataclass
class JobState:
    request_id: str
    created_at: float
    cancel_requested: bool = False


class JobRegistry:
    """Thread-safe active analysis job registry with a hard concurrency limit."""

    def __init__(self, max_active: int):
        self.max_active = max(1, max_active)
        self._jobs: dict[str, JobState] = {}
        self._lock = Lock()

    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._jobs)

    def start(self, request_id: str) -> bool:
        with self._lock:
            if request_id in self._jobs:
                return True
            if len(self._jobs) >= self.max_active:
                return False
            self._jobs[request_id] = JobState(request_id=request_id, created_at=time())
            return True

    def finish(self, request_id: str) -> None:
        with self._lock:
            self._jobs.pop(request_id, None)

    def cancel(self, request_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(request_id)
            if job is None:
                return False
            job.cancel_requested = True
            return True

    def is_cancelled(self, request_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(request_id)
            return bool(job and job.cancel_requested)

    def is_active(self, request_id: str) -> bool:
        with self._lock:
            return request_id in self._jobs
