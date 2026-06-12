import unittest
from unittest.mock import patch

from web.analysis_scheduler import SchedulerEmitter, WorkerRef


class ProgressThrottlingTests(unittest.TestCase):
    def worker(self):
        return WorkerRef(
            worker_id="w1",
            label="W1",
            slot_key="slot-1",
            direction="outbound",
            target_ip="10.0.0.10",
        )

    def test_fetch_progress_is_throttled_by_percentage_step_but_keeps_final_event(self):
        emitted = []
        emitter = SchedulerEmitter(emitted.append, monotonic=lambda: 0.0)
        worker = self.worker()

        with patch.dict(
            "os.environ",
            {
                "PROGRESS_MIN_PERCENT_STEP": "10",
                "PROGRESS_MIN_INTERVAL_SECONDS": "999",
            },
        ):
            for pct in (0, 1, 5, 9, 10, 19, 20, 99, 100):
                emitter.fetch_progress(worker, fetched=pct, total=100, pct=pct)

        self.assertEqual([event["pct"] for event in emitted], [0, 10, 20, 99, 100])
        self.assertTrue(all(event["type"] == "fetch_progress" for event in emitted))

    def test_fetch_progress_time_fallback_emits_during_long_running_same_step(self):
        emitted = []
        now = iter([0.0, 1.0, 2.0, 2.5, 4.0])
        emitter = SchedulerEmitter(emitted.append, monotonic=lambda: next(now))
        worker = self.worker()

        with patch.dict(
            "os.environ",
            {
                "PROGRESS_MIN_PERCENT_STEP": "100",
                "PROGRESS_MIN_INTERVAL_SECONDS": "2",
            },
        ):
            for pct in (0, 1, 2, 3, 4):
                emitter.fetch_progress(worker, fetched=pct, total=100, pct=pct)

        self.assertEqual([event["pct"] for event in emitted], [0, 2, 4])

    def test_fetch_progress_resets_when_same_worker_starts_new_task(self):
        emitted = []
        emitter = SchedulerEmitter(emitted.append, monotonic=lambda: 0.0)
        worker = self.worker()

        with patch.dict(
            "os.environ",
            {
                "PROGRESS_MIN_PERCENT_STEP": "10",
                "PROGRESS_MIN_INTERVAL_SECONDS": "999",
            },
        ):
            emitter.fetch_progress(worker, fetched=100, total=100, pct=100)
            emitter.fetch_progress(worker, fetched=1, total=100, pct=1)

        self.assertEqual([event["pct"] for event in emitted], [100, 1])

    def test_non_progress_events_are_not_throttled(self):
        emitted = []
        emitter = SchedulerEmitter(emitted.append, monotonic=lambda: 0.0)
        worker = self.worker()

        with patch.dict("os.environ", {"PROGRESS_MIN_PERCENT_STEP": "100"}):
            emitter.message("first", worker=worker)
            emitter.message("second", worker=worker)
            emitter.worker_finished(worker, "done")

        self.assertEqual([event["type"] for event in emitted], ["message", "message", "worker_finished"])
        self.assertEqual([event.get("message") for event in emitted], ["first", "second", "done"])


if __name__ == "__main__":
    unittest.main()
