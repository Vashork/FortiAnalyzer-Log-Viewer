import asyncio
import unittest

from web.app import _enqueue_progress_event


class ProgressQueueCoalescingTests(unittest.TestCase):
    def drain_queue(self, queue):
        items = []
        while not queue.empty():
            items.append(queue.get_nowait())
        return items

    def test_enqueue_progress_event_drops_oldest_non_terminal_when_queue_is_full(self):
        queue = asyncio.Queue(maxsize=2)
        _enqueue_progress_event(queue, {"type": "message", "message": "old"})
        _enqueue_progress_event(queue, {"type": "fetch_progress", "pct": 10})
        _enqueue_progress_event(queue, {"type": "fetch_progress", "pct": 20})

        self.assertEqual(
            self.drain_queue(queue),
            [
                {"type": "fetch_progress", "pct": 10},
                {"type": "fetch_progress", "pct": 20},
            ],
        )

    def test_enqueue_progress_event_preserves_terminal_event_when_queue_is_full(self):
        queue = asyncio.Queue(maxsize=1)
        _enqueue_progress_event(queue, {"type": "fetch_progress", "pct": 99})
        _enqueue_progress_event(queue, {"type": "done", "result": {"ok": True}})

        self.assertEqual(self.drain_queue(queue), [{"type": "done", "result": {"ok": True}}])


if __name__ == "__main__":
    unittest.main()
