import unittest

from web.job_registry import JobRegistry


class JobRegistryTests(unittest.TestCase):
    def test_registry_rejects_job_when_active_limit_is_reached_until_finish(self):
        registry = JobRegistry(max_active=2)

        self.assertTrue(registry.start("job-1"))
        self.assertTrue(registry.start("job-2"))
        self.assertFalse(registry.start("job-3"))

        registry.finish("job-1")

        self.assertTrue(registry.start("job-3"))
        self.assertEqual(registry.active_count, 2)

    def test_registry_tracks_cancel_flags_and_cleans_up_on_finish(self):
        registry = JobRegistry(max_active=1)

        self.assertTrue(registry.start("job-1"))
        self.assertFalse(registry.is_cancelled("job-1"))

        self.assertTrue(registry.cancel("job-1"))
        self.assertTrue(registry.is_cancelled("job-1"))

        registry.finish("job-1")

        self.assertFalse(registry.is_active("job-1"))
        self.assertFalse(registry.is_cancelled("job-1"))
        self.assertEqual(registry.active_count, 0)

    def test_cancel_unknown_job_returns_false(self):
        registry = JobRegistry(max_active=1)

        self.assertFalse(registry.cancel("missing"))


if __name__ == "__main__":
    unittest.main()
