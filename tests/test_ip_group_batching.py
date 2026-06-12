import unittest

from utils.batching import group_target_ips


class IpGroupBatchingTests(unittest.TestCase):
    def test_group_target_ips_default_one_keeps_single_ip_batches(self):
        groups = group_target_ips(["10.0.0.1", "10.0.0.2"], group_size=1)

        self.assertEqual(groups, [["10.0.0.1"], ["10.0.0.2"]])

    def test_group_target_ips_batches_by_requested_size(self):
        groups = group_target_ips(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"], group_size=2)

        self.assertEqual(
            groups,
            [
                ["10.0.0.1", "10.0.0.2"],
                ["10.0.0.3", "10.0.0.4"],
                ["10.0.0.5"],
            ],
        )

    def test_group_target_ips_treats_invalid_size_as_one_for_compatibility(self):
        groups = group_target_ips(["10.0.0.1", "10.0.0.2"], group_size=0)

        self.assertEqual(groups, [["10.0.0.1"], ["10.0.0.2"]])


if __name__ == "__main__":
    unittest.main()
