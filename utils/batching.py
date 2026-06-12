from typing import Iterable


def group_target_ips(target_ips: Iterable[str], group_size: int = 1) -> list[list[str]]:
    """Split target IPs into ordered batches; group_size<=1 preserves legacy one-IP batches."""
    ips = list(target_ips)
    if group_size <= 1:
        return [[ip] for ip in ips]
    return [ips[index:index + group_size] for index in range(0, len(ips), group_size)]
