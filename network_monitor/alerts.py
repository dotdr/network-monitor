class HostAlertTracker:
    def __init__(self, failure_threshold: int = 2) -> None:
        if not 1 <= failure_threshold <= 20:
            raise ValueError("failure_threshold must be between 1 and 20.")
        self.failure_threshold = failure_threshold
        self._failure_counts: dict[int, int] = {}
        self._offline_hosts: set[int] = set()

    def record(self, host_id: int, success: bool) -> str | None:
        if success:
            self._failure_counts[host_id] = 0
            if host_id in self._offline_hosts:
                self._offline_hosts.remove(host_id)
                return "recovered"
            return None

        failures = self._failure_counts.get(host_id, 0) + 1
        self._failure_counts[host_id] = failures
        if failures >= self.failure_threshold and host_id not in self._offline_hosts:
            self._offline_hosts.add(host_id)
            return "offline"
        return None
