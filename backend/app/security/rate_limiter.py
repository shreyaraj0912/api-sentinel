from collections import deque
from dataclasses import dataclass
from time import monotonic


@dataclass
class RateLimitConfig:
    """
    Configuration for the prototype rate limiter.
    """

    max_requests: int = 10
    window_seconds: float = 60.0


class RateLimitTracker:
    """
    Simple in-memory sliding-window request tracker.

    This is intended for the API-Sentinel MVP/prototype.
    It tracks request timestamps per key and determines
    whether the configured request threshold is exceeded.
    """

    def __init__(
        self,
        config: RateLimitConfig | None = None,
    ):
        self.config = config or RateLimitConfig()

        self._requests: dict[str, deque[float]] = {}

    def _cleanup(
        self,
        key: str,
        now: float,
    ) -> deque[float]:
        """
        Remove timestamps outside the configured window.
        """

        timestamps = self._requests.setdefault(
            key,
            deque(),
        )

        cutoff = now - self.config.window_seconds

        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()

        return timestamps

    def record_request(
        self,
        key: str,
    ) -> int:
        """
        Record one request and return the current
        request count within the configured time window.
        """

        now = monotonic()

        timestamps = self._cleanup(
            key,
            now,
        )

        timestamps.append(now)

        return len(timestamps)

    def is_exceeded(
        self,
        key: str,
    ) -> bool:
        """
        Return True when the request count for the key
        exceeds the configured threshold.
        """

        now = monotonic()

        timestamps = self._cleanup(
            key,
            now,
        )

        return len(timestamps) > self.config.max_requests

    def get_count(
        self,
        key: str,
    ) -> int:
        """
        Return the current request count for the key.
        """

        now = monotonic()

        timestamps = self._cleanup(
            key,
            now,
        )

        return len(timestamps)

    def reset(
        self,
        key: str | None = None,
    ) -> None:
        """
        Reset one key or all tracked keys.
        """

        if key is None:
            self._requests.clear()
            return

        self._requests.pop(key, None)