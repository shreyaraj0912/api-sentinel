from backend.app.security.rate_limiter import (
    RateLimitConfig,
    RateLimitTracker,
)


def test_requests_below_threshold_are_allowed():
    tracker = RateLimitTracker(
        RateLimitConfig(
            max_requests=3,
            window_seconds=60,
        )
    )

    assert tracker.record_request("userA") == 1
    assert tracker.record_request("userA") == 2
    assert tracker.record_request("userA") == 3

    assert tracker.is_exceeded("userA") is False


def test_request_above_threshold_is_detected():
    tracker = RateLimitTracker(
        RateLimitConfig(
            max_requests=3,
            window_seconds=60,
        )
    )

    tracker.record_request("userA")
    tracker.record_request("userA")
    tracker.record_request("userA")

    assert tracker.is_exceeded("userA") is False

    tracker.record_request("userA")

    assert tracker.is_exceeded("userA") is True


def test_rate_limit_is_tracked_per_key():
    tracker = RateLimitTracker(
        RateLimitConfig(
            max_requests=2,
            window_seconds=60,
        )
    )

    assert tracker.record_request("userA") == 1
    assert tracker.record_request("userA") == 2

    assert tracker.record_request("userB") == 1

    assert tracker.get_count("userA") == 2
    assert tracker.get_count("userB") == 1


def test_reset_single_key():
    tracker = RateLimitTracker(
        RateLimitConfig(
            max_requests=2,
            window_seconds=60,
        )
    )

    tracker.record_request("userA")
    tracker.record_request("userA")

    assert tracker.get_count("userA") == 2

    tracker.reset("userA")

    assert tracker.get_count("userA") == 0


def test_reset_all_keys():
    tracker = RateLimitTracker(
        RateLimitConfig(
            max_requests=2,
            window_seconds=60,
        )
    )

    tracker.record_request("userA")
    tracker.record_request("userB")

    tracker.reset()

    assert tracker.get_count("userA") == 0
    assert tracker.get_count("userB") == 0