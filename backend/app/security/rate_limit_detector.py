from time import monotonic

from sqlalchemy.orm import Session

from ..detection.alert_helper import create_alert
from .rate_limiter import (
    RateLimitConfig,
    RateLimitTracker,
)


DEFAULT_RATE_LIMIT_CONFIG = RateLimitConfig(
    max_requests=10,
    window_seconds=60.0,
)


rate_limit_tracker = RateLimitTracker(
    DEFAULT_RATE_LIMIT_CONFIG
)


# Tracks when a RATE_LIMIT alert was last generated
# for each rate-limit key.
#
# This prevents multiple alerts from being generated
# for the same request burst.
_last_alert_at: dict[str, float] = {}


def check_rate_limit(
    db: Session,
    *,
    key: str,
    src_ip: str | None = None,
    user_id: str | None = None,
    method: str | None = None,
    path: str | None = None,
):
    """
    Record one request and generate a RATE_LIMIT alert
    when the configured threshold is exceeded.

    Only one alert is generated for a given key during
    the configured rate-limit window.
    """

    request_count = rate_limit_tracker.record_request(
        key
    )

    max_requests = (
        rate_limit_tracker.config.max_requests
    )

    window_seconds = (
        rate_limit_tracker.config.window_seconds
    )

    # Threshold has not been exceeded.
    if request_count <= max_requests:
        return None

    now = monotonic()

    previous_alert = _last_alert_at.get(key)

    # A RATE_LIMIT alert has already been generated
    # during the current window.
    if (
        previous_alert is not None
        and now - previous_alert < window_seconds
    ):
        return None

    alert = create_alert(
        db=db,
        alert_type="RATE_LIMIT",
        severity="MEDIUM",
        src_ip=src_ip,
        destination=path,
        description=(
            "Request rate exceeded the configured "
            "threshold for the current time window."
        ),
        evidence={
            "key": key,
            "request_count": request_count,
            "max_requests": max_requests,
            "window_seconds": window_seconds,
            "user_id": user_id,
            "method": method,
            "path": path,
        },
    )

    # Record the alert time only after an alert was created.
    _last_alert_at[key] = now

    return alert


def reset_rate_limit(
    key: str | None = None,
) -> None:
    """
    Reset one rate-limit tracking key or all keys.

    Also clears the corresponding alert-deduplication state.
    """

    if key is None:
        rate_limit_tracker.reset()
        _last_alert_at.clear()
        return

    rate_limit_tracker.reset(key)
    _last_alert_at.pop(key, None)