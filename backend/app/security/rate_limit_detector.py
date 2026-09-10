from sqlalchemy.orm import Session

from .rate_limiter import (
    RateLimitConfig,
    RateLimitTracker,
)
from ..detection.alert_helper import create_alert


# Default prototype configuration.
DEFAULT_RATE_LIMIT_CONFIG = RateLimitConfig(
    max_requests=10,
    window_seconds=60.0,
)


# One in-memory tracker for the running backend process.
rate_limit_tracker = RateLimitTracker(
    DEFAULT_RATE_LIMIT_CONFIG
)


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
    Record a request and generate a RATE_LIMIT alert
    when the configured threshold is exceeded.

    The key can represent a user, IP address, API client,
    or another identifier.
    """

    request_count = rate_limit_tracker.record_request(
        key
    )

    if request_count <= rate_limit_tracker.config.max_requests:
        return None

    return create_alert(
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
            "max_requests": (
                rate_limit_tracker.config.max_requests
            ),
            "window_seconds": (
                rate_limit_tracker.config.window_seconds
            ),
            "user_id": user_id,
            "method": method,
            "path": path,
        },
    )


def reset_rate_limit(
    key: str | None = None,
) -> None:
    """
    Reset one rate-limit tracking key or all keys.

    Primarily intended for testing and controlled resets.
    """

    rate_limit_tracker.reset(key)