from backend.app.models import Alert
from backend.app.security.rate_limit_detector import (
    check_rate_limit,
    rate_limit_tracker,
    reset_rate_limit,
)


def setup_function():
    """
    Reset the in-memory tracker before each test.
    """

    reset_rate_limit()

    rate_limit_tracker.config.max_requests = 3
    rate_limit_tracker.config.window_seconds = 60.0


def teardown_function():
    """
    Restore the default prototype configuration.
    """

    reset_rate_limit()

    rate_limit_tracker.config.max_requests = 10
    rate_limit_tracker.config.window_seconds = 60.0


def test_requests_within_limit_do_not_create_alert(db_session):
    for _ in range(3):
        alert = check_rate_limit(
            db=db_session,
            key="userA",
            src_ip="127.0.0.1",
            user_id="userA",
            method="GET",
            path="/api/profile",
        )

        assert alert is None

    alerts = db_session.query(Alert).all()

    assert len(alerts) == 0


def test_request_above_limit_creates_rate_limit_alert(
    db_session,
):
    for _ in range(3):
        check_rate_limit(
            db=db_session,
            key="userA",
            src_ip="127.0.0.1",
            user_id="userA",
            method="GET",
            path="/api/profile",
        )

    alert = check_rate_limit(
        db=db_session,
        key="userA",
        src_ip="127.0.0.1",
        user_id="userA",
        method="GET",
        path="/api/profile",
    )

    assert alert is not None
    assert alert.alert_type == "RATE_LIMIT"
    assert alert.severity == "MEDIUM"

    alerts = db_session.query(Alert).all()

    assert len(alerts) == 1


def test_rate_limit_is_tracked_per_key(db_session):
    for _ in range(3):
        check_rate_limit(
            db=db_session,
            key="userA",
            src_ip="127.0.0.1",
            user_id="userA",
            method="GET",
            path="/api/profile",
        )

    # userB has a separate counter.
    alert = check_rate_limit(
        db=db_session,
        key="userB",
        src_ip="127.0.0.2",
        user_id="userB",
        method="GET",
        path="/api/profile",
    )

    assert alert is None

    alerts = db_session.query(Alert).all()

    assert len(alerts) == 0


def test_rate_limit_alert_contains_evidence(db_session):
    for _ in range(4):
        check_rate_limit(
            db=db_session,
            key="userA",
            src_ip="127.0.0.1",
            user_id="userA",
            method="GET",
            path="/api/profile",
        )

    alert = (
        db_session.query(Alert)
        .filter(Alert.alert_type == "RATE_LIMIT")
        .first()
    )

    assert alert is not None
    assert alert.destination == "/api/profile"

    assert "request_count" in alert.evidence
    assert "max_requests" in alert.evidence
    assert "window_seconds" in alert.evidence