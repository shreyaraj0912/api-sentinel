from backend.app.detection.bfla import detect_bfla
from backend.app.detection.engine import run_detections
from backend.app.models import Alert


def test_admin_can_delete_user_without_bfla_alert(db_session):
    """
    ADMIN should be allowed to perform the protected DELETE
    operation.
    """

    result = detect_bfla(
        db=db_session,
        user_id="adminUser",
        role="ADMIN",
        method="DELETE",
        path="/api/users/10",
        src_ip="127.0.0.1",
    )

    assert result is None

    alerts = db_session.query(Alert).all()

    assert len(alerts) == 0


def test_user_cannot_delete_user(db_session):
    """
    A normal USER should not be allowed to perform the
    protected DELETE operation.
    """

    result = detect_bfla(
        db=db_session,
        user_id="userA",
        role="USER",
        method="DELETE",
        path="/api/users/10",
        src_ip="127.0.0.1",
    )

    assert result is not None
    assert result.alert_type == "BFLA"
    assert result.severity == "HIGH"

    alerts = db_session.query(Alert).all()

    assert len(alerts) == 1


def test_user_can_access_parameterized_get_endpoint(
    db_session,
):
    """
    A USER should be allowed to access the parameterized
    GET /api/users/{id} endpoint.
    """

    result = detect_bfla(
        db=db_session,
        user_id="userA",
        role="USER",
        method="GET",
        path="/api/users/103",
        src_ip="127.0.0.1",
    )

    assert result is None

    alerts = db_session.query(Alert).all()

    assert len(alerts) == 0


def test_unknown_role_is_not_granted_admin_operation(
    db_session,
):
    """
    An unknown role should not automatically receive
    permission to perform an ADMIN-only operation.
    """

    result = detect_bfla(
        db=db_session,
        user_id="unknownUser",
        role="UNKNOWN",
        method="DELETE",
        path="/api/users/10",
        src_ip="127.0.0.1",
    )

    assert result is not None
    assert result.alert_type == "BFLA"

    alerts = db_session.query(Alert).all()

    assert len(alerts) == 1


def test_network_only_event_does_not_trigger_bfla(
    db_session,
):
    """
    Network-only telemetry without application/security
    context should not trigger BFLA.
    """

    alerts_created = run_detections(
        db=db_session,
        user_id=None,
        role=None,
        method=None,
        path=None,
        object_id=None,
        src_ip="10.0.2.15",
    )

    assert alerts_created == []

    alerts = db_session.query(Alert).all()

    assert len(alerts) == 0