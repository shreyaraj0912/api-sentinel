from backend.app.detection.bola import detect_bola
from backend.app.detection.engine import run_detections
from backend.app.models import Alert


def test_user_cannot_access_another_users_object(db_session):
    """
    User A should receive a BOLA alert when attempting to
    access an object owned by User B.
    """

    result = detect_bola(
        db=db_session,
        user_id="userA",
        object_id="201",
        owned_object_ids={"101", "102"},
        path="/api/users/201",
        src_ip="127.0.0.1",
    )

    assert result is not None
    assert result.alert_type == "BOLA"
    assert result.severity == "HIGH"

    alerts = db_session.query(Alert).all()

    assert len(alerts) == 1


def test_user_b_can_access_own_object_without_alert(db_session):
    """
    User B should not receive a BOLA alert when accessing
    an object included in User B's ownership set.
    """

    result = detect_bola(
        db=db_session,
        user_id="userB",
        object_id="201",
        owned_object_ids={"201", "202"},
        path="/api/users/201",
        src_ip="127.0.0.1",
    )

    assert result is None

    alerts = db_session.query(Alert).all()

    assert len(alerts) == 0


def test_unknown_user_is_treated_as_having_no_owned_objects(
    db_session,
):
    """
    An unknown user should not automatically gain access to
    an object. The prototype ownership model treats the user
    as having an empty ownership set.
    """

    alerts_before = db_session.query(Alert).count()

    alerts_created = run_detections(
        db=db_session,
        user_id="unknownUser",
        role=None,
        method="GET",
        path="/api/users/999",
        object_id="999",
        src_ip="127.0.0.1",
    )

    assert any(
        alert.alert_type == "BOLA"
        for alert in alerts_created
    )

    alerts_after = db_session.query(Alert).count()

    assert alerts_after == alerts_before + 1


def test_network_only_event_does_not_trigger_bola(
    db_session,
):
    """
    A network-only event without user/object/path context
    should not produce a BOLA alert.
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