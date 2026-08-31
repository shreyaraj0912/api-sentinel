from backend.app.detection.bfla import detect_bfla
from backend.app.detection.bola import detect_bola
from backend.app.detection.shadow_api import detect_shadow_api
from backend.app.models import Alert


def test_bola_allowed_object_does_not_create_alert(db_session):
    result = detect_bola(
        db=db_session,
        user_id="userA",
        object_id="101",
        owned_object_ids={"101", "102"},
        path="/api/users/101",
        src_ip="192.168.1.10",
    )

    assert result is None

    alerts = db_session.query(Alert).all()

    assert len(alerts) == 0


def test_bola_unauthorized_object_creates_alert(db_session):
    result = detect_bola(
        db=db_session,
        user_id="userA",
        object_id="103",
        owned_object_ids={"101", "102"},
        path="/api/users/103",
        src_ip="192.168.1.10",
    )

    assert result is not None
    assert result.alert_type == "BOLA"
    assert result.severity == "HIGH"

    alerts = db_session.query(Alert).all()

    assert len(alerts) == 1


def test_bfla_allowed_operation_does_not_create_alert(db_session):
    result = detect_bfla(
        db=db_session,
        user_id="userA",
        role="USER",
        method="GET",
        path="/api/profile",
        src_ip="192.168.1.10",
    )

    assert result is None

    alerts = db_session.query(Alert).all()

    assert len(alerts) == 0


def test_bfla_unauthorized_operation_creates_alert(db_session):
    result = detect_bfla(
        db=db_session,
        user_id="userA",
        role="USER",
        method="DELETE",
        path="/api/users",
        src_ip="192.168.1.10",
    )

    assert result is not None
    assert result.alert_type == "BFLA"
    assert result.severity == "HIGH"

    alerts = db_session.query(Alert).all()

    assert len(alerts) == 1


def test_shadow_api_known_endpoint_does_not_create_alert(db_session):
    known_apis = {
        ("GET", "/api/users"),
        ("POST", "/api/login"),
    }

    result = detect_shadow_api(
        db=db_session,
        method="GET",
        path="/api/users",
        known_apis=known_apis,
        src_ip="192.168.1.10",
    )

    assert result is None

    alerts = db_session.query(Alert).all()

    assert len(alerts) == 0


def test_shadow_api_unknown_endpoint_creates_alert(db_session):
    known_apis = {
        ("GET", "/api/users"),
        ("POST", "/api/login"),
    }

    result = detect_shadow_api(
        db=db_session,
        method="GET",
        path="/api/internal/debug",
        known_apis=known_apis,
        src_ip="192.168.1.10",
    )

    assert result is not None
    assert result.alert_type == "SHADOW_API"
    assert result.severity == "MEDIUM"

    alerts = db_session.query(Alert).all()

    assert len(alerts) == 1

def test_bfla_admin_can_delete_user(db_session):
    result = detect_bfla(
        db=db_session,
        user_id="admin1",
        role="ADMIN",
        method="DELETE",
        path="/api/users/10",
        src_ip="192.168.1.10",
    )

    assert result is None

    alerts = db_session.query(Alert).all()

    assert len(alerts) == 0
def test_bfla_normal_user_cannot_delete_user(db_session):
    result = detect_bfla(
        db=db_session,
        user_id="userA",
        role="USER",
        method="DELETE",
        path="/api/users/10",
        src_ip="192.168.1.10",
    )

    assert result is not None
    assert result.alert_type == "BFLA"

    alerts = db_session.query(Alert).all()

    assert len(alerts) == 1