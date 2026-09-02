from backend.app.detection.bfla import detect_bfla
from backend.app.detection.bola import detect_bola
from backend.app.detection.shadow_api import detect_shadow_api
from backend.app.models import Alert


# =========================================================
# BOLA TESTS
# =========================================================


def test_bola_allowed_object_does_not_create_alert(db_session):
    """
    A user accessing an object they own should not
    generate a BOLA alert.
    """

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
    """
    A user accessing an object outside their ownership
    set should generate a BOLA alert.
    """

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


# =========================================================
# BFLA TESTS
# =========================================================


def test_bfla_allowed_operation_does_not_create_alert(db_session):
    """
    A USER accessing an endpoint permitted to USER should
    not generate a BFLA alert.
    """

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
    """
    A normal USER attempting an ADMIN-only operation
    should generate a BFLA alert.
    """

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


def test_bfla_admin_can_delete_user(db_session):
    """
    An ADMIN should be permitted to DELETE a specific user.
    """

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
    """
    A normal USER should not be allowed to DELETE a user.
    """

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
    assert result.severity == "HIGH"

    alerts = db_session.query(Alert).all()

    assert len(alerts) == 1


def test_bfla_user_can_get_specific_user(db_session):
    """
    GET /api/users/{id} is a normal USER operation in
    our prototype and should not create a BFLA alert.
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


# =========================================================
# SHADOW API TESTS
# =========================================================


def test_shadow_api_known_endpoint_does_not_create_alert(db_session):
    """
    A documented endpoint should not generate a Shadow API alert.
    """

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


def test_shadow_api_known_parameterized_endpoint_does_not_create_alert(
    db_session,
):
    """
    /api/users/103 should match the documented
    /api/users/{id} endpoint pattern.
    """

    known_apis = {
        ("GET", "/api/users"),
        ("GET", "/api/users/{id}"),
        ("POST", "/api/login"),
    }

    result = detect_shadow_api(
        db=db_session,
        method="GET",
        path="/api/users/103",
        known_apis=known_apis,
        src_ip="127.0.0.1",
    )

    assert result is None

    alerts = db_session.query(Alert).all()

    assert len(alerts) == 0


def test_shadow_api_unknown_endpoint_creates_alert(db_session):
    """
    An endpoint that is not in the known/documented API
    set should generate a Shadow API alert.
    """

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