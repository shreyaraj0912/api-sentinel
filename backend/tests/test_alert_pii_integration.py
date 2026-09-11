import json

from backend.app.models import Alert
from backend.app.routes.alerts import sanitize_alert


def test_alert_description_masks_email(db_session):
    alert = Alert(
        alert_type="BFLA",
        severity="HIGH",
        src_ip="127.0.0.1",
        destination="/api/users/10",
        description=(
            "User user@example.com with role USER "
            "attempted an unauthorized operation."
        ),
        evidence=json.dumps(
            {
                "user_id": "user@example.com",
                "role": "USER",
                "method": "DELETE",
                "path": "/api/users/10",
                "src_ip": "127.0.0.1",
            }
        ),
        status="OPEN",
    )

    sanitized = sanitize_alert(alert)

    assert "user@example.com" not in sanitized["description"]
    assert "u***@example.com" in sanitized["description"]

    evidence = json.loads(sanitized["evidence"])

    assert evidence["user_id"] == "u***@example.com"
    assert evidence["role"] == "USER"
    assert evidence["method"] == "DELETE"
    assert evidence["path"] == "/api/users/10"
    assert evidence["src_ip"] == "127.0.0.1"


def test_alert_without_pii_remains_unchanged(db_session):
    alert = Alert(
        alert_type="BOLA",
        severity="HIGH",
        src_ip="127.0.0.1",
        destination="/api/users/103",
        description="Unauthorized object access detected.",
        evidence=json.dumps(
            {
                "user_id": "userA",
                "object_id": "103",
                "path": "/api/users/103",
            }
        ),
        status="OPEN",
    )

    sanitized = sanitize_alert(alert)

    assert sanitized["description"] == (
        "Unauthorized object access detected."
    )

    evidence = json.loads(sanitized["evidence"])

    assert evidence["user_id"] == "userA"
    assert evidence["object_id"] == "103"
    assert evidence["path"] == "/api/users/103"