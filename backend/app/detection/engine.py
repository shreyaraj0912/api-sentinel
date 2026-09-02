from sqlalchemy.orm import Session

from .bfla import detect_bfla
from .bola import detect_bola
from .shadow_api import detect_shadow_api


# Prototype BOLA ownership data.
OWNED_OBJECTS = {
    "userA": {"101", "102"},
    "userB": {"201", "202"},
}


# Prototype documented APIs.
KNOWN_APIS = {
    ("GET", "/api/profile"),
    ("GET", "/api/users"),
    ("GET", "/api/users/{id}"),
    ("POST", "/api/login"),
    ("DELETE", "/api/users/{id}"),
}


def run_detections(
    db: Session,
    *,
    user_id: str | None,
    role: str | None,
    method: str | None,
    path: str | None,
    object_id: str | None,
    src_ip: str | None,
):
    """
    Run all applicable API-security detectors.

    Network-only events are accepted but do not trigger
    API-level detectors when the required context is absent.
    """

    alerts = []

    # =========================================================
    # BOLA
    # =========================================================

    if user_id and object_id and path:

        owned_objects = OWNED_OBJECTS.get(
            user_id,
            set(),
        )

        alert = detect_bola(
            db=db,
            user_id=user_id,
            object_id=object_id,
            owned_object_ids=owned_objects,
            path=path,
            src_ip=src_ip,
        )

        if alert is not None:
            alerts.append(alert)

    # =========================================================
    # BFLA
    # =========================================================

    if user_id and role and method and path:

        alert = detect_bfla(
            db=db,
            user_id=user_id,
            role=role,
            method=method,
            path=path,
            src_ip=src_ip,
        )

        if alert is not None:
            alerts.append(alert)

    # =========================================================
    # Shadow API
    # =========================================================

    if method and path:

        alert = detect_shadow_api(
            db=db,
            method=method,
            path=path,
            known_apis=KNOWN_APIS,
            src_ip=src_ip,
        )

        if alert is not None:
            alerts.append(alert)

    return alerts