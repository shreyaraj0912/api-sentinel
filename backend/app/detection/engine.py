from sqlalchemy.orm import Session

from .bfla import detect_bfla
from .bola import detect_bola
from .shadow_api import detect_shadow_api
from ..security.rate_limit_detector import check_rate_limit


# ---------------------------------------------------------
# Prototype BOLA ownership rules
# ---------------------------------------------------------

OWNED_OBJECTS = {
    "userA": {"101", "102"},
    "userB": {"201", "202"},
}


# ---------------------------------------------------------
# Prototype documented API set
# ---------------------------------------------------------

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
    Run the API-Sentinel detection pipeline.

    Detection types:
    - BOLA
    - BFLA
    - Shadow API
    - Rate limiting

    Network-only events can still be stored normally.
    API-level detections are only performed when the
    required API/security context is available.
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

    # =========================================================
    # Rate Limit
    # =========================================================
    #
    # Only API-aware events participate in rate limiting.
    #
    # Current Member 1 network-only events have:
    #
    # method = None
    # path = None
    #
    # Therefore they are stored but are not interpreted
    # as API requests for this detector.
    #
    # The rate-limit key uses:
    #
    # user_id -> preferred
    # src_ip  -> fallback for anonymous traffic
    # =========================================================

    if method and path:

        rate_limit_key = user_id or src_ip

        if rate_limit_key:

            alert = check_rate_limit(
                db=db,
                key=rate_limit_key,
                src_ip=src_ip,
                user_id=user_id,
                method=method,
                path=path,
            )

            if alert is not None:
                alerts.append(alert)

    return alerts