from sqlalchemy.orm import Session

from .alert_helper import create_alert


def detect_bola(
    db: Session,
    user_id: str,
    object_id: str,
    owned_object_ids: set[str],
    path: str,
    src_ip: str | None = None,
):
    """
    Prototype BOLA detector.

    Generates an alert when a user accesses an object
    that is not included in that user's known ownership set.
    """

    if object_id in owned_object_ids:
        return None

    return create_alert(
        db=db,
        alert_type="BOLA",
        severity="HIGH",
        src_ip=src_ip,
        destination=path,
        description=(
            f"User {user_id} attempted to access "
            f"object {object_id}, which is not authorized "
            f"according to the prototype ownership rules."
        ),
        evidence={
            "user_id": user_id,
            "object_id": object_id,
            "owned_object_ids": list(owned_object_ids),
            "path": path,
        },
    )