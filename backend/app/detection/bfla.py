from sqlalchemy.orm import Session

from .alert_helper import create_alert


ROLE_PERMISSIONS = {
    "USER": {
        ("GET", "/api/profile"),
        ("GET", "/api/users"),
    },
    "ADMIN": {
        ("GET", "/api/profile"),
        ("GET", "/api/users"),
        ("DELETE", "/api/users"),
        ("POST", "/api/admin"),
    },
}


def detect_bfla(
    db: Session,
    user_id: str,
    role: str,
    method: str,
    path: str,
    src_ip: str | None = None,
):
    """
    Prototype BFLA detector based on a static
    role/endpoint permission table.
    """

    allowed = (method.upper(), path) in ROLE_PERMISSIONS.get(
        role.upper(),
        set(),
    )

    if allowed:
        return None

    return create_alert(
        db=db,
        alert_type="BFLA",
        severity="HIGH",
        src_ip=src_ip,
        destination=path,
        description=(
            f"User {user_id} with role {role} attempted "
            f"an unauthorized operation."
        ),
        evidence={
            "user_id": user_id,
            "role": role,
            "method": method.upper(),
            "path": path,
        },
    )