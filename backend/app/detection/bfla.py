from sqlalchemy.orm import Session

from .alert_helper import create_alert
from .path_utils import normalize_path


ROLE_PERMISSIONS = {
    "USER": {
        ("GET", "/api/profile"),
        ("GET", "/api/users"),
        ("GET", "/api/users/{id}"),
    },
    "ADMIN": {
        ("GET", "/api/profile"),
        ("GET", "/api/users"),
        ("DELETE", "/api/users/{id}"),
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
    Prototype BFLA detector based on role/endpoint rules.
    """

    normalized_method = method.upper()
    normalized_path = normalize_path(path)

    allowed = (
        normalized_method,
        normalized_path,
    ) in ROLE_PERMISSIONS.get(
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
            "method": normalized_method,
            "path": path,
            "normalized_path": normalized_path,
        },
    )