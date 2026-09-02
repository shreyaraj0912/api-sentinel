import re

from sqlalchemy.orm import Session

from .alert_helper import create_alert


def normalize_path(path: str) -> str:
    """
    Convert numeric path components into {id}.

    Example:
        /api/users/103
        -> /api/users/{id}
    """

    return re.sub(
        r"/\d+(?=/|$)",
        "/{id}",
        path,
    )


def detect_shadow_api(
    db: Session,
    method: str,
    path: str,
    known_apis: set[tuple[str, str]],
    src_ip: str | None = None,
):
    """
    Prototype Shadow API detector.

    An API is considered shadowed only when its normalized
    method/path combination is not present in the known API set.
    """

    normalized_method = method.upper()
    normalized_path = normalize_path(path)

    normalized_known_apis = {
        (
            known_method.upper(),
            normalize_path(known_path),
        )
        for known_method, known_path in known_apis
    }

    observed_api = (
        normalized_method,
        normalized_path,
    )

    if observed_api in normalized_known_apis:
        return None

    return create_alert(
        db=db,
        alert_type="SHADOW_API",
        severity="MEDIUM",
        src_ip=src_ip,
        destination=path,
        description=(
            "Observed API endpoint is not present "
            "in the known/documented API inventory."
        ),
        evidence={
            "method": normalized_method,
            "path": path,
            "normalized_path": normalized_path,
            "known_apis": [
                {
                    "method": known_method,
                    "path": known_path,
                }
                for known_method, known_path in known_apis
            ],
        },
    )