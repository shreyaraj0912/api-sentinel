from sqlalchemy.orm import Session

from .alert_helper import create_alert


def detect_shadow_api(
    db: Session,
    method: str,
    path: str,
    known_apis: set[tuple[str, str]],
    src_ip: str | None = None,
):
    """
    Prototype Shadow API detector.

    Generates an alert when an observed method/path pair
    is not present in the known/documented API set.
    """

    api = (method.upper(), path)

    if api in known_apis:
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
            "method": method.upper(),
            "path": path,
            "known_apis": [
                {
                    "method": item[0],
                    "path": item[1],
                }
                for item in known_apis
            ],
        },
    )