import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..models import Alert


def create_alert(
    db: Session,
    alert_type: str,
    severity: str,
    description: str,
    src_ip: str | None = None,
    destination: str | None = None,
    evidence: dict | None = None,
):
    """
    Create and persist a security alert.

    All detection modules use this helper so alerts
    have a consistent structure.
    """

    alert = Alert(
        alert_type=alert_type,
        severity=severity,
        src_ip=src_ip,
        destination=destination,
        timestamp=datetime.now(timezone.utc),
        description=description,
        evidence=json.dumps(evidence) if evidence else None,
        status="OPEN",
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)

    return alert