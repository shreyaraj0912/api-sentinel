from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Alert
from ..schemas import AlertResponse
from ..security.pii_masker import mask_json_string, mask_pii


router = APIRouter(
    prefix="/alerts",
    tags=["Alerts"],
)


def sanitize_alert(alert: Alert) -> dict:
    """
    Convert a database Alert into a sanitized API response.

    PII is masked at the response boundary so that the original
    database record remains unchanged.

    Currently supported PII:
    - Email addresses inside description
    - Email addresses inside JSON evidence
    """

    return {
        "id": alert.id,
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "src_ip": alert.src_ip,
        "destination": alert.destination,
        "timestamp": alert.timestamp,
        "description": mask_pii(alert.description),
        "evidence": mask_json_string(alert.evidence),
        "status": alert.status,
    }


@router.get(
    "",
    response_model=list[AlertResponse],
)
def get_alerts(
    db: Session = Depends(get_db),
):
    """
    Return all security alerts.

    Alert descriptions and evidence are sanitized before
    being exposed to API consumers.
    """

    alerts = (
        db.query(Alert)
        .order_by(Alert.id.desc())
        .all()
    )

    return [
        sanitize_alert(alert)
        for alert in alerts
    ]


@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
):
    """
    Return one security alert by ID.

    The returned alert is sanitized before being exposed.
    """

    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_id)
        .first()
    )

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    return sanitize_alert(alert)