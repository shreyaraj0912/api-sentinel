from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..detection.engine import run_detections
from ..models import Event, Inventory
from ..schemas import EventCreate, EventResponse
from ..detection.path_utils import normalize_path


router = APIRouter(
    prefix="/events",
    tags=["Events"],
)


@router.post(
    "",
    response_model=EventResponse,
    status_code=201,
)
def create_event(
    event_data: EventCreate,
    db: Session = Depends(get_db),
):
    """
    Receive telemetry from Member 1.

    Processing order:

    1. Store the event.
    2. Update API/service inventory.
    3. Run applicable security detectors.
    4. Return the stored event.
    """

    # =========================================================
    # STEP 1: Store the incoming telemetry event
    # =========================================================

    event = Event(
        **event_data.model_dump()
    )

    db.add(event)

    db.commit()

    db.refresh(event)

    normalized_path = normalize_path(event.path)

    # =========================================================
    # STEP 2: Update inventory
    # =========================================================

    now = datetime.now(timezone.utc)

    # If API information is available, include method/path
    # when finding the corresponding inventory entry.
    if event.path or event.method:

        inventory_item = (
            db.query(Inventory)
            .filter(
                Inventory.dst_ip == event.dst_ip,
                Inventory.dst_port == event.dst_port,
                Inventory.protocol == event.protocol,
                Inventory.path == normalized_path,
                Inventory.method == event.method,
            )
            .first()
        )

    else:

        # Current Member 1 network-only telemetry.
        #
        # Example:
        # method = None
        # path = None
        #
        # We identify the service using:
        # dst_ip + dst_port + protocol

        inventory_item = (
            db.query(Inventory)
            .filter(
                Inventory.dst_ip == event.dst_ip,
                Inventory.dst_port == event.dst_port,
                Inventory.protocol == event.protocol,
                Inventory.path.is_(None),
                Inventory.method.is_(None),
            )
            .first()
        )

    # ---------------------------------------------------------
    # Create a new inventory entry
    # ---------------------------------------------------------

    if inventory_item is None:

        inventory_item = Inventory(
            path=normalized_path,
            method=event.method,
            dst_ip=event.dst_ip,
            dst_port=event.dst_port,
            protocol=event.protocol,
            first_seen=now,
            last_seen=now,
            request_count=1,
            documented=False,
        )

        db.add(inventory_item)

    # ---------------------------------------------------------
    # Update an existing inventory entry
    # ---------------------------------------------------------

    else:

        inventory_item.last_seen = now
        inventory_item.request_count += 1

    db.commit()

    # =========================================================
    # STEP 3: Run security detection
    # =========================================================
    #
    # IMPORTANT:
    #
    # Member 1's current telemetry has:
    #
    # method=None
    # path=None
    # user_id=None
    # role=None
    # object_id=None
    #
    # In that case, the detection engine simply stores the
    # network event and does not generate API-security alerts.
    #
    # If API context is available, the appropriate detectors
    # will run.
    # =========================================================

    run_detections(
        db=db,
        user_id=event.user_id,
        role=event.role,
        method=event.method,
        path=event.path,
        object_id=event.object_id,
        src_ip=event.src_ip,
    )

    # =========================================================
    # STEP 4: Return the stored event
    # =========================================================

    return event


@router.get(
    "",
    response_model=list[EventResponse],
)
def get_events(
    db: Session = Depends(get_db),
):
    """
    Return all stored telemetry events.

    Newest events are returned first.
    """

    events = (
        db.query(Event)
        .order_by(Event.id.desc())
        .all()
    )

    return events


@router.get(
    "/{event_id}",
    response_model=EventResponse,
)
def get_event(
    event_id: int,
    db: Session = Depends(get_db),
):
    """
    Return one stored event by database ID.
    """

    event = (
        db.query(Event)
        .filter(Event.id == event_id)
        .first()
    )

    if event is None:
        raise HTTPException(
            status_code=404,
            detail="Event not found",
        )

    return event