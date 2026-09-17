from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Event, Inventory
from ..schemas import EventCreate, EventResponse


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
    Receive telemetry, store it, and update API inventory.
    """

    # ---------------------------------------------------------
    # 1. Store the incoming telemetry event
    # ---------------------------------------------------------

    event = Event(
        **event_data.model_dump()
    )

    db.add(event)

    # Commit so that the event receives its database ID.
    db.commit()

    # Reload object from database.
    db.refresh(event)

    # ---------------------------------------------------------
    # 2. Find matching inventory item
    # ---------------------------------------------------------

    inventory_item = (
        db.query(Inventory)
        .filter(
            Inventory.dst_ip == event.dst_ip,
            Inventory.dst_port == event.dst_port,
            Inventory.protocol == event.protocol,
        )
        .first()
    )

    now = datetime.now(timezone.utc)

    # ---------------------------------------------------------
    # 3. Create inventory item if this service is new
    # ---------------------------------------------------------

    if inventory_item is None:

        inventory_item = Inventory(
            path=None,
            method=None,
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
    # 4. Update existing inventory item
    # ---------------------------------------------------------

    else:

        inventory_item.last_seen = now
        inventory_item.request_count += 1

    db.commit()

    return event


@router.get(
    "",
    response_model=list[EventResponse],
)
def get_events(
    db: Session = Depends(get_db),
):
    """
    Return all stored events.

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
    Return one event by ID.
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