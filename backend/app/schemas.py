from datetime import datetime

from pydantic import BaseModel


class EventCreate(BaseModel):
    """
    Telemetry payload accepted by POST /events.

    These fields intentionally match the current provisional
    Member 1 eBPF telemetry format.
    """

    event_id: str | None = None

    timestamp: float

    src_ip: str | None = None
    dst_ip: str | None = None

    src_port: int | None = None
    dst_port: int | None = None

    protocol: str | None = None
    packet_len: int | None = None


class EventResponse(EventCreate):
    """
    Event returned by the backend after storage.
    """

    id: int

    model_config = {
        "from_attributes": True
    }


class InventoryResponse(BaseModel):
    """
    Observed API/service returned by GET /inventory.
    """

    id: int

    path: str | None = None
    method: str | None = None

    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None

    first_seen: datetime
    last_seen: datetime

    request_count: int
    documented: bool

    model_config = {
        "from_attributes": True
    }
class AlertResponse(BaseModel):
    """
    Security alert returned by the API.
    """

    id: int

    alert_type: str
    severity: str

    src_ip: str | None = None
    destination: str | None = None

    timestamp: datetime

    description: str
    evidence: str | None = None

    status: str

    model_config = {
        "from_attributes": True
    }