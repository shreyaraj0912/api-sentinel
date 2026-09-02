from datetime import datetime

from pydantic import BaseModel


class EventCreate(BaseModel):
    """
    Stable Member 1 -> Member 2 telemetry contract.

    Network fields are required.

    API/application fields are optional because the current
    XDP collector does not reliably provide them.
    """

    event_id: str

    timestamp: int

    src_ip: str
    dst_ip: str

    src_port: int
    dst_port: int

    protocol: str
    packet_len: int

    # Optional API/application enrichment.
    method: str | None = None
    path: str | None = None

    user_id: str | None = None
    role: str | None = None
    object_id: str | None = None

class EventResponse(EventCreate):
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