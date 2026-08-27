from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Inventory
from ..schemas import InventoryResponse


router = APIRouter(
    prefix="/inventory",
    tags=["Inventory"],
)


@router.get(
    "",
    response_model=list[InventoryResponse],
)
def get_inventory(
    db: Session = Depends(get_db),
):
    """
    Return all observed services/APIs.

    Newest inventory entries are returned first.
    """

    inventory = (
        db.query(Inventory)
        .order_by(Inventory.id.desc())
        .all()
    )

    return inventory


@router.get(
    "/{inventory_id}",
    response_model=InventoryResponse,
)
def get_inventory_item(
    inventory_id: int,
    db: Session = Depends(get_db),
):
    """
    Return one inventory item by ID.
    """

    item = (
        db.query(Inventory)
        .filter(Inventory.id == inventory_id)
        .first()
    )

    if item is None:
        raise HTTPException(
            status_code=404,
            detail="Inventory item not found",
        )

    return item