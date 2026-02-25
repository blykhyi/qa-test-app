import math
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Asset
from ..schemas import AssetCreate, AssetUpdate, AssetResponse, PaginatedAssets

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("", response_model=PaginatedAssets)
def list_assets(
    page: int = Query(1, ge=1),
    per_page: int = Query(10, ge=1, le=100),
    environment: str = Query(None),
    asset_type: str = Query(None),
    db: Session = Depends(get_db),
):
    query = db.query(Asset).filter(Asset.is_active == True)

    if environment:
        query = query.filter(Asset.environment == environment)
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)

    total = query.count()

    # BUG #6: off-by-one — skips first asset on every page
    items = query.order_by(Asset.id).offset((page - 1) * per_page + 1).limit(per_page).all()

    pages = math.ceil(total / per_page) if per_page > 0 else 0
    return PaginatedAssets(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
        pages=pages,
    )


@router.get("/{asset_id}", response_model=AssetResponse)
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.is_active == True,
    ).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.post("", response_model=AssetResponse, status_code=201)
def create_asset(asset_data: AssetCreate, db: Session = Depends(get_db)):
    asset = Asset(**asset_data.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@router.put("/{asset_id}", response_model=AssetResponse)
def update_asset(
    asset_id: int,
    asset_data: AssetUpdate,
    db: Session = Depends(get_db),
):
    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.is_active == True,
    ).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    update_data = asset_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(asset, key, value)

    db.commit()
    db.refresh(asset)
    return asset


@router.delete("/{asset_id}", status_code=204)
def deactivate_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.is_active == True,
    ).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    asset.is_active = False
    db.commit()
    return None
