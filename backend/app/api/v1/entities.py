from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Entity, EntityState, EntityType, ProvMode
from app.db.session import get_db_session
from app.pki.ca import CAEngine
from app.services.entity_service import EntityServiceError, create_entity, get_entity_detail
from app.services.revocation_service import RevocationError, revoke_entity

router = APIRouter(prefix="/entities", tags=["entities"])

class CreateEntityRequest(BaseModel):
    id: str
    entity_type: EntityType
    role_name: str
    provisioning_mode: ProvMode
    display_name: Optional[str] = None
    hw_model: Optional[str] = None

class RevokeEntityRequest(BaseModel):
    reason: str = "admin"

@router.get("")
async def list_entities(
    type: Optional[EntityType] = None,
    state: Optional[EntityState] = None,
    role: Optional[str] = None,
    db: AsyncSession = Depends(get_db_session)
) -> Dict[str, Any]:
    stmt = select(Entity)
    if type:
        stmt = stmt.where(Entity.entity_type == type)
    if state:
        stmt = stmt.where(Entity.state == state)
    if role:
        stmt = stmt.where(Entity.role_name == role)

    res = await db.execute(stmt)
    entities = res.scalars().all()
    items = []
    for e in entities:
        items.append({
            "id": e.id,
            "entity_type": e.entity_type,
            "role_name": e.role_name,
            "state": e.state,
            "online": e.online,
            "current_cert_serial": e.current_cert_serial,
            "created_at": e.created_at.isoformat(),
        })
    return {"items": items, "next_cursor": None}

@router.post("", status_code=201)
async def create_new_entity(
    req: CreateEntityRequest, db: AsyncSession = Depends(get_db_session)
) -> Dict[str, Any]:
    try:
        entity, plain_token, expires_at = await create_entity(
            db, req.id, req.entity_type, req.role_name, req.provisioning_mode, req.display_name, req.hw_model
        )
        res = {
            "entity": {
                "id": entity.id,
                "entity_type": entity.entity_type,
                "role_name": entity.role_name,
                "state": entity.state,
                "provisioning_mode": entity.provisioning_mode,
                "created_at": entity.created_at.isoformat(),
            }
        }
        if plain_token:
            res["claim_token"] = plain_token
            res["claim_expires_at"] = expires_at.isoformat() if expires_at else None
            res["qr_payload"] = {
                "api_base": "http://localhost:8000/api/v1",
                "entity_id": entity.id,
                "token": plain_token
            }
        return res
    except EntityServiceError as e:
        raise HTTPException(
            status_code=409 if e.code == "conflict" else 400,
            detail={"error": {"code": e.code, "message": e.message}}
        )

@router.get("/{entity_id}")
async def get_entity(entity_id: str, db: AsyncSession = Depends(get_db_session)) -> Dict[str, Any]:
    detail = await get_entity_detail(db, entity_id)
    if not detail:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": f"Entity '{entity_id}' not found"}})
    return detail

@router.post("/{entity_id}/revoke")
async def revoke_entity_endpoint(
    entity_id: str, req: RevokeEntityRequest, db: AsyncSession = Depends(get_db_session)
) -> Dict[str, Any]:
    ca = CAEngine()
    try:
        res = await revoke_entity(db, ca, entity_id, reason=req.reason)
        return res
    except RevocationError as e:
        raise HTTPException(
            status_code=404 if e.code == "not_found" else 400,
            detail={"error": {"code": e.code, "message": e.message}}
        )
