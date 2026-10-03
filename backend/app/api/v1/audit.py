from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog
from app.db.session import get_db_session
from app.services.audit_service import verify_audit_chain

router = APIRouter(prefix="/audit", tags=["audit"])

@router.get("")
async def list_audit_logs(
    category: Optional[str] = None,
    action: Optional[str] = None,
    entity_id: Optional[str] = None,
    outcome: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    db: AsyncSession = Depends(get_db_session)
) -> Dict[str, Any]:
    stmt = select(AuditLog)
    if category:
        stmt = stmt.where(AuditLog.category == category)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if entity_id:
        stmt = stmt.where(AuditLog.entity_id == entity_id)
    if outcome:
        stmt = stmt.where(AuditLog.outcome == outcome)

    stmt = stmt.order_by(AuditLog.id.desc()).limit(limit)
    res = await db.execute(stmt)
    rows = res.scalars().all()

    items = []
    for r in rows:
        items.append({
            "id": r.id,
            "ts": r.ts.isoformat(),
            "category": r.category,
            "action": r.action,
            "actor_type": r.actor_type,
            "actor_id": r.actor_id,
            "entity_id": r.entity_id,
            "outcome": r.outcome,
            "detail": r.detail,
            "prev_hash": r.prev_hash.hex(),
            "hash": r.hash.hex(),
        })

    return {"items": items, "next_cursor": None}

@router.get("/verify")
async def verify_chain_endpoint(db: AsyncSession = Depends(get_db_session)) -> Dict[str, Any]:
    res = await verify_audit_chain(db)
    return res
