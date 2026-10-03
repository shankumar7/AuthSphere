import json
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from sqlalchemy import select, text, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models import AuditLog

GENESIS_PREV_HASH = b"\x00" * 32

def compute_canonical_json(
    ts: datetime,
    category: str,
    action: str,
    actor_type: str,
    actor_id: Optional[str],
    entity_id: Optional[str],
    outcome: str,
    detail: Dict[str, Any]
) -> bytes:
    if isinstance(ts, str):
        ts_str = ts
    else:
        # Convert to UTC and format cleanly to ISO-8601 with Z
        dt_utc = ts.astimezone(timezone.utc) if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        ts_str = dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    
    payload = {
        "action": action,
        "actor_id": actor_id,
        "actor_type": actor_type,
        "category": category,
        "detail": detail or {},
        "entity_id": entity_id,
        "outcome": outcome,
        "ts": ts_str,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return canonical.encode("utf-8")


def compute_row_hash(prev_hash: bytes, canonical_json_bytes: bytes) -> bytes:
    return hashlib.sha256(prev_hash + canonical_json_bytes).digest()

async def append_audit_entry(
    db: AsyncSession,
    category: str,
    action: str,
    actor_type: str,
    outcome: str,
    actor_id: Optional[str] = None,
    entity_id: Optional[str] = None,
    detail: Optional[Dict[str, Any]] = None,
    ts: Optional[datetime] = None
) -> AuditLog:
    if db.bind and "postgresql" in db.bind.dialect.name:
        await db.execute(text("SELECT pg_advisory_xact_lock(7001)"))

    # Fetch last audit entry to get latest hash
    res = await db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
    last_entry = res.scalar_one_or_none()

    prev_hash = last_entry.hash if last_entry else GENESIS_PREV_HASH
    entry_ts = ts or datetime.now(timezone.utc)
    entry_detail = detail or {}

    canonical_bytes = compute_canonical_json(
        ts=entry_ts,
        category=category,
        action=action,
        actor_type=actor_type,
        actor_id=actor_id,
        entity_id=entity_id,
        outcome=outcome,
        detail=entry_detail
    )
    row_hash = compute_row_hash(prev_hash, canonical_bytes)

    audit_row = AuditLog(
        ts=entry_ts,
        category=category,
        action=action,
        actor_type=actor_type,
        actor_id=actor_id,
        entity_id=entity_id,
        outcome=outcome,
        detail=entry_detail,
        prev_hash=prev_hash,
        hash=row_hash
    )
    db.add(audit_row)
    await db.commit()
    await db.refresh(audit_row)
    return audit_row

async def verify_audit_chain(db: AsyncSession) -> Dict[str, Any]:
    res = await db.execute(select(AuditLog).order_by(AuditLog.id.asc()))
    rows = res.scalars().all()

    checked = len(rows)
    expected_prev = GENESIS_PREV_HASH

    for row in rows:
        if row.prev_hash != expected_prev:
            return {"valid": False, "checked": checked, "first_bad_id": row.id}

        canonical_bytes = compute_canonical_json(
            ts=row.ts,
            category=row.category,
            action=row.action,
            actor_type=row.actor_type,
            actor_id=row.actor_id,
            entity_id=row.entity_id,
            outcome=row.outcome,
            detail=row.detail
        )
        calculated_hash = compute_row_hash(row.prev_hash, canonical_bytes)
        if row.hash != calculated_hash:
            return {"valid": False, "checked": checked, "first_bad_id": row.id}

        expected_prev = row.hash

    return {"valid": True, "checked": checked, "first_bad_id": None}
