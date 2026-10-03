import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.security import generate_claim_token, hash_claim_token
from app.db.models import Certificate, CertStatus, ClaimToken, Entity, EntityState, EntityType, ProvMode, Role
from app.services.audit_service import append_audit_entry

ENTITY_ID_REGEX = re.compile(r"^(dev|usr|svc)-[a-z0-9][a-z0-9-]{2,31}$")

class EntityServiceError(Exception):
    def __init__(self, message: str, code: str = "invalid_request"):
        self.message = message
        self.code = code

async def create_entity(
    db: AsyncSession,
    entity_id: str,
    entity_type: EntityType,
    role_name: str,
    provisioning_mode: ProvMode,
    display_name: Optional[str] = None,
    hw_model: Optional[str] = None,
    actor_id: Optional[str] = None,
) -> Tuple[Entity, Optional[str], Optional[datetime]]:
    if not ENTITY_ID_REGEX.match(entity_id):
        raise EntityServiceError("Invalid entity ID slug format. Must match ^(dev|usr|svc)-[a-z0-9-]{2,31}$", "invalid_id")

    res_role = await db.execute(select(Role).where(Role.name == role_name))
    role = res_role.scalar_one_or_none()
    if not role:
        raise EntityServiceError(f"Role '{role_name}' does not exist", "role_not_found")

    res_existing = await db.execute(select(Entity).where(Entity.id == entity_id))
    if res_existing.scalar_one_or_none():
        raise EntityServiceError(f"Entity '{entity_id}' already exists", "conflict")

    entity = Entity(
        id=entity_id,
        entity_type=entity_type,
        role_name=role_name,
        provisioning_mode=provisioning_mode,
        display_name=display_name,
        hw_model=hw_model,
        state=EntityState.PENDING,
    )
    db.add(entity)

    plain_token: Optional[str] = None
    expires_at: Optional[datetime] = None

    if provisioning_mode == ProvMode.CLAIM_TOKEN:
        plain_token, token_hash = generate_claim_token()
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=settings.CLAIM_TOKEN_TTL_SECONDS)
        claim_rec = ClaimToken(
            entity_id=entity_id,
            token_hash=token_hash,
            expires_at=expires_at,
        )
        db.add(claim_rec)

    await db.commit()
    await db.refresh(entity)

    await append_audit_entry(
        db,
        category="entity",
        action="entity.create",
        actor_type="dashboard_user" if actor_id else "system",
        actor_id=actor_id,
        entity_id=entity_id,
        outcome="success",
        detail={"mode": provisioning_mode.value, "role": role_name},
    )

    return entity, plain_token, expires_at

async def get_entity_detail(db: AsyncSession, entity_id: str) -> Optional[Dict[str, Any]]:
    res = await db.execute(select(Entity).where(Entity.id == entity_id))
    entity = res.scalar_one_or_none()
    if not entity:
        return None

    res_cert = await db.execute(
        select(Certificate).where(
            Certificate.entity_id == entity_id,
            Certificate.status == CertStatus.ACTIVE
        )
    )
    current_cert = res_cert.scalar_one_or_none()

    now = datetime.now(timezone.utc)
    rotation_due = False
    at_risk = False

    cert_info = None
    if current_cert:
        total_sec = (current_cert.not_after - current_cert.not_before).total_seconds()
        elapsed_sec = (now - current_cert.not_before).total_seconds()
        pct = (elapsed_sec / total_sec * 100) if total_sec > 0 else 100

        renew_at = current_cert.not_before + timedelta(seconds=total_sec * 0.66)
        rotation_due = now >= renew_at
        at_risk = pct >= 80 and entity.state != EntityState.REVOKED

        cert_info = {
            "serial": current_cert.serial,
            "kind": current_cert.kind,
            "not_before": current_cert.not_before.isoformat(),
            "not_after": current_cert.not_after.isoformat(),
            "renew_at": renew_at.isoformat(),
            "fingerprint_sha256": current_cert.fingerprint_sha256,
        }

    return {
        "id": entity.id,
        "entity_type": entity.entity_type,
        "role_name": entity.role_name,
        "state": entity.state,
        "provisioning_mode": entity.provisioning_mode,
        "display_name": entity.display_name,
        "hw_model": entity.hw_model,
        "fw_version": entity.fw_version,
        "online": entity.online,
        "last_seen_at": entity.last_seen_at.isoformat() if entity.last_seen_at else None,
        "current_cert": cert_info,
        "flags": {
            "rotation_due": rotation_due,
            "at_risk": at_risk,
        }
    }
