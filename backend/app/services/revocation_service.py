from datetime import datetime, timezone
from typing import Any, Dict

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.broker.dynsec import DynSecBrokerAdmin
from app.db.models import Certificate, CertStatus, Entity, EntityState
from app.pki.ca import CAEngine
from app.pki.crl import generate_crl
from app.services.audit_service import append_audit_entry

class RevocationError(Exception):
    def __init__(self, message: str, code: str = "invalid_request"):
        self.message = message
        self.code = code

async def revoke_entity(
    db: AsyncSession,
    ca_engine: CAEngine,
    entity_id: str,
    reason: str = "admin",
    actor_id: str | None = None
) -> Dict[str, Any]:
    res = await db.execute(select(Entity).where(Entity.id == entity_id))
    entity = res.scalar_one_or_none()
    if not entity:
        raise RevocationError(f"Entity '{entity_id}' not found", "not_found")

    now = datetime.now(timezone.utc)
    entity.state = EntityState.REVOKED
    entity.revoked_at = now
    entity.revoke_reason = reason
    entity.online = False

    # 1. Update certificates to revoked
    res_certs = await db.execute(
        select(Certificate).where(
            Certificate.entity_id == entity_id,
            Certificate.status.in_([CertStatus.ACTIVE, CertStatus.ISSUED])
        )
    )
    revoked_serials = []
    for cert in res_certs.scalars().all():
        cert.status = CertStatus.REVOKED
        cert.revoked_at = now
        cert.revoke_reason = reason
        revoked_serials.append(cert.serial)

    await db.commit()

    # 2. Broker disconnect session (<2s)
    admin = DynSecBrokerAdmin()
    await admin.set_client_enabled(entity_id, False)
    await admin.delete_client(entity_id)

    # 3. Regenerate CRL
    res_all_revoked = await db.execute(
        select(Certificate).where(Certificate.status == CertStatus.REVOKED)
    )
    revoked_items = []
    for c in res_all_revoked.scalars().all():
        try:
            s_int = int(c.serial, 16)
            revoked_items.append((s_int, c.revoked_at or now))
        except ValueError:
            pass

    crl_pem = generate_crl(ca_engine, revoked_items, crl_number=int(now.timestamp()))

    # 4. Audit entry
    await append_audit_entry(
        db, "entity", "entity.revoke",
        actor_type="dashboard_user" if actor_id else "system",
        actor_id=actor_id, entity_id=entity_id,
        outcome="success", detail={"reason": reason, "serials": revoked_serials}
    )

    return {"status": "revoked", "entity_id": entity_id, "revoked_certs": len(revoked_serials)}
