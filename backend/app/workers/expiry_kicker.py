import asyncio
from datetime import datetime, timezone
import structlog
from sqlalchemy import select
from app.db.session import async_session_factory
from app.db.models import Certificate, CertStatus, Entity, EntityState
from app.broker.dynsec import DynSecBrokerAdmin
from app.services.audit_service import append_audit_entry

logger = structlog.get_logger(__name__)

async def run_expiry_kicker_loop(interval_seconds: int = 15):
    logger.info("starting_expiry_kicker_worker", interval=interval_seconds)
    admin = DynSecBrokerAdmin()

    while True:
        try:
            async with async_session_factory() as db:
                now = datetime.now(timezone.utc)
                res = await db.execute(
                    select(Certificate, Entity).join(Entity, Certificate.entity_id == Entity.id).where(
                        Certificate.status == CertStatus.ACTIVE,
                        Entity.state == EntityState.ACTIVE
                    )
                )
                for cert, entity in res.all():
                    not_after = cert.not_after
                    if not_after.tzinfo is None:
                        not_after = not_after.replace(tzinfo=timezone.utc)

                    if not_after < now:
                        logger.warn("certificate_expired", entity_id=entity.id, serial=cert.serial)
                        cert.status = CertStatus.EXPIRED
                        entity.state = EntityState.EXPIRED
                        await db.commit()

                        await admin.kick(entity.id)
                        await append_audit_entry(
                            db, "entity", "entity.state_change", "system", "success",
                            entity_id=entity.id, detail={"from": "ACTIVE", "to": "EXPIRED", "reason": "cert_expired"}
                        )
        except Exception as e:
            logger.error("expiry_kicker_error", error=str(e))

        await asyncio.sleep(interval_seconds)
