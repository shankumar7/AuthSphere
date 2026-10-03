import asyncio
from datetime import datetime, timedelta, timezone
import structlog
from sqlalchemy import select
from app.config import settings
from app.db.session import async_session_factory
from app.db.models import Certificate, CertStatus, RotationEvent, RotationStatus
from app.pki.ca import CAEngine
from app.pki.crl import generate_crl
from app.services.audit_service import append_audit_entry

logger = structlog.get_logger(__name__)

async def run_rotation_watcher_loop(interval_seconds: int = 15):
    timeout_limit = settings.DEMO_CERT_LIFETIME_SECONDS // 4 if settings.DEMO_MODE else settings.ROTATION_CONFIRM_TIMEOUT_SECONDS
    logger.info("starting_rotation_watcher_worker", timeout_seconds=timeout_limit)

    while True:
        try:
            async with async_session_factory() as db:
                now = datetime.now(timezone.utc)
                cutoff = now - timedelta(seconds=timeout_limit)

                res = await db.execute(
                    select(RotationEvent).where(
                        RotationEvent.status == RotationStatus.ISSUED,
                        RotationEvent.created_at <= cutoff
                    )
                )
                events = res.scalars().all()
                for event in events:
                    logger.warn("rotation_confirmation_timeout", rotation_id=event.id, entity_id=event.entity_id)
                    event.status = RotationStatus.TIMEOUT
                    event.error = "Confirmation timeout exceeded"

                    # Revoke stale issued cert as unconfirmed
                    res_cert = await db.execute(
                        select(Certificate).where(Certificate.serial == event.new_serial)
                    )
                    stale_cert = res_cert.scalar_one_or_none()
                    if stale_cert and stale_cert.status == CertStatus.ISSUED:
                        stale_cert.status = CertStatus.REVOKED
                        stale_cert.revoked_at = now
                        stale_cert.revoke_reason = "unconfirmed"

                    await db.commit()

                    await append_audit_entry(
                        db, "pki", "pki.rotate_timeout", "system", "error",
                        entity_id=event.entity_id, detail={"rotation_id": event.id, "new_serial": event.new_serial}
                    )
        except Exception as e:
            logger.error("rotation_watcher_error", error=str(e))

        await asyncio.sleep(interval_seconds)
