import hashlib
from datetime import datetime, timezone
from typing import Any, Dict

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.config import settings
from app.db.models import Certificate, CertKind, CertStatus, Entity, EntityState, IssuedVia, Role, RotationEvent, RotationStatus, RotationTrigger
from app.pki.ca import CAEngine
from app.pki.policy import CertKind
from app.services.audit_service import append_audit_entry

class RotationError(Exception):
    def __init__(self, message: str, code: str = "invalid_request"):
        self.message = message
        self.code = code

async def request_certificate_rotation(
    db: AsyncSession,
    ca_engine: CAEngine,
    entity: Entity,
    current_cert: Certificate,
    csr_pem: str,
    trigger: RotationTrigger = RotationTrigger.SCHEDULED
) -> Dict[str, Any]:
    if entity.state == EntityState.REVOKED:
        await append_audit_entry(db, "pki", "pki.rotate_denied", "entity", "denied", entity_id=entity.id, detail={"reason": "revoked"})
        raise RotationError("Entity is revoked", "forbidden")

    # If an issued unconfirmed cert exists, revoke it as unconfirmed
    res_stale = await db.execute(
        select(Certificate).where(
            Certificate.entity_id == entity.id,
            Certificate.status == CertStatus.ISSUED
        )
    )
    for stale_cert in res_stale.scalars().all():
        stale_cert.status = CertStatus.REVOKED
        stale_cert.revoked_at = datetime.now(timezone.utc)
        stale_cert.revoke_reason = "unconfirmed"

    # Fetch role policy
    res_role = await db.execute(select(Role).where(Role.name == entity.role_name))
    role = res_role.scalar_one_or_none()
    lifetime = settings.DEMO_CERT_LIFETIME_SECONDS if settings.DEMO_MODE else (role.cert_lifetime_seconds if role else 604800)

    # Determine kind
    issue_kind = CertKind.OPERATIONAL

    cert_obj, cert_pem, serial_hex = ca_engine.issue_certificate(
        csr_pem=csr_pem,
        entity_id=entity.id,
        role_name=entity.role_name,
        lifetime_seconds=lifetime,
        kind=issue_kind
    )

    fingerprint = hashlib.sha256(cert_obj.public_bytes(serialization.Encoding.DER)).hexdigest()
    pub_key_pem = cert_obj.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")


    # Status is 'issued' (unconfirmed) until confirmed by test connect or presence report
    new_cert_record = Certificate(
        serial=serial_hex,
        entity_id=entity.id,
        kind=issue_kind,
        status=CertStatus.ISSUED,
        issued_via=IssuedVia.ROTATE,
        not_before=cert_obj.not_valid_before_utc,
        not_after=cert_obj.not_valid_after_utc,
        fingerprint_sha256=fingerprint,
        public_key_pem=pub_key_pem,
        cert_pem=cert_pem
    )
    db.add(new_cert_record)

    rot_event = RotationEvent(
        entity_id=entity.id,
        old_serial=current_cert.serial if current_cert else None,
        new_serial=serial_hex,
        trigger=trigger,
        status=RotationStatus.ISSUED
    )
    db.add(rot_event)

    await db.commit()
    await db.refresh(rot_event)

    await append_audit_entry(
        db, "pki", "pki.rotate_ok", "entity", "success",
        entity_id=entity.id, detail={"new_serial": serial_hex, "rotation_id": rot_event.id}
    )

    renew_at = cert_obj.not_valid_before_utc + (cert_obj.not_valid_after_utc - cert_obj.not_valid_before_utc) * 0.66
    return {
        "cert_pem": cert_pem,
        "ca_chain_pem": ca_engine.ca_chain_pem,
        "serial": serial_hex,
        "not_before": cert_obj.not_valid_before_utc.isoformat(),
        "not_after": cert_obj.not_valid_after_utc.isoformat(),
        "renew_at": renew_at.isoformat(),
        "rotation_id": rot_event.id,
        "mqtt": {"host": settings.MQTT_PUBLIC_HOSTNAME, "port": settings.MQTT_PORT}
    }
