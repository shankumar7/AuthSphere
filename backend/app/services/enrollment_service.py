import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from app.config import settings


from app.core.security import hash_claim_token
from app.db.models import Certificate, CertKind, CertStatus, ClaimToken, Entity, EntityState, IssuedVia, ProvMode, Role
from app.pki.ca import CAEngine
from app.pki.policy import CertKind
from app.services.audit_service import append_audit_entry
from app.broker.dynsec import DynSecBrokerAdmin

class EnrollmentError(Exception):
    def __init__(self, message: str, code: str = "invalid_request"):
        self.message = message
        self.code = code

async def enroll_device_mode_a(
    db: AsyncSession,
    ca_engine: CAEngine,
    entity_id: str,
    claim_token_plain: str,
    csr_pem: str
) -> Dict[str, Any]:
    # 1. Fetch Entity
    res = await db.execute(select(Entity).where(Entity.id == entity_id))
    entity = res.scalar_one_or_none()
    if not entity:
        await append_audit_entry(db, "pki", "pki.enroll_denied", "entity", "denied", entity_id=entity_id, detail={"reason": "entity_not_found"})
        raise EnrollmentError("Entity not found", "not_found")

    if entity.state == EntityState.REVOKED:
        await append_audit_entry(db, "pki", "pki.enroll_denied", "entity", "denied", entity_id=entity_id, detail={"reason": "entity_revoked"})
        raise EnrollmentError("Entity is revoked", "forbidden")

    # 2. Fetch & verify Claim Token
    token_hash = hash_claim_token(claim_token_plain)
    res_tok = await db.execute(
        select(ClaimToken).where(
            ClaimToken.entity_id == entity_id,
            ClaimToken.token_hash == token_hash
        )
    )
    claim_rec = res_tok.scalar_one_or_none()
    now = datetime.now(timezone.utc)

    if not claim_rec:
        await append_audit_entry(db, "pki", "pki.enroll_denied", "entity", "denied", entity_id=entity_id, detail={"reason": "invalid_token"})
        raise EnrollmentError("Invalid claim token", "unauthorized")

    if claim_rec.used_at is not None:
        await append_audit_entry(db, "pki", "pki.enroll_denied", "entity", "denied", entity_id=entity_id, detail={"reason": "token_already_used"})
        raise EnrollmentError("Claim token has already been used", "token_used")

    exp_dt = claim_rec.expires_at
    if exp_dt.tzinfo is None:
        exp_dt = exp_dt.replace(tzinfo=timezone.utc)

    if exp_dt < now:
        await append_audit_entry(db, "pki", "pki.enroll_denied", "entity", "denied", entity_id=entity_id, detail={"reason": "token_expired"})
        raise EnrollmentError("Claim token has expired", "token_expired")


    # Mark token used
    claim_rec.used_at = now

    # 3. Fetch Role policy
    res_role = await db.execute(select(Role).where(Role.name == entity.role_name))
    role = res_role.scalar_one_or_none()
    lifetime = settings.DEMO_CERT_LIFETIME_SECONDS if settings.DEMO_MODE else (role.cert_lifetime_seconds if role else 604800)

    # 4. Issue Operational Certificate
    try:
        cert_obj, cert_pem, serial_hex = ca_engine.issue_certificate(
            csr_pem=csr_pem,
            entity_id=entity_id,
            role_name=entity.role_name,
            lifetime_seconds=lifetime,
            kind=CertKind.OPERATIONAL
        )
    except Exception as e:
        await append_audit_entry(db, "pki", "pki.enroll_denied", "entity", "denied", entity_id=entity_id, detail={"reason": str(e)})
        raise EnrollmentError(f"Failed to issue certificate: {e}", "invalid_csr")

    fingerprint = hashlib.sha256(cert_obj.public_bytes(serialization.Encoding.DER)).hexdigest()
    pub_key_pem = cert_obj.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")


    cert_record = Certificate(
        serial=serial_hex,
        entity_id=entity_id,
        kind=CertKind.OPERATIONAL,
        status=CertStatus.ACTIVE,
        issued_via=IssuedVia.ENROLL,
        not_before=cert_obj.not_valid_before_utc,
        not_after=cert_obj.not_valid_after_utc,
        fingerprint_sha256=fingerprint,
        public_key_pem=pub_key_pem,
        cert_pem=cert_pem
    )
    db.add(cert_record)

    # Update Entity
    entity.state = EntityState.ACTIVE
    entity.current_cert_serial = serial_hex

    await db.commit()

    # Sync Mosquitto Dynamic Security client
    admin = DynSecBrokerAdmin()
    await admin.upsert_client(entity_id, entity.role_name)

    await append_audit_entry(db, "pki", "pki.enroll_ok", "entity", "success", entity_id=entity_id, detail={"serial": serial_hex})

    renew_at = cert_obj.not_valid_before_utc + (cert_obj.not_valid_after_utc - cert_obj.not_valid_before_utc) * 0.66
    return {
        "cert_pem": cert_pem,
        "ca_chain_pem": ca_engine.ca_chain_pem,
        "serial": serial_hex,
        "not_before": cert_obj.not_valid_before_utc.isoformat(),
        "not_after": cert_obj.not_valid_after_utc.isoformat(),
        "renew_at": renew_at.isoformat(),
        "mqtt": {"host": settings.MQTT_PUBLIC_HOSTNAME, "port": settings.MQTT_PORT}
    }
