import base64
import hashlib
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature



from app.config import settings
from app.db.models import Certificate, CertKind, CertStatus, Entity, EntityState, PopNonce
from app.db.session import get_db_session

class PoPVerificationError(HTTPException):
    def __init__(self, detail: str, code: str = "invalid_signature"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": code, "message": detail}}
        )

async def verify_pop_signature(
    request: Request,
    db: AsyncSession = Depends(get_db_session)
) -> tuple[Entity, Certificate]:
    allowed_kinds = (CertKind.OPERATIONAL, CertKind.BOOTSTRAP)


    x_as_entity = request.headers.get("x-as-entity") or request.headers.get("X-AS-Entity")
    x_as_serial = request.headers.get("x-as-serial") or request.headers.get("X-AS-Serial")
    x_as_timestamp = request.headers.get("x-as-timestamp") or request.headers.get("X-AS-Timestamp")
    x_as_nonce = request.headers.get("x-as-nonce") or request.headers.get("X-AS-Nonce")
    x_as_signature = request.headers.get("x-as-signature") or request.headers.get("X-AS-Signature")

    if not all([x_as_entity, x_as_serial, x_as_timestamp, x_as_nonce, x_as_signature]):
        raise PoPVerificationError("Missing required PoP headers (X-AS-*)")

    try:
        ts_int = int(x_as_timestamp)
    except ValueError:
        raise PoPVerificationError("Invalid X-AS-Timestamp header")

    # 1. Check timestamp skew
    now_ts = int(time.time())
    if abs(now_ts - ts_int) > settings.POP_MAX_SKEW_SECONDS:
        raise PoPVerificationError("Timestamp skew exceeds allowable limit")

    # 2. Check & record nonce to prevent replay attacks
    existing_nonce = await db.execute(
        select(PopNonce).where(PopNonce.entity_id == x_as_entity, PopNonce.nonce == x_as_nonce)
    )
    if existing_nonce.scalar_one_or_none():
        raise PoPVerificationError("Replayed nonce detected")

    expires_at = datetime.fromtimestamp(ts_int + 600, tz=timezone.utc)
    new_nonce = PopNonce(entity_id=x_as_entity, nonce=x_as_nonce, expires_at=expires_at)
    db.add(new_nonce)

    # 3. Check Entity status
    res = await db.execute(select(Entity).where(Entity.id == x_as_entity))
    entity = res.scalar_one_or_none()
    if not entity or entity.state == EntityState.REVOKED:
        raise PoPVerificationError("Entity does not exist or is revoked")

    # 4. Check Certificate status and kind
    res_cert = await db.execute(
        select(Certificate).where(
            Certificate.serial == x_as_serial,
            Certificate.entity_id == x_as_entity
        )
    )
    cert_record = res_cert.scalar_one_or_none()
    if not cert_record:
        raise PoPVerificationError("Certificate serial not found for entity")

    if cert_record.status != CertStatus.ACTIVE:
        raise PoPVerificationError(f"Certificate status is {cert_record.status}, must be active")

    if cert_record.kind not in allowed_kinds:
        raise PoPVerificationError(f"Certificate kind {cert_record.kind} is not allowed for this endpoint")

    now_dt = datetime.now(timezone.utc)
    not_after_dt = cert_record.not_after
    if not_after_dt.tzinfo is None:
        not_after_dt = not_after_dt.replace(tzinfo=timezone.utc)

    if not_after_dt < now_dt:
        raise PoPVerificationError("Certificate has expired")


    # 5. Build and verify signing string
    body_bytes = await request.body()
    body_hash = hashlib.sha256(body_bytes).hexdigest().lower()

    method = request.method.upper()
    path = request.url.path

    signing_string = "\n".join([
        "AUTHSPHERE-POP-V1",
        method,
        path,
        body_hash,
        str(ts_int),
        x_as_nonce,
        x_as_entity,
        x_as_serial
    ])

    try:
        signature_bytes = base64.b64decode(x_as_signature)
        cert_obj = load_pem_x509_certificate(cert_record.cert_pem.encode("utf-8"))
        pub_key = cert_obj.public_key()
        pub_key.verify(signature_bytes, signing_string.encode("utf-8"), ec.ECDSA(hashes.SHA256()))

    except Exception as e:
        raise PoPVerificationError(f"PoP Signature verification failed: {e}")

    await db.commit()
    return entity, cert_record
