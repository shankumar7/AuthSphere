import base64
import hashlib
import time
import pytest
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.main import app
from app.db.models import Base, Role, EntityType
from app.db.session import get_db_session

@pytest.fixture
def anyio_backend():
    return 'asyncio'

@pytest.fixture
async def test_app_client():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    
    # Seed default sensor role
    async with session_factory() as session:
        role = Role(
            name="sensor",
            entity_type=EntityType.DEVICE,
            description="Sensor role",
            cert_lifetime_seconds=604800,
            renew_at_pct=66,
            pub_topics=["devices/%u/status", "devices/%u/telemetry"],
            sub_topics=["devices/%u/cmd/#"],
            builtin=True
        )
        session.add(role)
        await session.commit()

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db_session] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    app.dependency_overrides.clear()
    await engine.dispose()

def generate_ec_p256_key_and_csr(entity_id: str):
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, entity_id)]))
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return key, csr_pem

@pytest.mark.anyio
async def test_full_enroll_rotate_revoke_flow(test_app_client: AsyncClient):
    entity_id = "dev-demo-01"

    # 1. Create Entity
    create_res = await test_app_client.post("/api/v1/entities", json={
        "id": entity_id,
        "entity_type": "device",
        "role_name": "sensor",
        "provisioning_mode": "claim_token",
        "display_name": "Demo Sensor Device"
    })
    assert create_res.status_code == 201
    data = create_res.json()
    assert data["entity"]["id"] == entity_id
    claim_token = data["claim_token"]

    # 2. Mode A Enroll
    key1, csr_pem1 = generate_ec_p256_key_and_csr(entity_id)
    enroll_res = await test_app_client.post("/api/v1/pki/enroll", json={
        "entity_id": entity_id,
        "claim_token": claim_token,
        "csr_pem": csr_pem1
    })
    assert enroll_res.status_code == 200
    enroll_data = enroll_res.json()
    serial1 = enroll_data["serial"]

    # 3. PoP Signed Certificate Rotation
    key2, csr_pem2 = generate_ec_p256_key_and_csr(entity_id)
    ts = str(int(time.time()))
    nonce = "0123456789abcdef0123456789abcdef"
    body_json = {"csr_pem": csr_pem2, "trigger": "scheduled"}
    import json
    raw_body_bytes = json.dumps(body_json, separators=(',', ':')).encode("utf-8")
    body_hash = hashlib.sha256(raw_body_bytes).hexdigest().lower()

    signing_string = "\n".join([
        "AUTHSPHERE-POP-V1", "POST", "/api/v1/pki/rotate", body_hash, ts, nonce, entity_id, serial1
    ])
    signature_bytes = key1.sign(signing_string.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    sig_b64 = base64.b64encode(signature_bytes).decode("utf-8")

    headers = {
        "X-AS-Entity": entity_id,
        "X-AS-Serial": serial1,
        "X-AS-Timestamp": ts,
        "X-AS-Nonce": nonce,
        "X-AS-Signature": sig_b64,
        "Content-Type": "application/json"
    }

    rotate_res = await test_app_client.post("/api/v1/pki/rotate", content=raw_body_bytes, headers=headers)
    assert rotate_res.status_code == 200

    rotate_data = rotate_res.json()
    assert "serial" in rotate_data
    assert "rotation_id" in rotate_data

    # 4. Revoke Entity
    revoke_res = await test_app_client.post(f"/api/v1/entities/{entity_id}/revoke", json={"reason": "compromised"})
    assert revoke_res.status_code == 200

    # 5. Verify Audit Chain
    audit_res = await test_app_client.get("/api/v1/audit/verify")
    assert audit_res.status_code == 200
    audit_data = audit_res.json()
    assert audit_data["valid"] is True
    assert audit_data["checked"] >= 4
