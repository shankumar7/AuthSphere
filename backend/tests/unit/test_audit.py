import pytest
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from app.db.models import Base, AuditLog
from app.services.audit_service import append_audit_entry, verify_audit_chain

@pytest.fixture
def anyio_backend():
    return 'asyncio'

@pytest.fixture
async def async_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as session:
        yield session

    await engine.dispose()

@pytest.mark.anyio
async def test_audit_hash_chain_validity(async_db):
    row1 = await append_audit_entry(
        async_db, category="entity", action="entity.create", actor_type="dashboard_user",
        outcome="success", entity_id="dev-demo-01", detail={"mode": "claim_token"}
    )
    row2 = await append_audit_entry(
        async_db, category="pki", action="pki.enroll_ok", actor_type="entity",
        outcome="success", entity_id="dev-demo-01", detail={"serial": "1234abcd"}
    )

    res = await verify_audit_chain(async_db)
    assert res["valid"] is True
    assert res["checked"] == 2
    assert res["first_bad_id"] is None

@pytest.mark.anyio
async def test_audit_hash_chain_tamper_detection(async_db):
    row1 = await append_audit_entry(
        async_db, category="entity", action="entity.create", actor_type="dashboard_user",
        outcome="success", entity_id="dev-demo-01"
    )
    row2 = await append_audit_entry(
        async_db, category="pki", action="pki.enroll_ok", actor_type="entity",
        outcome="success", entity_id="dev-demo-01"
    )

    # Tamper with row 1 action text directly
    row1.action = "tampered.action"
    await async_db.commit()

    res = await verify_audit_chain(async_db)
    assert res["valid"] is False
    assert res["first_bad_id"] == row1.id
