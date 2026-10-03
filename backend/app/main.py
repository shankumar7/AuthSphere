from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.config import settings
from app.db.models import Base, Role, EntityType
from app.db.session import engine, async_session_factory
from app.api.v1.auth import router as auth_router
from app.api.v1.pki import router as pki_router
from app.api.v1.entities import router as entities_router
from app.api.v1.audit import router as audit_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Seed default roles if missing
    async with async_session_factory() as session:
        res = await session.execute(select(Role).where(Role.name == "sensor"))
        if not res.scalar_one_or_none():
            roles = [
                Role(name="sensor", entity_type=EntityType.DEVICE, cert_lifetime_seconds=604800, renew_at_pct=66, pub_topics=["devices/%u/status", "devices/%u/telemetry", "devices/%u/benchmark", "devices/%u/ack"], sub_topics=["devices/%u/cmd/#"], builtin=True),
                Role(name="actuator", entity_type=EntityType.DEVICE, cert_lifetime_seconds=604800, renew_at_pct=66, pub_topics=["devices/%u/status", "devices/%u/telemetry", "devices/%u/benchmark", "devices/%u/ack"], sub_topics=["devices/%u/cmd/#"], builtin=True),
                Role(name="chat-user", entity_type=EntityType.USER, cert_lifetime_seconds=604800, renew_at_pct=66, pub_topics=["chat/+/inbox", "users/%u/status"], sub_topics=["chat/%u/inbox"], builtin=True),
            ]
            session.add_all(roles)
            await session.commit()
    yield

app = FastAPI(
    title="AuthSphere API",
    version="1.0.0",
    description="AuthSphere Device and User Authentication API",
    docs_url="/api/v1/docs" if settings.ENV != "prod" else None,
    redoc_url=None,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/api/v1")
app.include_router(pki_router, prefix="/api/v1")
app.include_router(entities_router, prefix="/api/v1")
app.include_router(audit_router, prefix="/api/v1")

@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok", "environment": settings.ENV}

@app.get("/api/v1/health")
async def api_health_check() -> dict[str, str]:
    return {"status": "ok", "environment": settings.ENV}
