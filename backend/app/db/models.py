import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum as SQLEnum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    LargeBinary,
    Numeric,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass

class EntityType(str, Enum):
    DEVICE = "device"
    USER = "user"
    SERVICE = "service"

class EntityState(str, Enum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"

class ProvMode(str, Enum):
    CLAIM_TOKEN = "claim_token"
    FACTORY = "factory"

class CertKind(str, Enum):
    BOOTSTRAP = "bootstrap"
    OPERATIONAL = "operational"

class CertStatus(str, Enum):
    ISSUED = "issued"
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"

class IssuedVia(str, Enum):
    ENROLL = "enroll"
    PROVISION = "provision"
    ROTATE = "rotate"

class RotationTrigger(str, Enum):
    SCHEDULED = "scheduled"
    MANUAL = "manual"
    EMERGENCY = "emergency"
    RECOVERY = "recovery"

class RotationStatus(str, Enum):
    ISSUED = "issued"
    CONFIRMED = "confirmed"
    TIMEOUT = "timeout"

class DashRole(str, Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"

class DashboardUser(Base):
    __tablename__ = "dashboard_users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[DashRole] = mapped_column(SQLEnum(DashRole, name="dash_role"), nullable=False)
    totp_secret_enc: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

class Role(Base):
    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(String, primary_key=True)
    entity_type: Mapped[EntityType] = mapped_column(SQLEnum(EntityType, name="entity_type"), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cert_lifetime_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    renew_at_pct: Mapped[int] = mapped_column(Integer, nullable=False)
    pub_topics: Mapped[List[str]] = mapped_column(JSON, nullable=False)
    sub_topics: Mapped[List[str]] = mapped_column(JSON, nullable=False)
    builtin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

class Entity(Base):
    __tablename__ = "entities"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    entity_type: Mapped[EntityType] = mapped_column(SQLEnum(EntityType, name="entity_type"), nullable=False)
    display_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    role_name: Mapped[str] = mapped_column(String, ForeignKey("roles.name"), nullable=False)
    state: Mapped[EntityState] = mapped_column(SQLEnum(EntityState, name="entity_state"), default=EntityState.PENDING, nullable=False)
    provisioning_mode: Mapped[ProvMode] = mapped_column(SQLEnum(ProvMode, name="prov_mode"), nullable=False)
    hw_model: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    fw_version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    online: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    current_cert_serial: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    metadata_: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("dashboard_users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoke_reason: Mapped[Optional[str]] = mapped_column(String, nullable=True)

class ClaimToken(Base):
    __tablename__ = "claim_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id: Mapped[str] = mapped_column(String(32), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("dashboard_users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class Certificate(Base):
    __tablename__ = "certificates"

    serial: Mapped[str] = mapped_column(String, primary_key=True)
    entity_id: Mapped[str] = mapped_column(String(32), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[CertKind] = mapped_column(SQLEnum(CertKind, name="cert_kind"), nullable=False)
    status: Mapped[CertStatus] = mapped_column(SQLEnum(CertStatus, name="cert_status"), nullable=False)
    issued_via: Mapped[IssuedVia] = mapped_column(SQLEnum(IssuedVia, name="issued_via"), nullable=False)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    fingerprint_sha256: Mapped[str] = mapped_column(String, nullable=False)
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    cert_pem: Mapped[str] = mapped_column(Text, nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoke_reason: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("idx_certificates_entity_status", "entity_id", "status"),
    )

class RotationEvent(Base):
    __tablename__ = "rotation_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entity_id: Mapped[str] = mapped_column(String(32), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False)
    old_serial: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    new_serial: Mapped[str] = mapped_column(String, nullable=False)
    trigger: Mapped[RotationTrigger] = mapped_column(SQLEnum(RotationTrigger, name="rotation_trigger"), nullable=False)
    status: Mapped[RotationStatus] = mapped_column(SQLEnum(RotationStatus, name="rotation_status"), nullable=False)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    confirmed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

class PopNonce(Base):
    __tablename__ = "pop_nonces"

    entity_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(32), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    category: Mapped[str] = mapped_column(String, nullable=False)
    action: Mapped[str] = mapped_column(String, nullable=False)
    actor_type: Mapped[str] = mapped_column(String, nullable=False)
    actor_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    entity_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    outcome: Mapped[str] = mapped_column(String, nullable=False)
    detail: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    prev_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

class Telemetry(Base):
    __tablename__ = "telemetry"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entity_id: Mapped[str] = mapped_column(String(32), nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    payload: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)

    __table_args__ = (
        Index("idx_telemetry_entity_ts", "entity_id", ts.desc()),
    )

class Benchmark(Base):
    __tablename__ = "benchmarks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    entity_id: Mapped[str] = mapped_column(String(32), nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    algorithm: Mapped[str] = mapped_column(String, nullable=False)
    operation: Mapped[str] = mapped_column(String, nullable=False)
    iterations: Mapped[int] = mapped_column(Integer, nullable=False)
    avg_ms: Mapped[float] = mapped_column(Numeric(10, 3), nullable=False)
    heap_bytes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    extra: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

class ChatKey(Base):
    __tablename__ = "chat_keys"

    kid: Mapped[str] = mapped_column(String(16), primary_key=True)
    entity_id: Mapped[str] = mapped_column(String(32), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False)
    enc_public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    signing_serial: Mapped[str] = mapped_column(String, ForeignKey("certificates.serial"), nullable=False)
    signature: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    status: Mapped[str] = mapped_column(String, default="active", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class CAState(Base):
    __tablename__ = "ca_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    crl_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    crl_updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)

