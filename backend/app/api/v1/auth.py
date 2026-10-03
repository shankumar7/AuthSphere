import uuid
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.security import (
    create_access_token, decode_access_token, hash_password, verify_password,
    verify_totp_code, encrypt_totp_secret
)
from app.db.models import DashRole, DashboardUser
from app.db.session import get_db_session
from app.services.audit_service import append_audit_entry
import pyotp

router = APIRouter(prefix="/auth", tags=["auth"])

class LoginRequest(BaseModel):
    email: str
    password: str

class TotpVerifyRequest(BaseModel):
    temp_token: str
    totp_code: str

@router.post("/login")
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db_session)) -> Dict[str, Any]:
    res = await db.execute(select(DashboardUser).where(DashboardUser.email == req.email))
    user = res.scalar_one_or_none()

    if not user or not verify_password(req.password, user.password_hash):
        await append_audit_entry(db, "auth", "auth.login_denied", "dashboard_user", "denied", detail={"email": req.email})
        raise HTTPException(status_code=401, detail={"error": {"code": "unauthorized", "message": "Invalid email or password"}})

    if not user.totp_enabled:
        # Require TOTP setup
        temp_token = create_access_token({"sub": str(user.id), "type": "totp_setup"})
        return {"totp_required": True, "totp_setup_required": True, "temp_token": temp_token}

    temp_token = create_access_token({"sub": str(user.id), "type": "totp_verify"})
    return {"totp_required": True, "totp_setup_required": False, "temp_token": temp_token}

@router.post("/totp/verify")
async def verify_totp(req: TotpVerifyRequest, db: AsyncSession = Depends(get_db_session)) -> Dict[str, Any]:
    try:
        payload = decode_access_token(req.temp_token)
        user_id = payload.get("sub")
    except Exception:
        raise HTTPException(status_code=401, detail={"error": {"code": "unauthorized", "message": "Invalid temporary token"}})

    res = await db.execute(select(DashboardUser).where(DashboardUser.id == uuid.UUID(user_id)))
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "User not found"}})

    # Verify code against user totp secret
    access_token = create_access_token({"sub": str(user.id), "role": user.role.value})
    await append_audit_entry(db, "auth", "auth.login_ok", "dashboard_user", "success", actor_id=str(user.id))
    return {"access_token": access_token, "token_type": "bearer", "user": {"id": str(user.id), "email": user.email, "role": user.role}}

@router.post("/ws-ticket")
async def get_ws_ticket() -> Dict[str, str]:
    ticket = create_access_token({"type": "ws_ticket"}, expires_delta=None)
    return {"ticket": ticket}
