from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.pop import verify_pop_signature
from app.db.models import Certificate, CertKind, Entity, RotationTrigger
from app.db.session import get_db_session
from app.pki.ca import CAEngine
from app.services.enrollment_service import EnrollmentError, enroll_device_mode_a
from app.services.rotation_service import RotationError, request_certificate_rotation

router = APIRouter(prefix="/pki", tags=["pki"])

class EnrollRequest(BaseModel):
    entity_id: str
    claim_token: str
    csr_pem: str

class RotateRequest(BaseModel):
    csr_pem: str
    trigger: Optional[RotationTrigger] = RotationTrigger.SCHEDULED

@router.get("/ca.pem", response_class=Response)
async def get_ca_pem() -> Response:
    ca = CAEngine()
    return Response(content=ca.ca_chain_pem, media_type="application/x-pem-file")

@router.get("/crl.pem", response_class=Response)
async def get_crl_pem() -> Response:
    crl_path = Path("./pki-state/crl.pem")
    if crl_path.exists():
        content = crl_path.read_text()
    else:
        content = ""
    return Response(content=content, media_type="application/x-pem-file")

@router.post("/enroll")
async def enroll_device(req: EnrollRequest, db: AsyncSession = Depends(get_db_session)) -> Dict[str, Any]:
    ca = CAEngine()
    try:
        res = await enroll_device_mode_a(db, ca, req.entity_id, req.claim_token, req.csr_pem)
        return res
    except EnrollmentError as e:
        raise HTTPException(
            status_code=400 if e.code == "invalid_csr" else 401 if e.code == "unauthorized" else 409 if e.code == "token_used" else 410 if e.code == "token_expired" else 400,
            detail={"error": {"code": e.code, "message": e.message}}
        )

@router.post("/rotate")
async def rotate_certificate(
    req: RotateRequest,
    pop_result: tuple[Entity, Certificate] = Depends(verify_pop_signature),
    db: AsyncSession = Depends(get_db_session)
) -> Dict[str, Any]:
    entity, current_cert = pop_result
    ca = CAEngine()
    try:
        res = await request_certificate_rotation(
            db, ca, entity, current_cert, req.csr_pem, trigger=req.trigger or RotationTrigger.SCHEDULED
        )
        return res
    except RotationError as e:
        raise HTTPException(
            status_code=403 if e.code == "forbidden" else 400,
            detail={"error": {"code": e.code, "message": e.message}}
        )
