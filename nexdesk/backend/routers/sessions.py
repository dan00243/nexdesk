"""
NexDesk — Sessions Router
Create · End · History · Events · Stats
"""
from fastapi import APIRouter, HTTPException, Depends, Query, Body
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, or_, desc, func
from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List
from uuid import uuid4
import logging

from services.database import get_db
from services.security import verify_jwt
from models.device import Device, DeviceStatus
from models.session import Session, SessionStatus, EndReason, AuditEvent

router = APIRouter()
bearer = HTTPBearer()
log = logging.getLogger("nexdesk.sessions")


# ── Auth ─────────────────────────────────────────────────
async def current_device(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
    db: AsyncSession = Depends(get_db),
) -> Device:
    payload = verify_jwt(creds.credentials)
    if not payload:
        raise HTTPException(401, "Token invalide")
    r = await db.execute(select(Device).where(Device.id == payload.get("sub")))
    dev = r.scalar_one_or_none()
    if not dev or dev.status == DeviceStatus.BANNED:
        raise HTTPException(403, "Accès refusé")
    return dev


# ── Schemas ───────────────────────────────────────────────
class CreateIn(BaseModel):
    host_id: str
    controller_id: str
    view_only: bool = False
    quality: str = "balanced"

class SessionOut(BaseModel):
    id: str; status: str
    host_id: Optional[str]; controller_id: Optional[str]
    started_at: Optional[datetime]; ended_at: Optional[datetime]
    duration_s: Optional[int]; view_only: bool; quality: str
    bytes_sent: int; bytes_recv: int
    avg_latency: Optional[float]; avg_fps: Optional[float]
    end_reason: Optional[str]
    class Config: from_attributes = True

class EndIn(BaseModel):
    reason: str = "normal"
    error: Optional[str] = None

class EventIn(BaseModel):
    event_type: str
    detail: dict = {}

class StatsIn(BaseModel):
    bytes_sent: Optional[int] = None
    bytes_recv: Optional[int] = None
    avg_latency: Optional[float] = None
    avg_fps: Optional[float] = None


# ── Create ───────────────────────────────────────────────
@router.post("/", response_model=SessionOut, status_code=201)
async def create_session(
    body: CreateIn,
    dev: Device = Depends(current_device),
    db: AsyncSession = Depends(get_db),
):
    # Check max concurrent (5 per host)
    count = (await db.execute(
        select(func.count()).where(Session.host_id == body.host_id, Session.status == SessionStatus.ACTIVE)
    )).scalar()
    if count >= 5:
        raise HTTPException(429, "Nombre maximum de sessions simultanées atteint")

    now = datetime.utcnow()
    session = Session(
        id=str(uuid4()),
        status=SessionStatus.ACTIVE,
        host_id=body.host_id,
        controller_id=body.controller_id,
        view_only=body.view_only,
        quality=body.quality,
        started_at=now,
    )
    db.add(session)
    await db.flush()

    db.add(AuditEvent(
        session_id=session.id, device_id=body.controller_id,
        event_type="started",
        detail={"host": body.host_id, "view_only": body.view_only},
    ))
    log.info(f"Session {session.id[:8]} — {body.controller_id} → {body.host_id}")
    return session


# ── List active ──────────────────────────────────────────
@router.get("/active", response_model=List[SessionOut])
async def active_sessions(dev: Device = Depends(current_device), db: AsyncSession = Depends(get_db)):
    r = await db.execute(
        select(Session).where(
            or_(Session.host_id == dev.id, Session.controller_id == dev.id),
            Session.status == SessionStatus.ACTIVE,
        )
    )
    return r.scalars().all()


# ── History ──────────────────────────────────────────────
@router.get("/history", response_model=List[SessionOut])
async def history(
    limit: int = Query(50, le=200),
    offset: int = 0,
    dev: Device = Depends(current_device),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(
        select(Session)
        .where(or_(Session.host_id == dev.id, Session.controller_id == dev.id))
        .order_by(desc(Session.started_at))
        .limit(limit).offset(offset)
    )
    return r.scalars().all()


# ── Get one ──────────────────────────────────────────────
@router.get("/{sid}", response_model=SessionOut)
async def get_session(
    sid: str, dev: Device = Depends(current_device), db: AsyncSession = Depends(get_db)
):
    r = await db.execute(select(Session).where(Session.id == sid))
    s = r.scalar_one_or_none()
    if not s:
        raise HTTPException(404, "Session introuvable")
    if dev.id not in [s.host_id, s.controller_id]:
        raise HTTPException(403, "Accès refusé")
    return s


# ── End ──────────────────────────────────────────────────
@router.delete("/{sid}")
async def end_session(
    sid: str,
    body: EndIn = Body(default=EndIn()),
    dev: Device = Depends(current_device),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(select(Session).where(Session.id == sid))
    s = r.scalar_one_or_none()
    if not s:
        raise HTTPException(404, "Session introuvable")
    if dev.id not in [s.host_id, s.controller_id]:
        raise HTTPException(403, "Accès refusé")
    if s.status != SessionStatus.ACTIVE:
        raise HTTPException(400, "Session non active")

    now = datetime.utcnow()
    duration = int((now - s.started_at).total_seconds()) if s.started_at else 0
    await db.execute(
        update(Session).where(Session.id == sid).values(
            status=SessionStatus.ENDED, end_reason=body.reason,
            error_msg=body.error, ended_at=now, duration_s=duration,
        )
    )
    db.add(AuditEvent(session_id=sid, device_id=dev.id, event_type="ended",
                      detail={"reason": body.reason, "duration_s": duration}))
    log.info(f"Session {sid[:8]} ended by {dev.id} after {duration}s")
    return {"ok": True, "duration_s": duration}


# ── Log event ────────────────────────────────────────────
@router.post("/{sid}/event")
async def log_event(
    sid: str, body: EventIn,
    dev: Device = Depends(current_device), db: AsyncSession = Depends(get_db)
):
    r = await db.execute(select(Session).where(Session.id == sid))
    s = r.scalar_one_or_none()
    if not s or dev.id not in [s.host_id, s.controller_id]:
        raise HTTPException(403, "Accès refusé")
    db.add(AuditEvent(session_id=sid, device_id=dev.id,
                      event_type=body.event_type, detail=body.detail))
    return {"ok": True}


# ── Update stats ─────────────────────────────────────────
@router.patch("/{sid}/stats")
async def update_stats(
    sid: str, body: StatsIn,
    dev: Device = Depends(current_device), db: AsyncSession = Depends(get_db)
):
    vals = {k: v for k, v in body.dict().items() if v is not None}
    if vals:
        await db.execute(update(Session).where(Session.id == sid).values(**vals))
    return {"ok": True}


# ── Get events ───────────────────────────────────────────
@router.get("/{sid}/events")
async def get_events(
    sid: str, dev: Device = Depends(current_device), db: AsyncSession = Depends(get_db)
):
    r = await db.execute(select(Session).where(Session.id == sid))
    s = r.scalar_one_or_none()
    if not s or dev.id not in [s.host_id, s.controller_id]:
        raise HTTPException(403, "Accès refusé")
    evts = await db.execute(
        select(AuditEvent).where(AuditEvent.session_id == sid).order_by(AuditEvent.timestamp)
    )
    return {"events": evts.scalars().all()}
