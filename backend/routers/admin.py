"""
NexDesk — Admin Router
Dashboard · Device management · Session oversight · Audit logs
"""
from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func, desc
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional, List
import logging

from services.database import get_db, ping_db
from services.security import verify_jwt
from models.device import Device, DeviceStatus
from models.session import Session, SessionStatus, AuditEvent
from config import settings

router = APIRouter()
bearer = HTTPBearer()
log = logging.getLogger("nexdesk.admin")

# Admin uses the JWT_SECRET[:32] as API key — in prod use a dedicated secret
ADMIN_KEY = settings.JWT_SECRET[:32]


# ── Auth ─────────────────────────────────────────────────
async def require_admin(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    if creds.credentials != ADMIN_KEY:
        raise HTTPException(403, "Accès administrateur requis")
    return True


# ── Dashboard ────────────────────────────────────────────
@router.get("/dashboard")
async def dashboard(admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    return {
        "total_devices":       (await db.execute(select(func.count()).select_from(Device))).scalar(),
        "online_devices":      (await db.execute(select(func.count()).where(Device.online == True))).scalar(),  # noqa
        "active_sessions":     (await db.execute(select(func.count()).where(Session.status == SessionStatus.ACTIVE))).scalar(),
        "sessions_today":      (await db.execute(select(func.count()).where(Session.started_at >= today))).scalar(),
        "banned_devices":      (await db.execute(select(func.count()).where(Device.status == DeviceStatus.BANNED))).scalar(),
        "db": await ping_db(),
    }


# ── Devices ──────────────────────────────────────────────
@router.get("/devices")
async def list_devices(
    status: Optional[str] = None,
    platform: Optional[str] = None,
    online: Optional[bool] = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    admin=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    q = select(Device)
    if status:   q = q.where(Device.status == status)
    if platform: q = q.where(Device.platform == platform)
    if online is not None: q = q.where(Device.online == online)
    r = await db.execute(q.order_by(desc(Device.created_at)).limit(limit).offset(offset))
    devices = r.scalars().all()
    return {"devices": devices, "count": len(devices)}


@router.post("/devices/{device_id}/ban")
async def ban_device(
    device_id: str,
    reason: Optional[str] = None,
    admin=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(select(Device).where(Device.id == device_id))
    if not r.scalar_one_or_none():
        raise HTTPException(404, "Appareil introuvable")
    await db.execute(
        update(Device).where(Device.id == device_id).values(
            status=DeviceStatus.BANNED, online=False, updated_at=datetime.utcnow()
        )
    )
    log.warning(f"Device {device_id} BANNED — {reason}")
    return {"ok": True, "reason": reason}


@router.post("/devices/{device_id}/unban")
async def unban_device(device_id: str, admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(
        update(Device).where(Device.id == device_id).values(
            status=DeviceStatus.ACTIVE, updated_at=datetime.utcnow()
        )
    )
    return {"ok": True}


# ── Sessions ─────────────────────────────────────────────
@router.get("/sessions")
async def list_sessions(
    status: Optional[str] = None,
    limit: int = Query(50, le=200),
    admin=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    q = select(Session)
    if status: q = q.where(Session.status == status)
    r = await db.execute(q.order_by(desc(Session.started_at)).limit(limit))
    return {"sessions": r.scalars().all()}


@router.delete("/sessions/{sid}/force")
async def force_end(sid: str, admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(Session).where(Session.id == sid))
    s = r.scalar_one_or_none()
    if not s:
        raise HTTPException(404, "Session introuvable")
    if s.status != SessionStatus.ACTIVE:
        raise HTTPException(400, "Session non active")
    now = datetime.utcnow()
    await db.execute(
        update(Session).where(Session.id == sid).values(
            status=SessionStatus.ENDED, end_reason="kicked", ended_at=now,
            duration_s=int((now - s.started_at).total_seconds()) if s.started_at else 0,
        )
    )
    log.warning(f"Session {sid[:8]} force-ended by admin")
    return {"ok": True}


# ── Audit ────────────────────────────────────────────────
@router.get("/audit")
async def get_audit(
    device_id: Optional[str] = None,
    event_type: Optional[str] = None,
    since_hours: int = 24,
    limit: int = Query(100, le=500),
    admin=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.utcnow() - timedelta(hours=since_hours)
    q = select(AuditEvent).where(AuditEvent.timestamp >= since)
    if device_id:   q = q.where(AuditEvent.device_id == device_id)
    if event_type:  q = q.where(AuditEvent.event_type == event_type)
    r = await db.execute(q.order_by(desc(AuditEvent.timestamp)).limit(limit))
    return {"events": r.scalars().all(), "since": since.isoformat()}


# ── Stats ────────────────────────────────────────────────
@router.get("/stats/platforms")
async def platform_stats(admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(Device.platform, func.count().label("n")).group_by(Device.platform))
    return [{"platform": row[0], "count": row[1]} for row in r.all()]
