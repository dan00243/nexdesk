"""
NexDesk — Devices Router
Device info · Whitelist management
"""
from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func, desc
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional, List
import logging

from services.database import get_db
from services.security import verify_jwt
from models.device import Device, DeviceStatus, WhitelistEntry

router = APIRouter()
bearer = HTTPBearer()
log = logging.getLogger("nexdesk.devices")


# ── Auth dependency ───────────────────────────────────────
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
class DeviceOut(BaseModel):
    id: str; name: str; platform: str; status: str
    online: bool; last_seen: Optional[datetime]; created_at: datetime
    allow_unattended: bool
    class Config: from_attributes = True

class UpdateIn(BaseModel):
    name: Optional[str] = None
    allow_unattended: Optional[bool] = None

class WhitelistIn(BaseModel):
    trusted_device_id: str
    label: Optional[str] = None
    expires_hours: Optional[int] = None

class WhitelistOut(BaseModel):
    id: int; device_id: str; trusted_device_id: str
    label: Optional[str]; created_at: datetime; expires_at: Optional[datetime]
    class Config: from_attributes = True


# ── Me ───────────────────────────────────────────────────
@router.get("/me", response_model=DeviceOut)
async def get_me(dev: Device = Depends(current_device)):
    return dev

@router.patch("/me", response_model=DeviceOut)
async def update_me(
    body: UpdateIn,
    dev: Device = Depends(current_device),
    db: AsyncSession = Depends(get_db),
):
    vals = {k: v for k, v in body.dict().items() if v is not None}
    if vals:
        vals["updated_at"] = datetime.utcnow()
        await db.execute(update(Device).where(Device.id == dev.id).values(**vals))
        await db.refresh(dev)
    return dev


# ── Get device ───────────────────────────────────────────
@router.get("/{device_id}", response_model=DeviceOut)
async def get_device(
    device_id: str,
    _: Device = Depends(current_device),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(select(Device).where(Device.id == device_id))
    dev = r.scalar_one_or_none()
    if not dev:
        raise HTTPException(404, "Appareil introuvable")
    return dev


# ── Online devices ───────────────────────────────────────
@router.get("/", response_model=List[DeviceOut])
async def list_online(
    _: Device = Depends(current_device),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(
        select(Device)
        .where(Device.online == True, Device.status == DeviceStatus.ACTIVE)  # noqa
        .order_by(desc(Device.last_seen)).limit(50)
    )
    return r.scalars().all()


# ── Whitelist ────────────────────────────────────────────
@router.get("/me/whitelist", response_model=List[WhitelistOut])
async def get_whitelist(dev: Device = Depends(current_device), db: AsyncSession = Depends(get_db)):
    r = await db.execute(
        select(WhitelistEntry).where(WhitelistEntry.device_id == dev.id)
        .order_by(desc(WhitelistEntry.created_at))
    )
    return r.scalars().all()


@router.post("/me/whitelist", response_model=WhitelistOut, status_code=201)
async def add_whitelist(
    body: WhitelistIn,
    dev: Device = Depends(current_device),
    db: AsyncSession = Depends(get_db),
):
    if body.trusted_device_id == dev.id:
        raise HTTPException(400, "Impossible de s'ajouter soi-même")

    # Target exists?
    r = await db.execute(select(Device).where(Device.id == body.trusted_device_id))
    if not r.scalar_one_or_none():
        raise HTTPException(404, "Appareil introuvable")

    # Duplicate?
    r = await db.execute(
        select(WhitelistEntry).where(
            WhitelistEntry.device_id == dev.id,
            WhitelistEntry.trusted_device_id == body.trusted_device_id,
        )
    )
    if r.scalar_one_or_none():
        raise HTTPException(409, "Déjà dans la liste blanche")

    exp = datetime.utcnow() + timedelta(hours=body.expires_hours) if body.expires_hours else None
    entry = WhitelistEntry(
        device_id=dev.id, trusted_device_id=body.trusted_device_id,
        label=body.label, expires_at=exp,
    )
    db.add(entry)
    await db.flush()
    await db.refresh(entry)
    log.info(f"Whitelist: {body.trusted_device_id} → {dev.id}")
    return entry


@router.delete("/me/whitelist/{entry_id}", status_code=204)
async def remove_whitelist(
    entry_id: int,
    dev: Device = Depends(current_device),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(
        select(WhitelistEntry).where(
            WhitelistEntry.id == entry_id,
            WhitelistEntry.device_id == dev.id,
        )
    )
    entry = r.scalar_one_or_none()
    if not entry:
        raise HTTPException(404, "Entrée introuvable")
    await db.delete(entry)


# ── Stats ────────────────────────────────────────────────
@router.get("/me/stats")
async def my_stats(dev: Device = Depends(current_device), db: AsyncSession = Depends(get_db)):
    from models.session import Session, SessionStatus
    host_count = (await db.execute(
        select(func.count()).where(Session.host_id == dev.id, Session.status == SessionStatus.ENDED)
    )).scalar()
    ctrl_count = (await db.execute(
        select(func.count()).where(Session.controller_id == dev.id, Session.status == SessionStatus.ENDED)
    )).scalar()
    wl_count = (await db.execute(
        select(func.count()).where(WhitelistEntry.device_id == dev.id)
    )).scalar()
    return {
        "device_id": dev.id,
        "sessions_as_host": host_count,
        "sessions_as_controller": ctrl_count,
        "whitelist_size": wl_count,
        "online": dev.online,
        "last_seen": dev.last_seen,
    }
