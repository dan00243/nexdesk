"""
NexDesk — Auth Router
Register · Passwords · Connection validation · Heartbeat
"""
from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from pydantic import BaseModel, field_validator
from datetime import datetime, timedelta
from typing import Optional
import re, logging

from services.database import get_db
from services.security import (
    hash_password, verify_password, create_jwt, verify_jwt,
    generate_temp_password, brute_force
)
from models.device import Device, DeviceStatus, Platform, WhitelistEntry
from config import settings

router = APIRouter()
bearer = HTTPBearer()
log = logging.getLogger("nexdesk.auth")


# ── Schemas ───────────────────────────────────────────────
class RegisterIn(BaseModel):
    device_id: str
    name: str
    public_key: str
    platform: str
    os_version: Optional[str] = None
    app_version: Optional[str] = None

    @field_validator("device_id")
    @classmethod
    def check_id(cls, v):
        if not re.match(r"^[A-Z0-9]{3}-[A-Z0-9]{3}-[A-Z0-9]{3}$", v):
            raise ValueError("Format ID invalide")
        return v

    @field_validator("platform")
    @classmethod
    def check_platform(cls, v):
        if v not in {p.value for p in Platform}:
            raise ValueError("Plateforme invalide")
        return v


class ConnectIn(BaseModel):
    target_id: str
    password: str


class SetPasswordIn(BaseModel):
    password: str
    permanent: bool = False
    allow_unattended: Optional[bool] = None


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    device_id: str


# ── Dependency ────────────────────────────────────────────
async def current_device(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
    db: AsyncSession = Depends(get_db),
) -> Device:
    payload = verify_jwt(creds.credentials)
    if not payload:
        raise HTTPException(401, "Token invalide ou expiré")
    r = await db.execute(select(Device).where(Device.id == payload.get("sub")))
    device = r.scalar_one_or_none()
    if not device or device.status == DeviceStatus.BANNED:
        raise HTTPException(403, "Appareil non autorisé")
    return device


# ── Register ─────────────────────────────────────────────
@router.post("/register", response_model=TokenOut, status_code=201)
async def register(body: RegisterIn, request: Request, db: AsyncSession = Depends(get_db)):
    """Enregistre ou met à jour un appareil. Retourne un JWT."""
    ip = request.client.host
    r = await db.execute(select(Device).where(Device.id == body.device_id))
    device = r.scalar_one_or_none()

    if device:
        if device.status == DeviceStatus.BANNED:
            raise HTTPException(403, "Appareil banni")
        await db.execute(
            update(Device).where(Device.id == body.device_id).values(
                name=body.name, public_key=body.public_key,
                platform=body.platform, os_version=body.os_version,
                app_version=body.app_version, online=True,
                last_ip=ip, last_seen=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
        )
    else:
        db.add(Device(
            id=body.device_id, name=body.name, public_key=body.public_key,
            platform=body.platform, os_version=body.os_version,
            app_version=body.app_version, online=True,
            last_ip=ip, last_seen=datetime.utcnow(),
        ))
        await db.flush()
    log.info(f"Device {body.device_id} registered from {ip}")

    return TokenOut(
        access_token=create_jwt({"sub": body.device_id}),
        expires_in=86400, device_id=body.device_id,
    )


# ── Generate temp password ───────────────────────────────
@router.post("/generate-password")
async def generate_password(
    dev: Device = Depends(current_device),
    db: AsyncSession = Depends(get_db),
):
    """Génère un mot de passe temporaire (8 chars, expire 10 min)."""
    pw = generate_temp_password()
    exp = datetime.utcnow() + timedelta(minutes=settings.TEMP_PASSWORD_TTL_MIN)
    await db.execute(
        update(Device).where(Device.id == dev.id).values(
            temp_pw_hash=hash_password(pw), temp_pw_exp=exp, updated_at=datetime.utcnow()
        )
    )
    log.info(f"Temp password generated for {dev.id}")
    return {"password": pw, "expires_at": exp.isoformat(), "expires_in_seconds": settings.TEMP_PASSWORD_TTL_MIN * 60}


# ── Set permanent password ───────────────────────────────
@router.post("/set-password")
async def set_password(
    body: SetPasswordIn,
    dev: Device = Depends(current_device),
    db: AsyncSession = Depends(get_db),
):
    if len(body.password) < 6:
        raise HTTPException(400, "Mot de passe trop court (min 6 caractères)")
    vals: dict = {"updated_at": datetime.utcnow()}
    if body.permanent:
        vals.update(perm_pw_hash=hash_password(body.password), temp_pw_hash=None, temp_pw_exp=None)
    else:
        vals.update(
            temp_pw_hash=hash_password(body.password),
            temp_pw_exp=datetime.utcnow() + timedelta(minutes=settings.TEMP_PASSWORD_TTL_MIN),
        )
    if body.allow_unattended is not None:
        vals["allow_unattended"] = body.allow_unattended
    await db.execute(update(Device).where(Device.id == dev.id).values(**vals))
    return {"success": True}


# ── Clear password ───────────────────────────────────────
@router.delete("/password")
async def clear_password(dev: Device = Depends(current_device), db: AsyncSession = Depends(get_db)):
    await db.execute(
        update(Device).where(Device.id == dev.id).values(
            temp_pw_hash=None, temp_pw_exp=None, perm_pw_hash=None,
            allow_unattended=False, updated_at=datetime.utcnow(),
        )
    )
    return {"success": True}


# ── Validate connection ──────────────────────────────────
@router.post("/connect")
async def validate_connection(
    body: ConnectIn,
    dev: Device = Depends(current_device),
    db: AsyncSession = Depends(get_db),
):
    """Valide qu'un contrôleur peut se connecter à l'hôte cible."""
    key = f"conn:{dev.id}→{body.target_id}"

    if brute_force.is_locked(key):
        raise HTTPException(429, "Trop de tentatives. Réessayez dans 15 minutes.")

    # Load target
    r = await db.execute(select(Device).where(Device.id == body.target_id))
    target = r.scalar_one_or_none()
    if not target:
        raise HTTPException(404, "Appareil introuvable")
    if target.status == DeviceStatus.BANNED:
        raise HTTPException(403, "Appareil banni")
    if not target.online:
        raise HTTPException(409, "L'appareil est hors ligne")

    # Whitelist check
    wl = await db.execute(
        select(WhitelistEntry).where(
            WhitelistEntry.device_id == body.target_id,
            WhitelistEntry.trusted_device_id == dev.id,
        )
    )
    entry = wl.scalar_one_or_none()
    if entry and (not entry.expires_at or datetime.utcnow() <= entry.expires_at):
        brute_force.reset(key)
        return {"authorized": True, "requires_confirmation": False,
                "method": "whitelist", "public_key": target.public_key}

    # Permanent password
    if target.perm_pw_hash:
        if not verify_password(body.password, target.perm_pw_hash):
            count = brute_force.record_failure(key)
            raise HTTPException(401, f"Mot de passe incorrect ({count}/{brute_force.MAX_ATTEMPTS})")
        brute_force.reset(key)
        return {"authorized": True, "requires_confirmation": not target.allow_unattended,
                "method": "permanent", "public_key": target.public_key}

    # Temporary password
    if target.temp_pw_hash:
        if target.temp_pw_exp and datetime.utcnow() > target.temp_pw_exp:
            raise HTTPException(401, "Mot de passe temporaire expiré")
        if not verify_password(body.password, target.temp_pw_hash):
            count = brute_force.record_failure(key)
            raise HTTPException(401, f"Mot de passe incorrect ({count}/{brute_force.MAX_ATTEMPTS})")
        brute_force.reset(key)
        return {"authorized": True, "requires_confirmation": True,
                "method": "temporary", "public_key": target.public_key}

    raise HTTPException(401, "Aucun mot de passe configuré sur cet appareil")


# ── Public key ───────────────────────────────────────────
@router.get("/pubkey/{device_id}")
async def get_pubkey(
    device_id: str,
    _: Device = Depends(current_device),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(select(Device.id, Device.public_key).where(Device.id == device_id))
    row = r.first()
    if not row:
        raise HTTPException(404, "Appareil introuvable")
    return {"device_id": device_id, "public_key": row.public_key}


# ── Heartbeat ────────────────────────────────────────────
@router.post("/heartbeat")
async def heartbeat(
    request: Request,
    dev: Device = Depends(current_device),
    db: AsyncSession = Depends(get_db),
):
    """Maintient le device en ligne (toutes les 30s)."""
    await db.execute(
        update(Device).where(Device.id == dev.id).values(
            online=True, last_seen=datetime.utcnow(), last_ip=request.client.host,
        )
    )
    return {"ok": True}


# ── Logout ───────────────────────────────────────────────
@router.post("/logout")
async def logout(dev: Device = Depends(current_device), db: AsyncSession = Depends(get_db)):
    await db.execute(
        update(Device).where(Device.id == dev.id).values(online=False, updated_at=datetime.utcnow())
    )
    return {"status": "offline"}


# ── Refresh ──────────────────────────────────────────────
@router.post("/refresh", response_model=TokenOut)
async def refresh(dev: Device = Depends(current_device)):
    return TokenOut(
        access_token=create_jwt({"sub": dev.id}),
        expires_in=86400, device_id=dev.id,
    )
