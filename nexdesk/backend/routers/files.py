"""
NexDesk — File Transfer Router
Chunked upload · SHA-256 integrity · Download
"""
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, BackgroundTasks
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, or_
from pydantic import BaseModel
from pathlib import Path
import aiofiles, hashlib, asyncio, logging
from datetime import datetime
from typing import Optional
from uuid import uuid4

from services.database import get_db
from services.security import verify_jwt
from models.device import Device, DeviceStatus
from models.session import Session, SessionStatus, FileTransfer
from config import settings

router = APIRouter()
bearer = HTTPBearer()
log = logging.getLogger("nexdesk.files")

UPLOAD_DIR = Path(settings.UPLOAD_DIR)
MAX_SIZE = settings.MAX_FILE_MB * 1024 * 1024
CHUNK = settings.CHUNK_SIZE


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


async def get_active_session(session_id: str, device_id: str, db: AsyncSession) -> Session:
    r = await db.execute(select(Session).where(Session.id == session_id))
    s = r.scalar_one_or_none()
    if not s:
        raise HTTPException(404, "Session introuvable")
    if device_id not in [s.host_id, s.controller_id]:
        raise HTTPException(403, "Accès refusé")
    if s.status != SessionStatus.ACTIVE:
        raise HTTPException(400, "Session non active")
    if not s.allow_files:
        raise HTTPException(403, "Transferts désactivés dans cette session")
    return s


# ── Schemas ───────────────────────────────────────────────
class InitIn(BaseModel):
    session_id: str
    filename: str
    file_size: int
    sha256: str
    mime_type: Optional[str] = None


# ── Init transfer ────────────────────────────────────────
@router.post("/init", status_code=201)
async def init_transfer(
    body: InitIn,
    dev: Device = Depends(current_device),
    db: AsyncSession = Depends(get_db),
):
    if body.file_size > MAX_SIZE:
        raise HTTPException(413, f"Fichier trop volumineux (max {settings.MAX_FILE_MB} MB)")

    await get_active_session(body.session_id, dev.id, db)

    total_chunks = (body.file_size + CHUNK - 1) // CHUNK
    xfer = FileTransfer(
        session_id=body.session_id,
        sender_id=dev.id,
        filename=body.filename,
        mime_type=body.mime_type,
        size_bytes=body.file_size,
        sha256=body.sha256,
        status="pending",
    )
    db.add(xfer)
    await db.flush()
    await db.refresh(xfer)

    # Create chunk directory
    chunk_dir = UPLOAD_DIR / str(xfer.id)
    chunk_dir.mkdir(parents=True, exist_ok=True)
    await db.execute(
        update(FileTransfer).where(FileTransfer.id == xfer.id).values(storage_path=str(chunk_dir))
    )

    log.info(f"Transfer {xfer.id} init: {body.filename} ({body.file_size}B, {total_chunks} chunks)")
    return {"transfer_id": xfer.id, "chunk_size": CHUNK, "total_chunks": total_chunks}


# ── Upload chunk ─────────────────────────────────────────
@router.post("/{transfer_id}/chunk/{index}")
async def upload_chunk(
    transfer_id: int,
    index: int,
    chunk: UploadFile = File(...),
    dev: Device = Depends(current_device),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(select(FileTransfer).where(FileTransfer.id == transfer_id))
    xfer = r.scalar_one_or_none()
    if not xfer or xfer.sender_id != dev.id:
        raise HTTPException(404, "Transfert introuvable")

    content = await chunk.read()
    chunk_path = Path(xfer.storage_path) / f"{index:06d}"
    async with aiofiles.open(chunk_path, "wb") as f:
        await f.write(content)

    await db.execute(
        update(FileTransfer).where(FileTransfer.id == transfer_id).values(status="in_progress")
    )
    return {"index": index, "bytes": len(content)}


# ── Finalize ─────────────────────────────────────────────
@router.post("/{transfer_id}/finalize")
async def finalize(
    transfer_id: int,
    bg: BackgroundTasks,
    dev: Device = Depends(current_device),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(select(FileTransfer).where(FileTransfer.id == transfer_id))
    xfer = r.scalar_one_or_none()
    if not xfer or xfer.sender_id != dev.id:
        raise HTTPException(404, "Transfert introuvable")

    chunk_dir = Path(xfer.storage_path)
    final_path = UPLOAD_DIR / f"{transfer_id}_{xfer.filename}"
    sha256 = hashlib.sha256()

    chunks = sorted(chunk_dir.glob("*"), key=lambda p: int(p.name))
    if not chunks:
        raise HTTPException(400, "Aucun chunk reçu")

    async with aiofiles.open(final_path, "wb") as out:
        for cp in chunks:
            async with aiofiles.open(cp, "rb") as f:
                data = await f.read()
                await out.write(data)
                sha256.update(data)

    computed = sha256.hexdigest()
    if computed != xfer.sha256:
        final_path.unlink(missing_ok=True)
        await db.execute(update(FileTransfer).where(FileTransfer.id == transfer_id).values(status="failed"))
        raise HTTPException(422, "Intégrité SHA-256 invalide")

    await db.execute(
        update(FileTransfer).where(FileTransfer.id == transfer_id).values(
            status="done", storage_path=str(final_path), completed_at=datetime.utcnow()
        )
    )
    bg.add_task(_cleanup_chunks, chunk_dir)
    log.info(f"Transfer {transfer_id} done: {xfer.filename}")
    return {"ok": True, "sha256": computed}


# ── Download ─────────────────────────────────────────────
@router.get("/{transfer_id}/download")
async def download(
    transfer_id: int,
    dev: Device = Depends(current_device),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(select(FileTransfer).where(FileTransfer.id == transfer_id))
    xfer = r.scalar_one_or_none()
    if not xfer or xfer.status != "done":
        raise HTTPException(404, "Fichier introuvable ou transfert non terminé")

    # Verify participant
    sr = await db.execute(select(Session).where(Session.id == xfer.session_id))
    s = sr.scalar_one_or_none()
    if not s or dev.id not in [s.host_id, s.controller_id]:
        raise HTTPException(403, "Accès refusé")

    fp = Path(xfer.storage_path)
    if not fp.exists():
        raise HTTPException(410, "Fichier expiré")

    return FileResponse(fp, filename=xfer.filename,
                        media_type=xfer.mime_type or "application/octet-stream")


# ── List session transfers ────────────────────────────────
@router.get("/session/{session_id}")
async def list_transfers(
    session_id: str,
    dev: Device = Depends(current_device),
    db: AsyncSession = Depends(get_db),
):
    await get_active_session(session_id, dev.id, db)
    r = await db.execute(select(FileTransfer).where(FileTransfer.session_id == session_id))
    return {"transfers": r.scalars().all()}


async def _cleanup_chunks(chunk_dir: Path):
    await asyncio.sleep(2)
    try:
        for f in chunk_dir.glob("*"):
            f.unlink(missing_ok=True)
        chunk_dir.rmdir()
    except Exception as e:
        log.warning(f"Chunk cleanup error: {e}")
