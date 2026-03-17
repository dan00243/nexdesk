"""
NexDesk — Session, AuditEvent, FileTransfer Models
"""
from sqlalchemy import Column, String, Boolean, DateTime, Integer, Text, Float, Enum, ForeignKey, Index
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime
import enum

from services.database import Base


class SessionStatus(str, enum.Enum):
    PENDING   = "pending"
    ACTIVE    = "active"
    ENDED     = "ended"
    REJECTED  = "rejected"
    TIMEOUT   = "timeout"


class EndReason(str, enum.Enum):
    NORMAL     = "normal"
    HOST_LEFT  = "host_left"
    CTRL_LEFT  = "ctrl_left"
    KICKED     = "kicked"
    TIMEOUT    = "timeout"
    ERROR      = "error"


class Session(Base):
    __tablename__ = "sessions"

    id            = Column(String(36), primary_key=True)   # UUID
    status        = Column(Enum(SessionStatus), default=SessionStatus.PENDING, index=True)

    host_id       = Column(String(11), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True)
    controller_id = Column(String(11), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True)

    # Timing
    created_at    = Column(DateTime, default=datetime.utcnow)
    started_at    = Column(DateTime, nullable=True)
    ended_at      = Column(DateTime, nullable=True)
    duration_s    = Column(Integer, nullable=True)

    # Config
    view_only     = Column(Boolean, default=False)
    allow_files   = Column(Boolean, default=True)
    allow_chat    = Column(Boolean, default=True)
    quality       = Column(String(20), default="balanced")

    # Stats
    bytes_sent    = Column(Integer, default=0)
    bytes_recv    = Column(Integer, default=0)
    avg_latency   = Column(Float, nullable=True)
    avg_fps       = Column(Float, nullable=True)

    # End info
    end_reason    = Column(Enum(EndReason), nullable=True)
    error_msg     = Column(Text, nullable=True)

    # Relationships
    host       = relationship("Device", foreign_keys=[host_id],       back_populates="host_sessions")
    controller = relationship("Device", foreign_keys=[controller_id], back_populates="ctrl_sessions")
    events     = relationship("AuditEvent",   back_populates="session", cascade="all, delete-orphan")
    transfers  = relationship("FileTransfer", back_populates="session", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_session_host_status", "host_id", "status"),
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id  = Column(String(11), ForeignKey("devices.id",  ondelete="SET NULL"), nullable=True)
    timestamp  = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(String(50), nullable=False)
    detail     = Column(JSONB, default={})

    session = relationship("Session", back_populates="events")


class FileTransfer(Base):
    __tablename__ = "file_transfers"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    session_id   = Column(String(36), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    sender_id    = Column(String(11), ForeignKey("devices.id",  ondelete="SET NULL"), nullable=True)
    filename     = Column(String(255), nullable=False)
    mime_type    = Column(String(100), nullable=True)
    size_bytes   = Column(Integer, nullable=True)
    sha256       = Column(String(64), nullable=True)
    status       = Column(String(20), default="pending")  # pending|in_progress|done|failed
    started_at   = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    storage_path = Column(Text, nullable=True)

    session = relationship("Session", back_populates="transfers")
