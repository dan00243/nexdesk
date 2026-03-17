"""
NexDesk — Device Model
"""
from sqlalchemy import Column, String, Boolean, DateTime, Text, Enum, Integer, ForeignKey, Index
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime
import enum

from services.database import Base


class DeviceStatus(str, enum.Enum):
    ACTIVE  = "active"
    BANNED  = "banned"
    PENDING = "pending"


class Platform(str, enum.Enum):
    WINDOWS = "windows"
    MACOS   = "macos"
    LINUX   = "linux"
    ANDROID = "android"
    IOS     = "ios"


class Device(Base):
    __tablename__ = "devices"

    # Identity
    id           = Column(String(11), primary_key=True)   # XXX-XXX-XXX
    name         = Column(String(100), default="")
    platform     = Column(Enum(Platform), nullable=False)
    os_version   = Column(String(50), nullable=True)
    app_version  = Column(String(20), nullable=True)
    status       = Column(Enum(DeviceStatus), default=DeviceStatus.ACTIVE, index=True)

    # Auth
    public_key       = Column(Text, nullable=True)         # RSA-2048 PEM
    temp_pw_hash     = Column(String(200), nullable=True)
    temp_pw_exp      = Column(DateTime, nullable=True)
    perm_pw_hash     = Column(String(200), nullable=True)
    totp_secret      = Column(String(64), nullable=True)
    allow_unattended = Column(Boolean, default=False)

    # Network
    last_ip    = Column(String(45), nullable=True)
    last_seen  = Column(DateTime, nullable=True)
    online     = Column(Boolean, default=False, index=True)

    # Meta
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    extra      = Column(JSONB, default={})

    # Relationships
    whitelist_entries = relationship("WhitelistEntry", back_populates="device",
                                     foreign_keys="WhitelistEntry.device_id",
                                     cascade="all, delete-orphan")
    authorized_by     = relationship("WhitelistEntry", back_populates="trusted_device",
                                     foreign_keys="WhitelistEntry.trusted_device_id")
    host_sessions     = relationship("Session", back_populates="host",
                                     foreign_keys="Session.host_id")
    ctrl_sessions     = relationship("Session", back_populates="controller",
                                     foreign_keys="Session.controller_id")

    __table_args__ = (
        Index("ix_device_status_online", "status", "online"),
    )


class WhitelistEntry(Base):
    """Appareils autorisés à se connecter sans mot de passe."""
    __tablename__ = "whitelist"

    id                = Column(Integer, primary_key=True, autoincrement=True)
    device_id         = Column(String(11), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    trusted_device_id = Column(String(11), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    label             = Column(String(100), nullable=True)
    created_at        = Column(DateTime, default=datetime.utcnow)
    expires_at        = Column(DateTime, nullable=True)   # None = permanent

    device         = relationship("Device", foreign_keys=[device_id],         back_populates="whitelist_entries")
    trusted_device = relationship("Device", foreign_keys=[trusted_device_id], back_populates="authorized_by")

    __table_args__ = (
        Index("ix_whitelist_pair", "device_id", "trusted_device_id", unique=True),
    )
