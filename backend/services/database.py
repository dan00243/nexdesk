"""
NexDesk — Database Service (AsyncPG + SQLAlchemy 2.0)
"""
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text
from typing import AsyncGenerator
import logging

from config import settings

logger = logging.getLogger("nexdesk.db")

engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    echo=settings.DEBUG,
    pool_pre_ping=True,
    pool_recycle=3600,
)

SessionLocal = async_sessionmaker(
    engine, class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False, autoflush=False,
)

class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    async with engine.begin() as conn:
        from models import device, session  # noqa — register models
        await conn.run_sync(Base.metadata.create_all)
    logger.info("✅ Database ready")


async def close_db():
    await engine.dispose()
    logger.info("Database closed")


async def ping_db() -> bool:
    try:
        async with SessionLocal() as s:
            await s.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
