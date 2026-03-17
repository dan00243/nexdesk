from pydantic_settings import BaseSettings
from typing import List, Optional
import secrets, os

class Settings(BaseSettings):
    # App
    APP_NAME: str = "NexDesk"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Security
    JWT_SECRET: str = secrets.token_hex(64)
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_HOURS: int = 24

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://nexdesk:nexdesk@localhost:5432/nexdesk"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # CORS
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "app://nexdesk"]

    # Signaling
    SIGNALING_URL: str = "http://localhost:7879"
    SIGNALING_SECRET: str = secrets.token_hex(32)

    # Files
    UPLOAD_DIR: str = "/tmp/nexdesk_uploads"
    MAX_FILE_MB: int = 500
    CHUNK_SIZE: int = 1_048_576  # 1 MB

    # Session
    TEMP_PASSWORD_TTL_MIN: int = 10
    MAX_SESSION_HOURS: int = 24

    # SSL
    SSL_KEY: Optional[str] = None
    SSL_CERT: Optional[str] = None

    class Config:
        env_file = ".env"

settings = Settings()
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
