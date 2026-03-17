"""
NexDesk — Security Service
AES-256-GCM · RSA-2048 · JWT · bcrypt · Brute-force protection
"""
import os, time, hmac, hashlib, secrets, base64, logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import jwt
from passlib.context import CryptContext
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import settings

logger = logging.getLogger("nexdesk.security")
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ── JWT ────────────────────────────────────────────────────
def create_jwt(payload: Dict[str, Any]) -> str:
    data = {**payload, "exp": datetime.utcnow() + timedelta(hours=settings.JWT_EXPIRE_HOURS)}
    return jwt.encode(data, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def verify_jwt(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except jwt.PyJWTError:
        return None


# ── Passwords ─────────────────────────────────────────────
def hash_password(plain: str) -> str:
    return pwd_ctx.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)

def generate_temp_password(length: int = 8) -> str:
    """Génère un mot de passe lisible (majuscules + chiffres, sans ambiguïté)."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ── AES-256-GCM ───────────────────────────────────────────
def generate_aes_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)

def aes_encrypt(data: bytes, key: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    return nonce, ciphertext

def aes_decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, None)


# ── RSA-2048 ──────────────────────────────────────────────
def rsa_encrypt(data: bytes, public_key_pem: str) -> bytes:
    pub = serialization.load_pem_public_key(public_key_pem.encode())
    return pub.encrypt(data, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None
    ))

def rsa_decrypt(ciphertext: bytes, private_key_pem: str) -> bytes:
    priv = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    return priv.decrypt(ciphertext, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None
    ))


# ── HMAC ──────────────────────────────────────────────────
def compute_hmac(data: bytes, key: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def verify_hmac(data: bytes, key: bytes, expected: str) -> bool:
    return hmac.compare_digest(compute_hmac(data, key), expected)


# ── Brute-force protection ────────────────────────────────
class BruteForceGuard:
    """In-memory brute-force protection. Redis-compatible interface."""
    MAX_ATTEMPTS = 5
    LOCKOUT_SECONDS = 900  # 15 min

    def __init__(self):
        self._attempts: Dict[str, list] = {}
        self._locked: Dict[str, float] = {}

    def is_locked(self, key: str) -> bool:
        if key in self._locked:
            if time.time() < self._locked[key]:
                return True
            del self._locked[key]
            self._attempts.pop(key, None)
        return False

    def record_failure(self, key: str) -> int:
        now = time.time()
        self._attempts.setdefault(key, [])
        # Keep only attempts within the window
        self._attempts[key] = [t for t in self._attempts[key] if now - t < 300]
        self._attempts[key].append(now)
        count = len(self._attempts[key])
        if count >= self.MAX_ATTEMPTS:
            self._locked[key] = now + self.LOCKOUT_SECONDS
            logger.warning(f"[BruteForce] {key} LOCKED for 15 min after {count} failures")
        return count

    def reset(self, key: str):
        self._attempts.pop(key, None)
        self._locked.pop(key, None)

brute_force = BruteForceGuard()
