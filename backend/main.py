"""
NexDesk — FastAPI Application Entry Point
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import uvicorn, logging, time

from services.database import init_db, close_db
from routers import auth, devices, sessions, files, admin
from config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("nexdesk")


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("🚀 NexDesk API starting...")
    await init_db()
    yield
    await close_db()
    log.info("👋 NexDesk API shutdown")


app = FastAPI(
    title="NexDesk API",
    description="API de contrôle à distance sécurisé",
    version=settings.VERSION,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url=None,
    lifespan=lifespan,
)

# ── CORS ─────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Security headers ─────────────────────────────────────
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# ── Request timing ───────────────────────────────────────
@app.middleware("http")
async def timing(request: Request, call_next):
    t = time.time()
    response = await call_next(request)
    ms = round((time.time() - t) * 1000, 1)
    response.headers["X-Process-Time"] = f"{ms}ms"
    log.info(f"{request.method} {request.url.path} → {response.status_code} ({ms}ms)")
    return response

# ── Routers ──────────────────────────────────────────────
app.include_router(auth.router,     prefix="/auth",     tags=["Auth"])
app.include_router(devices.router,  prefix="/devices",  tags=["Devices"])
app.include_router(sessions.router, prefix="/sessions", tags=["Sessions"])
app.include_router(files.router,    prefix="/files",    tags=["Files"])
app.include_router(admin.router,    prefix="/admin",    tags=["Admin"])

# ── Health ───────────────────────────────────────────────
@app.get("/", tags=["Info"])
async def root():
    return {"app": "NexDesk", "version": settings.VERSION, "status": "ok"}

@app.get("/health", tags=["Info"])
async def health():
    from services.database import ping_db
    return {"status": "ok", "db": await ping_db(), "ts": time.time()}

# ── Error handlers ───────────────────────────────────────
@app.exception_handler(404)
async def not_found(req, exc):
    return JSONResponse(404, {"detail": "Ressource introuvable"})

@app.exception_handler(500)
async def server_error(req, exc):
    log.error(f"500: {exc}")
    return JSONResponse(500, {"detail": "Erreur interne"})


if __name__ == "__main__":
    uvicorn.run(
        "main:app", host=settings.HOST, port=settings.PORT,
        reload=settings.DEBUG, log_level="info",
    )
