import os
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from backend.config.settings import settings
from backend.config.db import db_manager
from backend.utils.logger import setup_logging, logger
from backend.seed_data import seed_database
from backend.routes import auth, exams, attempts, proctoring, admin, demo
from backend.services.otp_service import _log_provider_startup

setup_logging()

# Log active OTP provider configuration at startup
_log_provider_startup()

# --- TLS Diagnostic (temporary — remove after Vercel diagnosis) ---
try:
    from backend.utils.tls_diag import _run_tls_diagnostics
    _run_tls_diagnostics()
except Exception as diag_err:
    logger.warning("TLS diagnostic failed (non-fatal): %s", diag_err)
# --- End TLS Diagnostic ---

# Initial database seed on load (only when using local storage)
if settings.DATABASE_MODE == "local":
    try:
        seed_database()
    except Exception as e:
        logger.error(f"Initial seed notice: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing Smart Proctoring Backend Engine via Lifespan...")
    # Connect to database (fail-fast in production if MongoDB is unreachable)
    db_manager.connect()
    if settings.DATABASE_MODE == "local":
        try:
            seed_database()
        except Exception as e:
            logger.error(f"Lifespan seeding notice: {e}")
    yield
    # Cleanup
    if db_manager.client:
        db_manager.client.close()
        logger.info("MongoDB connection closed.")
    logger.info("Smart Proctoring Backend Engine shutdown.")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="AI-Based Smart Examination Proctoring System REST API",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
logger.info(f"CORS origins: {settings.CORS_ORIGINS}")

# Mount Evidence Directory for static image retrieval
os.makedirs(settings.EVIDENCE_DIR, exist_ok=True)
app.mount("/evidence", StaticFiles(directory=settings.EVIDENCE_DIR), name="evidence")

# Include API Routers
app.include_router(auth.router, prefix=settings.API_PREFIX)
app.include_router(exams.router, prefix=settings.API_PREFIX)
app.include_router(attempts.router, prefix=settings.API_PREFIX)
app.include_router(proctoring.router, prefix=settings.API_PREFIX)
app.include_router(admin.router, prefix=settings.API_PREFIX)
app.include_router(demo.router, prefix=settings.API_PREFIX)

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "system": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "api_docs": "/docs",
        "demo_mode": settings.DEMO_MODE_ENABLED,
        "database_mode": settings.DATABASE_MODE,
        "scoring_weights": {
            "FACE_NOT_DETECTED": settings.WEIGHT_FACE_NOT_DETECTED,
            "MULTIPLE_PERSONS": settings.WEIGHT_MULTIPLE_PERSONS,
            "MOBILE_PHONE": settings.WEIGHT_MOBILE_PHONE,
            "SUSPICIOUS_HEAD_MOVEMENT": settings.WEIGHT_SUSPICIOUS_HEAD_MOVEMENT,
            "AUDIO_ACTIVITY": settings.WEIGHT_AUDIO_ACTIVITY,
            "STUDENT_ABSENT": settings.WEIGHT_STUDENT_ABSENT
        }
    }

@app.get("/api/health")
def api_health_check():
    return {
        "status": "healthy",
        "demo_mode": settings.DEMO_MODE_ENABLED,
        "database_mode": settings.DATABASE_MODE,
        "scoring_weights": {
            "FACE_NOT_DETECTED": settings.WEIGHT_FACE_NOT_DETECTED,
            "MULTIPLE_PERSONS": settings.WEIGHT_MULTIPLE_PERSONS,
            "MOBILE_PHONE": settings.WEIGHT_MOBILE_PHONE,
            "SUSPICIOUS_HEAD_MOVEMENT": settings.WEIGHT_SUSPICIOUS_HEAD_MOVEMENT,
            "AUDIO_ACTIVITY": settings.WEIGHT_AUDIO_ACTIVITY,
            "STUDENT_ABSENT": settings.WEIGHT_STUDENT_ABSENT
        }
    }

# In production, serve the frontend build as static files.
# This mount must come AFTER all API routes and the /evidence mount.
if not settings.DEBUG:
    _frontend_dist = Path(__file__).parent.parent / "frontend" / "dist"
    if _frontend_dist.exists():
        app.mount("/", StaticFiles(directory=str(_frontend_dist), html=True), name="frontend")
        logger.info(f"Production mode: serving frontend from {_frontend_dist}")
    else:
        logger.warning(
            f"DEBUG=False but frontend build not found at {_frontend_dist}. "
            "Run 'npm run build' in frontend/ to generate the production build."
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
