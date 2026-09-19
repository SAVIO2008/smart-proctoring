import os
from typing import List
from dotenv import load_dotenv
from pydantic import BaseModel

load_dotenv()

class Settings(BaseModel):
    PROJECT_NAME: str = "AI-Based Smart Examination Proctoring System"
    VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"
    
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", 8000))
    DEBUG: bool = os.getenv("DEBUG", "False").lower() in ("true", "1")
    
    # CORS
    CORS_ORIGINS: List[str] = os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:3000"
    ).split(",")
    
    # Database
    # "mongodb" = require MongoDB Atlas (production). "local" = file-backed JSON (dev/demo).
    DATABASE_MODE: str = os.getenv("DATABASE_MODE", "mongodb").strip().lower()
    MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    DATABASE_NAME: str = os.getenv("DATABASE_NAME", "smart_proctor_db")
    # Directory used by the file-backed storage when DATABASE_MODE=local.
    DATA_STORE_DIR: str = os.getenv("DATA_STORE_DIR", "./data_store")
    
    # Security
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "smart_proctoring_super_secret_jwt_key_2026_change_in_production")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 480))
    
    # Login rate limiting / lockout
    LOGIN_MAX_ATTEMPTS: int = int(os.getenv("LOGIN_MAX_ATTEMPTS", 5))
    LOGIN_LOCKOUT_SECONDS: int = int(os.getenv("LOGIN_LOCKOUT_SECONDS", 900))
    
    # OTP configuration
    OTP_LENGTH: int = int(os.getenv("OTP_LENGTH", 6))
    OTP_TTL_SECONDS: int = int(os.getenv("OTP_TTL_SECONDS", 300))
    OTP_MAX_ATTEMPTS: int = int(os.getenv("OTP_MAX_ATTEMPTS", 5))
    OTP_RESEND_COOLDOWN_SECONDS: int = int(os.getenv("OTP_RESEND_COOLDOWN_SECONDS", 60))
    OTP_PROVIDER: str = os.getenv("OTP_PROVIDER", "console").strip().lower()
    # When True, the console provider logs the plaintext OTP. FOR LOCAL TESTING ONLY.
    # Never enable in production. Defaults off.
    DEV_ECHO_OTP: bool = os.getenv("DEV_ECHO_OTP", "False").lower() in ("true", "1")
    # SMTP provider (used when OTP_PROVIDER=smtp)
    SMTP_HOST: str = os.getenv("SMTP_HOST", "")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", 587))
    SMTP_USERNAME: str = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM_EMAIL: str = os.getenv("SMTP_FROM_EMAIL", "")
    SMTP_USE_TLS: bool = os.getenv("SMTP_USE_TLS", "True").lower() in ("true", "1")
    
    # Suspicion Scoring Weights
    WEIGHT_FACE_NOT_DETECTED: int = int(os.getenv("WEIGHT_FACE_NOT_DETECTED", 20))
    WEIGHT_MULTIPLE_PERSONS: int = int(os.getenv("WEIGHT_MULTIPLE_PERSONS", 40))
    WEIGHT_MOBILE_PHONE: int = int(os.getenv("WEIGHT_MOBILE_PHONE", 50))
    WEIGHT_SUSPICIOUS_HEAD_MOVEMENT: int = int(os.getenv("WEIGHT_SUSPICIOUS_HEAD_MOVEMENT", 10))
    WEIGHT_AUDIO_ACTIVITY: int = int(os.getenv("WEIGHT_AUDIO_ACTIVITY", 20))
    WEIGHT_STUDENT_ABSENT: int = int(os.getenv("WEIGHT_STUDENT_ABSENT", 30))
    
    # Thresholds
    HEAD_POSE_YAW_THRESHOLD: float = float(os.getenv("HEAD_POSE_YAW_THRESHOLD", 20.0))
    HEAD_POSE_PITCH_THRESHOLD: float = float(os.getenv("HEAD_POSE_PITCH_THRESHOLD", 16.0))
    PHONE_CONFIDENCE_THRESHOLD: float = float(os.getenv("PHONE_CONFIDENCE_THRESHOLD", 0.22))
    PHONE_DETECTION_DEBUG: bool = os.getenv("PHONE_DETECTION_DEBUG", "True").lower() in ("true", "1")
    PHONE_TEMPORAL_FRAMES: int = int(os.getenv("PHONE_TEMPORAL_FRAMES", 1))
    PHONE_TEMPORAL_WINDOW_SECONDS: float = float(os.getenv("PHONE_TEMPORAL_WINDOW_SECONDS", 0.5))
    AUDIO_ENERGY_THRESHOLD: float = float(os.getenv("AUDIO_ENERGY_THRESHOLD", 0.03))
    EVIDENCE_COOLDOWN_SECONDS: float = float(os.getenv("EVIDENCE_COOLDOWN_SECONDS", 5.0))
    ABSENCE_TIMEOUT_SECONDS: float = float(os.getenv("ABSENCE_TIMEOUT_SECONDS", 8.0))
    
    # Paths
    EVIDENCE_DIR: str = os.getenv("EVIDENCE_DIR", "./evidence")
    MODELS_DIR: str = os.getenv("MODELS_DIR", "./models/weights")
    YOLO_MODEL_PATH: str = os.getenv("YOLO_MODEL_PATH", "yolov8n.pt")
    
    # Demo/Test Mode
    DEMO_MODE_ENABLED: bool = os.getenv("DEMO_MODE_ENABLED", "False").lower() in ("true", "1")

    # Admin Registration
    ADMIN_INVITE_CODE: str = os.getenv("ADMIN_INVITE_CODE", "PROCTOR-ADMIN-2026")

    class Config:
        case_sensitive = True

settings = Settings()

# --- Production startup guards ---
# These warnings help operators catch misconfiguration before it reaches users.
# They never crash the process — only log at WARNING level.
import logging as _logging
_guard_log = _logging.getLogger("smart_proctor.config")

_DEFAULT_JWT_SECRET = "smart_proctoring_super_secret_jwt_key_2026_change_in_production"
if settings.JWT_SECRET_KEY == _DEFAULT_JWT_SECRET:
    _guard_log.warning(
        "JWT_SECRET_KEY is still the hardcoded default. "
        "Set a strong random secret via the JWT_SECRET_KEY environment variable for production."
    )
if settings.DEBUG:
    _guard_log.warning("DEBUG=True — stack traces and debug information may be exposed to clients.")
if settings.DEMO_MODE_ENABLED:
    _guard_log.warning("DEMO_MODE_ENABLED=True — synthetic proctoring events are enabled. Disable for production.")
if settings.OTP_PROVIDER == "console":
    _guard_log.warning(
        "OTP_PROVIDER=console — OTP codes will NOT be delivered. "
        "Set OTP_PROVIDER=smtp and configure SMTP_* environment variables for production."
    )
if settings.ADMIN_INVITE_CODE == "PROCTOR-ADMIN-2026":
    _guard_log.warning(
        "ADMIN_INVITE_CODE is still the hardcoded default. "
        "Set a unique ADMIN_INVITE_CODE environment variable for production."
    )
if settings.DEV_ECHO_OTP:
    _guard_log.warning(
        "DEV_ECHO_OTP=True — plaintext OTP codes will be echoed to server logs. "
        "This must NEVER be enabled in production."
    )
if not settings.DEBUG:
    for origin in settings.CORS_ORIGINS:
        if "localhost" in origin or "127.0.0.1" in origin:
            _guard_log.warning(
                f"CORS_ORIGINS contains '{origin}' while DEBUG=False. "
                "This may allow unintended localhost access in production."
            )
            break

# Ensure directories exist.
# On read-only filesystems (e.g. Vercel serverless runtime), fall back to /tmp.
def _ensure_dir(path: str) -> str:
    """Create a directory.  If the filesystem is read-only, relocate under /tmp."""
    try:
        os.makedirs(path, exist_ok=True)
        return path
    except OSError:
        _fallback = os.path.join("/tmp", os.path.basename(path) or "app_data")
        os.makedirs(_fallback, exist_ok=True)
        return _fallback

settings.EVIDENCE_DIR = _ensure_dir(settings.EVIDENCE_DIR)       # type: ignore[assignment]
settings.MODELS_DIR = _ensure_dir(settings.MODELS_DIR)           # type: ignore[assignment]
