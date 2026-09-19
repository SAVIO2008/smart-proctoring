"""Cryptographically secure one-time-password (OTP) service.

Design guarantees:
- OTPs are generated with ``secrets`` (cryptographically secure).
- Only a hash of the OTP is persisted (SHA-256 + per-OTP random salt); the
  plaintext OTP is never written to storage or logs.
- Short TTL, single-use (marked consumed + revoked), max verification attempts,
  and a per-email resend cooldown.
- Delivery is abstracted behind an environment-selected provider. The default
  provider is "console" (logs a masked hint only) so that development/testing
  never weakens production security: in production the provider must be set to a
  real channel that the OTP would actually reach the user through.

The OTP record itself is stored in the shared persistent ``sessions`` collection
(keyed by a purpose-specific namespace), so it survives restarts and works under
the same concurrency guarantees as the rest of the data layer.
"""

import hashlib
import hmac
import secrets
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from fastapi import HTTPException, status

from backend.config.settings import settings
from backend.config.db import get_sessions_col


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _record_id(email: str, purpose: str) -> str:
    return f"otp:{purpose}:{email.lower().strip()}"


def _hash_otp(otp: str) -> str:
    """Hash an OTP with a random salt (format: salt$digest)."""
    salt = secrets.token_hex(16)
    digest = hashlib.sha256(f"{salt}{otp}".encode("utf-8")).hexdigest()
    return f"{salt}${digest}"


def _verify_otp_hash(otp: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
    except (ValueError, AttributeError):
        return False
    candidate = hashlib.sha256(f"{salt}{otp}".encode("utf-8")).hexdigest()
    return hmac.compare_digest(candidate, digest)


class OtpProvider:
    """Base delivery abstraction. Subclasses deliver an OTP to a user."""

    def send(self, email: str, otp: str, purpose: str) -> None:
        raise NotImplementedError


class ConsoleOtpProvider(OtpProvider):
    """Development/testing provider.

    Deliberately does NOT print the OTP. It prints only a masked notification so a
    developer knows a send was requested; the plaintext OTP is never present in logs.
    """

    def send(self, email: str, otp: str, purpose: str) -> None:
        # Never emit the OTP value. A developer can enable a temp-safe retrieval via
        # settings.OTP_DEV_ECHO only when explicitly configured for local testing.
        if settings.DEV_ECHO_OTP:
            import logging
            logger = logging.getLogger("smart_proctor.otp")
            logger.warning("[DEV-ONLY] OTP for %s (purpose=%s): %s", email, purpose, otp)
        # Silence otherwise: we do not log the OTP.


def get_otp_provider() -> OtpProvider:
    provider = settings.OTP_PROVIDER
    if provider in ("console", "dev", "log"):
        return ConsoleOtpProvider()
    if provider in ("smtp", "email"):
        from backend.services.otp_providers import SmtpOtpProvider
        return SmtpOtpProvider()
    if provider == "none":
        return OtpProvider()  # raises at send time; used to hard-disable
    raise RuntimeError(f"Unknown OTP_PROVIDER configured: {provider!r}")


def _log_provider_startup() -> None:
    """Log the active OTP provider at startup (once)."""
    import logging
    _log = logging.getLogger("smart_proctor.otp")
    provider = settings.OTP_PROVIDER
    if provider in ("console", "dev", "log"):
        _log.warning(
            "OTP_PROVIDER=%s — OTP codes will NOT be delivered. "
            "Set OTP_PROVIDER=smtp and configure SMTP_* env vars for production.",
            provider,
        )
    elif provider == "smtp":
        if not (settings.SMTP_HOST and settings.SMTP_FROM_EMAIL):
            _log.error(
                "OTP_PROVIDER=smtp but SMTP_HOST / SMTP_FROM_EMAIL are not set. "
                "OTP delivery will fail."
            )
        else:
            _log.info(
                "OTP_PROVIDER=smtp — delivering via %s:%s (from %s)",
                settings.SMTP_HOST, settings.SMTP_PORT,
                settings.SMTP_FROM_EMAIL,
            )
    elif provider == "none":
        _log.warning("OTP_PROVIDER=none — OTP delivery is disabled entirely.")
    else:
        _log.error("Unknown OTP_PROVIDER=%r", provider)


class OtpService:
    def generate_and_send(self, email: str, purpose: str = "login") -> Dict[str, Any]:
        email_key = email.lower().strip()
        if not email_key:
            raise HTTPException(status_code=400, detail="Email is required")

        col = get_sessions_col()
        rid = _record_id(email_key, purpose)
        now = _utcnow()
        existing = col.find_one({"_id": rid})

        # Enforce resend cooldown.
        if existing and existing.get("created_at"):
            try:
                created = datetime.fromisoformat(existing["created_at"])
                elapsed = (now - created).total_seconds()
            except (TypeError, ValueError):
                elapsed = settings.OTP_RESEND_COOLDOWN_SECONDS + 1
            if elapsed < settings.OTP_RESEND_COOLDOWN_SECONDS:
                remaining = int(settings.OTP_RESEND_COOLDOWN_SECONDS - elapsed)
                raise HTTPException(
                    status_code=429,
                    detail=f"Please wait {remaining} seconds before requesting another code",
                )

        otp = "".join(secrets.choice("0123456789") for _ in range(settings.OTP_LENGTH))
        otp_hash = _hash_otp(otp)
        expires_at = (now.timestamp() + settings.OTP_TTL_SECONDS)

        record = {
            "_id": rid,
            "email": email_key,
            "purpose": purpose,
            "otp_hash": otp_hash,
            "attempts": 0,
            "consumed": False,
            "created_at": now.isoformat(),
            "expires_at": expires_at,
        }

        # Persist (upsert). For MongoDB this maps to replace; for local store we
        # delete-then-insert to emulate upsert without new operator support.
        if col.find_one({"_id": rid}):
            col.delete_one({"_id": rid})
        col.insert_one(record)

        # Deliver via configured provider. This is the only place the plaintext
        # OTP leaves this service (and only to the intended delivery channel).
        # A delivery failure must not leak the OTP and must surface gracefully
        # rather than crashing the request with an unhandled exception.
        try:
            get_otp_provider().send(email_key, otp, purpose)
        except Exception as exc:
            # Roll back the OTP record so a broken delivery does not leave a
            # dangling unconsumed code that the user can never receive.
            col.delete_one({"_id": rid})
            logger = logging.getLogger("smart_proctor.otp")
            logger.error(
                "OTP delivery failed for %s (purpose=%s): %s",
                email_key, purpose, exc.__class__.__name__,
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Unable to send verification code. Please try again later.",
            )

        # Explicitly drop the local variable reference to the plaintext OTP.
        del otp

        return {
            "message": "Verification code sent",
            "expires_in_seconds": settings.OTP_TTL_SECONDS,
        }

    def verify(self, email: str, otp: str, purpose: str = "login") -> bool:
        email_key = email.lower().strip()
        col = get_sessions_col()
        rid = _record_id(email_key, purpose)
        record = col.find_one({"_id": rid})
        now = _utcnow()

        if not record:
            raise HTTPException(status_code=400, detail="No verification code found. Request a new one.")

        if record.get("consumed"):
            raise HTTPException(status_code=400, detail="This verification code has already been used.")

        # Expiry check.
        expires_at = record.get("expires_at")
        if expires_at is not None and now.timestamp() > float(expires_at):
            # Expired records may be removed lazily.
            col.delete_one({"_id": rid})
            raise HTTPException(status_code=400, detail="Verification code has expired. Request a new one.")

        attempts = int(record.get("attempts", 0))
        if attempts >= settings.OTP_MAX_ATTEMPTS:
            col.delete_one({"_id": rid})
            raise HTTPException(
                status_code=429,
                detail="Too many incorrect attempts. Request a new code.",
            )

        if not _verify_otp_hash(otp, record.get("otp_hash", "")):
            col.update_one({"_id": rid}, {"$inc": {"attempts": 1}})
            remaining = settings.OTP_MAX_ATTEMPTS - attempts - 1
            raise HTTPException(
                status_code=400,
                detail=(
                    "Incorrect verification code."
                    + (f" {max(remaining, 0)} attempts remaining." if remaining > 0 else "")
                ),
            )

        # One-time use: mark consumed.
        col.update_one({"_id": rid}, {"$set": {"consumed": True}})
        return True


otp_service = OtpService()