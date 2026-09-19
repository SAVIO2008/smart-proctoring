"""SMTP-based OTP delivery provider (production-ready, optional).

Activated by setting OTP_PROVIDER=smtp and configuring SMTP_* environment variables.
Uses the standard library only (no new dependency).

=== Gmail configuration ===
1. Enable 2-Factor Authentication on your Google account.
2. Generate an App Password: https://myaccount.google.com/apppasswords
   - Select "Mail" as the app and your device type.
   - Google will show a 16-character password. Copy it.
3. In your .env file set:
     OTP_PROVIDER=smtp
     SMTP_HOST=smtp.gmail.com
     SMTP_PORT=587
     SMTP_USERNAME=your.email@gmail.com
     SMTP_PASSWORD=<the 16-char App Password, NOT your regular password>
     SMTP_FROM_EMAIL=your.email@gmail.com
     SMTP_USE_TLS=True

NOTE: Regular Gmail passwords will NOT work unless "Less secure app access" is
enabled (Google deprecated this). Use an App Password.
"""
import logging
import smtplib
import socket
from email.message import EmailMessage

from backend.config.settings import settings
from backend.services.otp_service import OtpProvider

logger = logging.getLogger("smart_proctor.otp.smtp")


class SmtpOtpProvider(OtpProvider):
    """Deliver OTP via SMTP (stdlib smtplib, no extra dependencies)."""

    def send(self, email: str, otp: str, purpose: str) -> None:
        if not (settings.SMTP_HOST and settings.SMTP_FROM_EMAIL):
            raise RuntimeError(
                "SMTP provider selected but SMTP_HOST / SMTP_FROM_EMAIL are not configured"
            )

        subject = "Your verification code"
        body = (
            f"Hello,\n\n"
            f"Your {purpose} verification code is: {otp}\n\n"
            f"This code expires in {settings.OTP_TTL_SECONDS // 60} minutes "
            f"and can be used only once.\n"
            f"If you did not request this code, please ignore this message.\n"
        )

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = settings.SMTP_FROM_EMAIL
        msg["To"] = email
        msg.set_content(body)

        try:
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
                # Identify ourselves to the server (helps with some providers)
                server.ehlo_or_helo_if_needed()

                if settings.SMTP_USE_TLS:
                    server.starttls()
                    server.ehlo_or_helo_if_needed()

                if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                    server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)

                server.send_message(msg)
                logger.info(
                    "OTP email delivered to %s via %s:%s",
                    _mask_email(email), settings.SMTP_HOST, settings.SMTP_PORT,
                )
        except smtplib.SMTPAuthenticationError as exc:
            logger.error(
                "SMTP authentication failed for %s:%s (user=%s): %s",
                settings.SMTP_HOST, settings.SMTP_PORT,
                settings.SMTP_USERNAME,
                _sanitize_smtp_error(exc),
            )
            raise RuntimeError(
                "Email delivery is not configured correctly (authentication failed). "
                "Please check SMTP_USERNAME and SMTP_PASSWORD."
            ) from exc
        except smtplib.SMTPConnectError as exc:
            logger.error(
                "SMTP connection refused for %s:%s: %s",
                settings.SMTP_HOST, settings.SMTP_PORT,
                _sanitize_smtp_error(exc),
            )
            raise RuntimeError(
                f"Could not connect to email server {settings.SMTP_HOST}:{settings.SMTP_PORT}. "
                "Please check SMTP_HOST and SMTP_PORT."
            ) from exc
        except (smtplib.SMTPException, socket.timeout, OSError) as exc:
            logger.error(
                "SMTP send failed for %s:%s: %s",
                settings.SMTP_HOST, settings.SMTP_PORT,
                _sanitize_smtp_error(exc),
            )
            raise RuntimeError(
                "Email delivery failed. Please check your SMTP configuration."
            ) from exc

    @staticmethod
    def test_connection() -> dict:
        """Diagnostic: test SMTP connectivity without sending an email.

        Returns a dict with keys: ok (bool), message (str), details (str | None).
        Does NOT expose credentials or OTP values.
        """
        if not (settings.SMTP_HOST and settings.SMTP_FROM_EMAIL):
            return {
                "ok": False,
                "message": "SMTP not configured",
                "details": "SMTP_HOST and/or SMTP_FROM_EMAIL are empty. Set them in your .env file.",
            }

        try:
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
                server.ehlo_or_helo_if_needed()
                if settings.SMTP_USE_TLS:
                    server.starttls()
                    server.ehlo_or_helo_if_needed()
                if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                    server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                return {
                    "ok": True,
                    "message": f"Connected to {settings.SMTP_HOST}:{settings.SMTP_PORT} successfully.",
                    "details": None,
                }
        except smtplib.SMTPAuthenticationError as exc:
            return {
                "ok": False,
                "message": "Authentication failed",
                "details": (
                    f"The server {settings.SMTP_HOST}:{settings.SMTP_PORT} rejected the "
                    f"credentials for {settings.SMTP_USERNAME}. "
                    "If using Gmail, make sure you are using an App Password "
                    "(not your regular password)."
                ),
            }
        except smtplib.SMTPConnectError as exc:
            return {
                "ok": False,
                "message": f"Could not connect to {settings.SMTP_HOST}:{settings.SMTP_PORT}",
                "details": str(exc),
            }
        except (smtplib.SMTPException, socket.timeout, OSError) as exc:
            return {
                "ok": False,
                "message": "SMTP error",
                "details": str(exc),
            }


def _mask_email(email: str) -> str:
    """Mask an email address for safe logging: u***@domain.com"""
    if "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    masked_local = local[0] + "***" if len(local) > 0 else "***"
    return f"{masked_local}@{domain}"


def _sanitize_smtp_error(exc: Exception) -> str:
    """Return the exception message, stripping any credentials that may appear."""
    msg = str(exc)
    # smtplib sometimes includes the server response which may contain the
    # username or other details. We keep the error class and first line only.
    return msg.split("\n")[0] if msg else exc.__class__.__name__