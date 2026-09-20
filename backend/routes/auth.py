from fastapi import APIRouter, Depends, HTTPException, status
from typing import Dict, Any
from pydantic import BaseModel
from backend.models.schemas import (
    RegisterRequest, AdminRegisterRequest, LoginRequest, TokenResponse, 
    UserProfileResponse, UserProfileUpdateRequest, UserProfileUpdateResponse,
    OtpRequestRequest, OtpVerifyRequest, OtpResponse,
    LoginChallengeResponse, LoginOtpVerifyRequest
)
from backend.services.auth_service import auth_service
from backend.services.otp_service import otp_service
from backend.utils.security import get_current_user, get_current_admin, decode_access_token, security_bearer
from backend.config.settings import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])

class ValidateFaceRequest(BaseModel):
    image_base64: str

@router.post("/validate-face")
def validate_registration_face(req: ValidateFaceRequest):
    """
    Validates a facial snapshot during candidate registration to ensure a single,
    well-lit, clearly detectable face is captured for future biometric identity verification.
    """
    import cv2
    import numpy as np
    from backend.utils.image_utils import decode_base64_image
    from backend.ai import face_detector

    img = decode_base64_image(req.image_base64)
    if img is None:
        return {
            "success": False,
            "camera_ready": False,
            "face_detected": False,
            "single_person": False,
            "lighting_ok": False,
            "brightness_score": 0,
            "message": "Unable to decode camera frame"
        }

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    brightness = float(np.mean(gray))
    lighting_ok = brightness >= 30.0

    faces = face_detector.detect_faces(img)
    face_count = len(faces)
    face_detected = face_count >= 1
    single_person = face_count == 1

    all_passed = lighting_ok and face_detected and single_person

    return {
        "success": all_passed,
        "camera_ready": True,
        "face_detected": face_detected,
        "single_person": single_person,
        "face_count": face_count,
        "faces": faces,
        "lighting_ok": lighting_ok,
        "brightness_score": round(brightness, 1),
        "message": (
            "Face successfully detected and validated as biometric baseline!"
            if all_passed
            else (
                "Lighting is too dim. Please brighten room lighting."
                if not lighting_ok
                else (
                    "No face detected. Please look directly into the camera."
                    if not face_detected
                    else f"Multiple faces detected ({face_count}). Only you should be in camera view."
                )
            )
        )
    }

@router.post("/register", response_model=TokenResponse)
def register(req: RegisterRequest):
    return auth_service.register_user(req)

@router.post("/register-admin", response_model=TokenResponse)
def register_admin(req: AdminRegisterRequest):
    """Register a new admin account. Requires a valid invite code."""
    if req.invite_code != settings.ADMIN_INVITE_CODE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid invite code. Admin registration is restricted."
        )
    # Force role to admin regardless of what was sent
    student_reg = RegisterRequest(
        name=req.name,
        email=req.email,
        password=req.password,
        role="admin",
        subject=req.subject or "All Subjects",
        student_id=None,
        face_reference=None
    )
    return auth_service.register_user(student_reg, allow_admin=True)

@router.post("/login", response_model=LoginChallengeResponse)
def login(req: LoginRequest):
    """Phase 1: validate credentials and return an email-OTP challenge (no JWT)."""
    return auth_service.login_user(req)

@router.post("/login/verify", response_model=TokenResponse)
def login_verify(req: LoginOtpVerifyRequest):
    """Phase 2: verify the emailed OTP and, on success, issue the authenticated JWT."""
    return auth_service.verify_login_otp(req.challenge_token, req.otp)

@router.post("/otp/request", response_model=OtpResponse)
def request_otp(req: OtpRequestRequest):
    """Request a one-time verification code. Delivered via the configured provider."""
    return otp_service.generate_and_send(req.email, req.purpose)

@router.post("/otp/verify")
def verify_otp(req: OtpVerifyRequest):
    """Verify a one-time code. One-time use; max attempts enforced."""
    otp_service.verify(req.email, req.otp, req.purpose)
    return {"message": "Verification successful"}

@router.post("/logout")
def logout(credentials = Depends(security_bearer)):
    """Revoke the current session token so it can no longer be used."""
    jti = None
    if credentials:
        payload = decode_access_token(credentials.credentials)
        if payload:
            jti = payload.get("jti")
    return auth_service.logout(jti)

@router.get("/me", response_model=UserProfileResponse)
def get_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    return {
        "id": str(current_user["_id"]),
        "name": current_user["name"],
        "email": current_user["email"],
        "role": current_user["role"],
        "student_id": current_user.get("student_id"),
        "subject": current_user.get("subject", "All Subjects" if current_user.get("role") == "admin" else None),
        "has_face_reference": bool(current_user.get("face_reference")),
        "face_reference": current_user.get("face_reference")
    }

@router.put("/me", response_model=UserProfileUpdateResponse)
def update_me(req: UserProfileUpdateRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Update profile details (name, student ID, subject domain, face baseline, password) for students & admins."""
    return auth_service.update_user_profile(str(current_user["_id"]), req)

@router.patch("/me", response_model=UserProfileUpdateResponse)
def patch_me(req: UserProfileUpdateRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Alias for updating profile details."""
    return auth_service.update_user_profile(str(current_user["_id"]), req)

@router.delete("/me")
def delete_my_account(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Permanently delete the logged in user's account and associated test sessions."""
    return auth_service.delete_user_account(str(current_user["_id"]))


@router.get("/smtp-check")
def smtp_check(_admin: Dict[str, Any] = Depends(get_current_admin)):
    """Admin-only: test SMTP connectivity without sending an email.

    Returns whether the configured SMTP server is reachable and credentials are
    accepted. Does NOT expose passwords, OTP values, or secrets.
    """
    from backend.services.otp_providers import SmtpOtpProvider
    result = SmtpOtpProvider.test_connection()
    result["provider"] = settings.OTP_PROVIDER
    result["host"] = settings.SMTP_HOST or "(not set)"
    result["port"] = settings.SMTP_PORT
    result["from_email"] = settings.SMTP_FROM_EMAIL or "(not set)"
    result["username"] = settings.SMTP_USERNAME or "(not set)"
    result["use_tls"] = settings.SMTP_USE_TLS
    return result

