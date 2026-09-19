"""
Full end-to-end system test suite using TestClient (in-process).

Tests the complete workflow: student OTP login → exam discovery → system check →
face verification → exam attempt → proctoring → demo simulation → submission →
admin OTP login → dashboard/sessions/reports.

Adapted for Phase 2 two-step OTP login flow.
"""
import base64
import cv2
import numpy as np
import pytest
from fastapi.testclient import TestClient
from backend.app import app
from backend.config.db import get_sessions_col


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _capture_otp_login(client, email, password):
    """Drive the full two-step OTP login and return (token, headers, user_dict)."""
    from backend.services import otp_service as otp_mod

    # Clear any stale OTP record for this email to avoid cooldown
    get_sessions_col().delete_one({"_id": f"otp:login:{email.lower().strip()}"})

    captured = {}
    orig = otp_mod.get_otp_provider

    class _CapturingProvider:
        def send(self, email_addr, otp_code, purpose):
            captured["otp"] = otp_code

    otp_mod.get_otp_provider = lambda: _CapturingProvider()

    try:
        # Phase 1 – credentials → challenge
        c = client.post("/api/auth/login", json={"email": email, "password": password})
        assert c.status_code == 200, f"Login challenge failed: {c.json()}"
        assert "challenge_token" in c.json()
        assert "access_token" not in c.json()

        otp_val = captured.get("otp")
        assert otp_val is not None, "OTP was not captured – provider not called"

        # Phase 2 – OTP verification → JWT
        v = client.post(
            "/api/auth/login/verify",
            json={"challenge_token": c.json()["challenge_token"], "otp": otp_val},
        )
        assert v.status_code == 200, f"OTP verify failed: {v.json()}"
        assert "access_token" in v.json()

        token = v.json()["access_token"]
        user = v.json()["user"]
        headers = {"Authorization": f"Bearer {token}"}
        return token, headers, user
    finally:
        otp_mod.get_otp_provider = orig


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_full_system_flow(client):
    """Complete E2E: student login → exam → proctoring → submit → admin login → reports."""

    # 1. Student Authentication (OTP login)
    student_token, student_headers, student_user = _capture_otp_login(
        client, "student@proctor.edu", "Student@123"
    )
    assert student_user["role"] == "student"

    # 2. Fetch Exams and Details (pick one with questions)
    exams = client.get("/api/exams", headers=student_headers).json()
    assert len(exams) > 0, "No exams found"
    exam_summary = None
    for e in exams:
        if e.get("questions_count", 0) >= 1:
            exam_summary = e
            break
    assert exam_summary is not None, "No exam with questions found"
    exam = client.get(
        f"/api/exams/{exam_summary['id']}", headers=student_headers
    ).json()
    assert len(exam.get("questions", [])) >= 1, "Exam has no questions"

    # 3. Create Synthetic Camera Frame
    frame = np.ones((480, 640, 3), dtype=np.uint8) * 180
    cv2.ellipse(frame, (320, 240), (90, 130), 0, 0, 360, (130, 160, 210), -1)
    cv2.circle(frame, (280, 210), 12, (50, 50, 50), -1)
    cv2.circle(frame, (360, 210), 12, (50, 50, 50), -1)
    cv2.ellipse(frame, (320, 300), (35, 15), 0, 0, 180, (50, 50, 150), -1)
    _, buf = cv2.imencode(".jpg", frame)
    frame_b64 = "data:image/jpeg;base64," + base64.b64encode(buf).decode("utf-8")

    # 4. System Check & Baseline Face Registration
    sys_check = client.post(
        "/api/proctoring/system-check",
        json={"image_base64": frame_b64},
        headers=student_headers,
    ).json()
    assert sys_check["camera_ready"] is True

    reg_face = client.post(
        "/api/proctoring/update-face-reference",
        json={"image_base64": frame_b64},
        headers=student_headers,
    ).json()
    assert reg_face["success"] is True

    verify_face = client.post(
        "/api/proctoring/verify-face",
        json={"query_image": frame_b64},
        headers=student_headers,
    ).json()
    assert verify_face["verified"] is True

    # 5. Start Exam Attempt
    start_res = client.post(
        "/api/attempts/start",
        json={"exam_id": exam["id"], "verified_face_reference": frame_b64},
        headers=student_headers,
    ).json()
    attempt = start_res["attempt"]
    attempt_id = attempt["id"]
    assert attempt["status"] == "in_progress"

    # 6. Live Proctoring & Anomaly Engine
    proc_frame = client.post(
        "/api/proctoring/frame",
        json={
            "attempt_id": attempt_id,
            "image_base64": frame_b64,
            "audio_energy": 0.06,
        },
        headers=student_headers,
    ).json()
    assert "risk_level" in proc_frame

    sim_phone = client.post(
        "/api/demo/simulate",
        json={
            "attempt_id": attempt_id,
            "event_type": "MOBILE_PHONE_DETECTED",
            "confidence": 0.95,
        },
        headers=student_headers,
    ).json()
    assert sim_phone["event"] == "MOBILE_PHONE_DETECTED"

    # 7. Answer Questions & Final Submission
    answers_map = {}
    for q in exam.get("questions", []):
        q_id = q.get("id") or q.get("_id")
        client.post(
            f"/api/attempts/{attempt_id}/answer",
            json={"question_id": q_id, "selected_option": 0},
            headers=student_headers,
        )
        answers_map[q_id] = 0

    submit_res = client.post(
        f"/api/attempts/{attempt_id}/submit",
        json={"answers": answers_map},
        headers=student_headers,
    ).json()
    assert submit_res.get("status") == "submitted"

    # 8. Admin Authentication (OTP login)
    admin_token, admin_headers, admin_user = _capture_otp_login(
        client, "admin@proctor.edu", "Admin@123"
    )
    assert admin_user["role"] == "admin"

    dash = client.get("/api/admin/dashboard", headers=admin_headers).json()
    assert "metrics" in dash

    sessions = client.get("/api/admin/sessions", headers=admin_headers).json()
    assert isinstance(sessions, list)

    report = client.get(
        f"/api/admin/reports/{attempt_id}", headers=admin_headers
    ).json()
    assert report.get("student_info", {}).get("name") is not None