import pytest
import uuid
from fastapi.testclient import TestClient
from backend.app import app
from backend.config.settings import settings

client = TestClient(app)


def _capture_otp(client, email, password):
    """Drive the full two-step login and return (status, data) of the final verify.

    Captures the plaintext OTP on the challenge request by stubbing the delivery
    provider, then verifies it and returns the authenticated session response.
    """
    from backend.services import otp_service as otp_mod
    captured = {}
    original = otp_mod.get_otp_provider

    class _Cap:
        def send(self, email, otp, purpose):
            captured["otp"] = otp

    otp_mod.get_otp_provider = lambda: _Cap()
    try:
        challenge = client.post("/api/auth/login", json={"email": email, "password": password})
    finally:
        otp_mod.get_otp_provider = original

    assert challenge.status_code == 200, challenge.text
    assert "challenge_token" in challenge.json()
    assert "access_token" not in challenge.json()
    otp_value = captured["otp"]

    return client.post("/api/auth/login/verify", json={
        "challenge_token": challenge.json()["challenge_token"],
        "otp": otp_value,
    })


def _register_unique(client, role="student", password="Passw0rd!"):
    """Register a unique user and return (email, token_response).

    Admin registration uses the invite-code endpoint; all other roles use
    the public /auth/register endpoint.
    """
    email = f"test-{uuid.uuid4().hex[:10]}@proctor.edu"
    if role == "admin":
        res = client.post("/api/auth/register-admin", json={
            "name": f"Test {role.title()}",
            "email": email,
            "password": password,
            "invite_code": settings.ADMIN_INVITE_CODE,
            "subject": "All Subjects",
        })
    else:
        res = client.post("/api/auth/register", json={
            "name": f"Test {role.title()}",
            "email": email,
            "password": password,
            "role": role,
            "subject": "DBMS" if role == "professor" else None,
        })
    assert res.status_code == 200, res.text
    return email, res.json()


def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "scoring_weights" in data


def test_admin_and_student_login():
    # Admin: valid credentials -> OTP challenge -> verify -> JWT.
    res_admin = _capture_otp(client, "admin@proctor.edu", "Admin@123")
    assert res_admin.status_code == 200, res_admin.text
    data_admin = res_admin.json()
    assert "access_token" in data_admin
    assert data_admin["user"]["role"] == "admin"

    # Student login (two-step).
    res_stu = _capture_otp(client, "student@proctor.edu", "Student@123")
    assert res_stu.status_code == 200, res_stu.text
    data_stu = res_stu.json()
    assert "access_token" in data_stu
    assert data_stu["user"]["role"] == "student"


def test_invalid_login():
    email = f"wrong-{uuid.uuid4().hex[:8]}@proctor.edu"
    res = client.post("/api/auth/login", json={
        "email": email,
        "password": "WrongPassword!"
    })
    assert res.status_code == 401


def test_password_alone_cannot_authenticate():
    """Correct credentials trigger a challenge, but WITHOUT the OTP there is no JWT."""
    email, _ = _register_unique(client)
    res = client.post("/api/auth/login", json={
        "email": email,
        "password": "Passw0rd!"
    })
    assert res.status_code == 200
    data = res.json()
    assert "access_token" not in data
    assert "challenge_token" in data


def test_update_profile_student_and_admin():
    # Use unique accounts to avoid OTP resend cooldown from prior tests.
    stu_email, _ = _register_unique(client, "student")
    adm_email, _ = _register_unique(client, "admin")

    # Full two-step student login.
    student_res = _capture_otp(client, stu_email, "Passw0rd!")
    assert student_res.status_code == 200, student_res.text
    token = student_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Update student name.
    update_res = client.put("/api/auth/me", json={
        "name": "Alex Updated Candidate",
        "student_id": "STU-NEW-88"
    }, headers=headers)
    assert update_res.status_code == 200
    user_data = update_res.json()["user"]
    assert user_data["name"] == "Alex Updated Candidate"
    assert user_data["student_id"] == "STU-NEW-88"

    # Verify via /api/auth/me.
    me_res = client.get("/api/auth/me", headers=headers)
    assert me_res.status_code == 200
    assert me_res.json()["name"] == "Alex Updated Candidate"

    # Full two-step admin login.
    admin_res = _capture_otp(client, adm_email, "Passw0rd!")
    assert admin_res.status_code == 200, admin_res.text
    admin_token = admin_res.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Update admin name.
    admin_update = client.put("/api/auth/me", json={
        "name": "Prof. Charles Xavier",
        "subject": "AI & Machine Learning"
    }, headers=admin_headers)
    assert admin_update.status_code == 200
    adm_user = admin_update.json()["user"]
    assert adm_user["name"] == "Prof. Charles Xavier"
    assert adm_user["subject"] == "AI & Machine Learning"


def test_jwt_persists_to_protected_endpoints():
    """Regression: after OTP login the JWT must authenticate protected endpoints.

    Verifies that the user created during registration is found by the JWT's
    ``sub`` claim when the token is presented to /api/exams and /api/auth/me.
    This guards against _id mismatch (ObjectId vs string) and ephemeral-storage
    data loss on serverless platforms.
    """
    email, reg_data = _register_unique(client, "student")
    token = reg_data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. /api/auth/me must return the same user.
    me = client.get("/api/auth/me", headers=headers)
    assert me.status_code == 200, f"GET /api/auth/me failed: {me.text}"
    assert me.json()["email"] == email

    # 2. /api/exams must NOT return "User associated with token no longer exists".
    exams = client.get("/api/exams", headers=headers)
    assert exams.status_code == 200, (
        f"GET /api/exams returned {exams.status_code}: {exams.text}\n"
        "If the detail is 'User associated with token no longer exists', "
        "the JWT sub does not match any persisted user."
    )
    assert isinstance(exams.json(), list)

    # 3. Full OTP login flow (two-step) must also reach /api/exams.
    otp_res = _capture_otp(client, email, "Passw0rd!")
    assert otp_res.status_code == 200, otp_res.text
    otp_token = otp_res.json()["access_token"]
    otp_headers = {"Authorization": f"Bearer {otp_token}"}

    me2 = client.get("/api/auth/me", headers=otp_headers)
    assert me2.status_code == 200
    assert me2.json()["email"] == email

    exams2 = client.get("/api/exams", headers=otp_headers)
    assert exams2.status_code == 200, (
        f"OTP-login GET /api/exams returned {exams2.status_code}: {exams2.text}"
    )
    assert isinstance(exams2.json(), list)


def test_jwt_user_not_found_is_401():
    """A tampered JWT with a valid signature but non-existent sub must return 401."""
    import jwt as pyjwt
    from backend.config.settings import settings

    fake_token = pyjwt.encode(
        {"sub": "nonexistent-user-id-xyz", "email": "ghost@proctor.edu", "role": "student"},
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    headers = {"Authorization": f"Bearer {fake_token}"}
    res = client.get("/api/exams", headers=headers)
    assert res.status_code == 401
    assert "no longer exists" in res.json()["detail"]