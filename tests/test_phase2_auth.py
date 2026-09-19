"""Phase 2 tests: authentication, roles, OTP, and persistence.

These tests use unique, timestamp-scoped accounts to avoid clobbering seeded data
and to verify that data persists across "restarts" (re-instantiated collection).
"""
import time
import uuid
import pytest
from fastapi.testclient import TestClient

from backend.app import app
from backend.services.otp_service import otp_service, _hash_otp, _verify_otp_hash
from backend.config.db import db_manager, LocalDocumentCollection
from backend.config.settings import settings


@pytest.fixture
def client():
    return TestClient(app)


def _uniq(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}@test.local"


def _capture_otp_login(client, email, password):
    """Drive the full two-step login and return the verify response."""
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
    return client.post("/api/auth/login/verify", json={
        "challenge_token": challenge.json()["challenge_token"],
        "otp": captured["otp"],
    })


def _register_student(client):
    email = _uniq("stu")
    res = client.post("/api/auth/register", json={
        "name": "Test Student",
        "email": email,
        "password": "Passw0rd!",
        "role": "student",
    })
    assert res.status_code == 200, res.text
    return email, res.json()


def _register_professor(client):
    email = _uniq("prof")
    res = client.post("/api/auth/register", json={
        "name": "Test Professor",
        "email": email,
        "password": "Passw0rd!",
        "role": "professor",
        "subject": "DBMS",
    })
    assert res.status_code == 200, res.text
    return email, res.json()


# ---------------------------------------------------------------- Authentication

def test_student_registration_and_login(client):
    email, data = _register_student(client)
    assert data["user"]["role"] == "student"
    token = data["access_token"]
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["email"] == email

    # Login via the two-step OTP flow.
    login = _capture_otp_login(client, email, "Passw0rd!")
    assert login.status_code == 200, login.text
    assert login.json()["user"]["role"] == "student"


def test_professor_registration_and_login(client):
    email, data = _register_professor(client)
    assert data["user"]["role"] == "professor"
    assert data["user"]["subject"] == "DBMS"

    login = _capture_otp_login(client, email, "Passw0rd!")
    assert login.status_code == 200, login.text
    assert login.json()["user"]["role"] == "professor"


def test_admin_login(client):
    # Use a unique admin to avoid cooldown from test_auth_api.py.
    email = f"adm-{uuid.uuid4().hex[:10]}@proctor.edu"
    client.post("/api/auth/register-admin", json={
        "name": "Test Admin",
        "email": email,
        "password": "Admin@123",
        "invite_code": settings.ADMIN_INVITE_CODE,
        "subject": "All Subjects",
    })
    res = _capture_otp_login(client, email, "Admin@123")
    assert res.status_code == 200, res.text
    assert res.json()["user"]["role"] == "admin"


def test_invalid_credentials(client):
    res = client.post("/api/auth/login", json={
        "email": "student@proctor.edu",
        "password": "definitely-wrong",
    })
    assert res.status_code == 401


def test_protected_route_without_token(client):
    res = client.get("/api/auth/me")
    assert res.status_code == 401


def test_protected_route_with_invalid_token(client):
    res = client.get("/api/auth/me", headers={"Authorization": "Bearer not-a-real-token"})
    assert res.status_code == 401


def test_logout_revokes_session(client):
    email, data = _register_student(client)
    token = data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    assert client.get("/api/auth/me", headers=headers).status_code == 200

    logout = client.post("/api/auth/logout", headers=headers)
    assert logout.status_code == 200

    # The same token must now be rejected.
    assert client.get("/api/auth/me", headers=headers).status_code == 401


def test_authorization_admin_vs_student(client):
    email, data = _register_student(client)
    token = data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # A student should NOT be able to hit an admin-only endpoint.
    res = client.get("/api/admin/dashboard", headers=headers)
    assert res.status_code in (403, 404)


def test_role_enum_supports_professor():
    from backend.models.entities import RoleEnum
    assert RoleEnum.PROFESSOR == "professor"


# ----------------------------------------------------------------------- OTP

def test_otp_hash_roundtrip():
    otp = "123456"
    h = _hash_otp(otp)
    assert h != otp
    assert _verify_otp_hash("123456", h) is True
    assert _verify_otp_hash("654321", h) is False
    # Stored hash never contains the plaintext.
    assert otp not in h


def test_otp_generate_and_verify_flow(client):
    email = _uniq("otp")

    # Capture the plaintext OTP on the very first request via a provider stub.
    captured = {}
    from backend.services import otp_service as otp_mod
    captured_send = otp_mod.get_otp_provider

    def capturing_provider():
        class _Cap:
            def send(self, email, otp, purpose):
                captured["otp"] = otp
        return _Cap()

    otp_mod.get_otp_provider = capturing_provider
    try:
        res = client.post("/api/auth/otp/request", json={"email": email, "purpose": "login"})
    finally:
        otp_mod.get_otp_provider = captured_send

    assert res.status_code == 200, res.text
    data = res.json()
    assert "expires_in_seconds" in data

    otp_value = captured.get("otp")
    assert otp_value and len(otp_value) == settings.OTP_LENGTH

    # Verify with the correct OTP.
    vres = client.post("/api/auth/otp/verify", json={"email": email, "otp": otp_value, "purpose": "login"})
    assert vres.status_code == 200, vres.text

    # Reusing the same OTP must fail (one-time use).
    vres2 = client.post("/api/auth/otp/verify", json={"email": email, "otp": otp_value, "purpose": "login"})
    assert vres2.status_code == 400


def test_otp_incorrect_code(client):
    email = _uniq("otpbad")
    client.post("/api/auth/otp/request", json={"email": email, "purpose": "login"})

    # Wrong code repeatedly; should exhaust attempts and eventually lock.
    wrong = "000000"
    statuses = []
    for _ in range(settings.OTP_MAX_ATTEMPTS + 1):
        r = client.post("/api/auth/otp/verify", json={"email": email, "otp": wrong, "purpose": "login"})
        statuses.append(r.status_code)

    assert statuses[0] == 400  # incorrect
    assert statuses[-1] in (400, 429)  # locked/consumed at limit


def test_otp_resend_cooldown(client):
    email = _uniq("otpcool")
    r1 = client.post("/api/auth/otp/request", json={"email": email, "purpose": "login"})
    assert r1.status_code == 200

    # Immediate resend must be rate-limited.
    r2 = client.post("/api/auth/otp/request", json={"email": email, "purpose": "login"})
    assert r2.status_code == 429


# --------------------------------------------------- OTP-Login integration

def test_password_alone_does_not_issue_jwt(client):
    """Correct credentials return a challenge, never a JWT directly."""
    email, _ = _register_student(client)
    challenge = client.post("/api/auth/login", json={"email": email, "password": "Passw0rd!"})
    assert challenge.status_code == 200
    data = challenge.json()
    assert "access_token" not in data
    assert "challenge_token" in data
    assert "email" in data


def test_login_wrong_otp_fails(client):
    email, _ = _register_student(client)
    challenge = client.post("/api/auth/login", json={"email": email, "password": "Passw0rd!"})
    assert challenge.status_code == 200
    ct = challenge.json()["challenge_token"]

    # Verify with a wrong OTP.
    v = client.post("/api/auth/login/verify", json={"challenge_token": ct, "otp": "000000"})
    assert v.status_code == 400
    assert "access_token" not in v.json()


def test_login_otp_reuse_fails(client):
    email, _ = _register_student(client)
    # First full login to consume one code, then get a fresh challenge.
    _capture_otp_login(client, email, "Passw0rd!")

    # Clear the consumed OTP record so the cooldown does not block the next request.
    from backend.config.db import get_sessions_col
    get_sessions_col().delete_one({"_id": f"otp:login:{email}"})

    # Get a second challenge and capture its OTP.
    from backend.services import otp_service as otp_mod
    captured = {}
    original = otp_mod.get_otp_provider

    class _Cap:
        def send(self, email, otp, purpose):
            captured["otp"] = otp
    otp_mod.get_otp_provider = lambda: _Cap()
    try:
        challenge = client.post("/api/auth/login", json={"email": email, "password": "Passw0rd!"})
    finally:
        otp_mod.get_otp_provider = original

    ct2 = challenge.json()["challenge_token"]
    otp_val = captured["otp"]

    # Use OTP once — success.
    v1 = client.post("/api/auth/login/verify", json={"challenge_token": ct2, "otp": otp_val})
    assert v1.status_code == 200

    # Reuse same OTP — fails.
    v2 = client.post("/api/auth/login/verify", json={"challenge_token": ct2, "otp": otp_val})
    assert v2.status_code == 400


def test_login_challenge_tampered_fails(client):
    """A tampered or expired challenge token must not authenticate."""
    v = client.post("/api/auth/login/verify", json={"challenge_token": "not-a-real-token", "otp": "123456"})
    assert v.status_code == 401


def test_login_otp_attempt_exhaustion(client):
    email, _ = _register_student(client)
    challenge = client.post("/api/auth/login", json={"email": email, "password": "Passw0rd!"})
    assert challenge.status_code == 200
    ct = challenge.json()["challenge_token"]

    # Exhaust all attempts with wrong codes.
    wrong = "000000"
    for _ in range(settings.OTP_MAX_ATTEMPTS):
        r = client.post("/api/auth/login/verify", json={"challenge_token": ct, "otp": wrong})
        assert r.status_code == 400
    # One more should be rejected (locked).
    r = client.post("/api/auth/login/verify", json={"challenge_token": ct, "otp": wrong})
    assert r.status_code in (400, 429)


# ------------------------------------------------------------------- Persistence

def test_persistence_across_collection_reinstantiation(tmp_path):
    """Data written through one collection instance must be readable by a fresh
    instance reading the same backing file (simulates a restart/serverless cold start)."""
    import backend.config.settings as s
    # Use a distinct data dir for this test.
    coll = LocalDocumentCollection("persist_test", db_path=str(tmp_path))
    _id = coll.insert_one({"name": "alpha"}).inserted_id
    assert coll.find_one({"_id": _id})["name"] == "alpha"

    # Fresh instance reads from disk.
    coll2 = LocalDocumentCollection("persist_test", db_path=str(tmp_path))
    assert coll2.find_one({"_id": _id})["name"] == "alpha"

    # Update on second instance and confirm on a third.
    coll2.update_one({"_id": _id}, {"$set": {"name": "beta"}})
    coll3 = LocalDocumentCollection("persist_test", db_path=str(tmp_path))
    assert coll3.find_one({"_id": _id})["name"] == "beta"


def test_concurrent_writes_do_not_corrupt(tmp_path):
    """Concurrent inserts/updates from many threads must not lose data."""
    import threading
    coll = LocalDocumentCollection("concurrent_test", db_path=str(tmp_path))
    errors = []

    def worker(n):
        try:
            for i in range(20):
                coll.insert_one({"worker": n, "i": i})
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert coll.count_documents({}) == 200

    # Reload from disk to confirm integrity.
    fresh = LocalDocumentCollection("concurrent_test", db_path=str(tmp_path))
    assert fresh.count_documents({}) == 200


def test_multiple_users_isolated(client):
    e1, d1 = _register_student(client)
    e2, d2 = _register_student(client)
    assert e1 != e2

    me1 = client.get("/api/auth/me", headers={"Authorization": f"Bearer {d1['access_token']}"})
    me2 = client.get("/api/auth/me", headers={"Authorization": f"Bearer {d2['access_token']}"})
    assert me1.json()["email"] == e1
    assert me2.json()["email"] == e2
    assert me1.json()["id"] != me2.json()["id"]