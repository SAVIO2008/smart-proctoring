"""Persistent session/revocation store.

Logout must actually invalidate a JWT server-side. Since JWTs are stateless,
we record revoked token ids (``jti``) so ``get_current_user`` can reject them.
This registry lives in the shared ``sessions`` collection so revocation survives
a process restart (important for multi-user and serverless deployments).

An in-memory cache avoids a full collection scan on every authenticated request.
"""
import threading
from typing import Set
from backend.config.db import get_sessions_col


class SessionStore:
    """Tracks revoked JWT ``jti`` values persistently with an in-memory cache."""

    def __init__(self):
        self._revoked: Set[str] = set()
        self._loaded = False
        self._lock = threading.Lock()

    def _ensure_loaded(self):
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            col = get_sessions_col()
            docs = list(col.find({"type": "revoked_jti"}))
            self._revoked = {d["_id"] for d in docs}
            self._loaded = True

    def _now(self):
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()

    def revoke(self, jti: str) -> None:
        self._ensure_loaded()
        col = get_sessions_col()
        existing = col.find_one({"_id": jti})
        if existing:
            return
        col.insert_one({
            "_id": jti,
            "type": "revoked_jti",
            "created_at": self._now(),
        })
        with self._lock:
            self._revoked.add(jti)

    def is_revoked(self, jti: str) -> bool:
        if not jti:
            return False
        self._ensure_loaded()
        return jti in self._revoked

    def get_revoked_jtis(self) -> Set[str]:
        """Return the full set of revoked jti values from the in-memory cache."""
        self._ensure_loaded()
        return self._revoked.copy()


session_store = SessionStore()