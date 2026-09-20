import os
import json
import uuid
import copy
import threading
from datetime import datetime, timezone
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from backend.config.settings import settings
import logging

logger = logging.getLogger(__name__)

def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

class MockCursor:
    def __init__(self, data):
        self._data = copy.deepcopy(data)
        self._sort_key = None
        self._sort_dir = 1
        self._limit = None
        self._skip = 0

    def sort(self, key_or_list, direction=1):
        if isinstance(key_or_list, list):
            for k, d in reversed(key_or_list):
                self._data.sort(key=lambda x: str(x.get(k, "")), reverse=(d == -1))
        else:
            self._data.sort(key=lambda x: str(x.get(key_or_list, "")), reverse=(direction == -1))
        return self

    def limit(self, n):
        self._limit = n
        return self

    def skip(self, n):
        self._skip = n
        return self

    def __iter__(self):
        data = self._data[self._skip:]
        if self._limit is not None:
            data = data[:self._limit]
        for item in data:
            yield item

    def to_list(self, length=None):
        data = self._data[self._skip:]
        if length is not None:
            data = data[:length]
        return data

class LocalDocumentCollection:
    """Thread-safe resilient document store mimicking MongoDB collection API.

    Each mutation is flushed to disk via an atomic write (temp file + os.replace)
    so a crash or concurrent request can never leave a truncated/corrupt JSON file.
    An in-process re-entrant lock serializes read-modify-write cycles across threads.
    """
    def __init__(self, name, db_path=None):
        self.name = name
        self.db_path = db_path or settings.DATA_STORE_DIR
        os.makedirs(self.db_path, exist_ok=True)
        self.file_path = os.path.join(self.db_path, f"{name}.json")
        self._docs = []
        self._lock = threading.RLock()
        self._load()

    def _load(self):
        if os.path.exists(self.file_path):
            try:
                with open(self.file_path, "r", encoding="utf-8") as f:
                    self._docs = json.load(f)
            except Exception as e:
                logger.error(f"Error loading {self.name}.json: {e}")
                self._docs = []
        else:
            self._docs = []

    def _save(self):
        # Atomic write: write to a temp file then atomically replace the target,
        # preventing partial/truncated JSON if the process dies mid-write.
        tmp_path = f"{self.file_path}.tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(self._docs, f, indent=2, default=str)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.file_path)
        except Exception as e:
            logger.error(f"Error saving {self.name}.json: {e}")
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass

    def _matches(self, doc, query):
        if not query:
            return True
        for key, val in query.items():
            if key == "$or" and isinstance(val, list):
                if not any(self._matches(doc, q) for q in val):
                    return False
                continue
            if isinstance(val, dict):
                doc_val = doc.get(key)
                if "$in" in val and doc_val not in val["$in"]:
                    return False
                if "$gte" in val and not (doc_val is not None and doc_val >= val["$gte"]):
                    return False
                if "$lte" in val and not (doc_val is not None and doc_val <= val["$lte"]):
                    return False
                if "$gt" in val and not (doc_val is not None and doc_val > val["$gt"]):
                    return False
                if "$lt" in val and not (doc_val is not None and doc_val < val["$lt"]):
                    return False
                if "$ne" in val and doc_val == val["$ne"]:
                    return False
            else:
                if str(doc.get(key)) != str(val) and doc.get(key) != val:
                    return False
        return True

    def find_one(self, query=None):
        query = query or {}
        with self._lock:
            for doc in self._docs:
                if self._matches(doc, query):
                    return copy.deepcopy(doc)
        return None

    def find(self, query=None):
        query = query or {}
        with self._lock:
            matches = [copy.deepcopy(doc) for doc in self._docs if self._matches(doc, query)]
        return MockCursor(matches)

    def insert_one(self, doc):
        with self._lock:
            new_doc = copy.deepcopy(doc)
            if "_id" not in new_doc:
                new_doc["_id"] = str(uuid.uuid4())
            if "created_at" not in new_doc:
                new_doc["created_at"] = _utcnow_iso()
            self._docs.append(new_doc)
            self._save()

            class InsertResult:
                inserted_id = new_doc["_id"]
            return InsertResult()

    def update_one(self, query, update):
        with self._lock:
            for doc in self._docs:
                if self._matches(doc, query):
                    if "$set" in update:
                        for k, v in update["$set"].items():
                            doc[k] = v
                    if "$inc" in update:
                        for k, v in update["$inc"].items():
                            doc[k] = doc.get(k, 0) + v
                    if "$push" in update:
                        for k, v in update["$push"].items():
                            if k not in doc or not isinstance(doc[k], list):
                                doc[k] = []
                            doc[k].append(v)
                    doc["updated_at"] = _utcnow_iso()
                    self._save()

                    class UpdateResult:
                        matched_count = 1
                        modified_count = 1
                    return UpdateResult()

            class UpdateResult:
                matched_count = 0
                modified_count = 0
            return UpdateResult()

    def delete_one(self, query):
        with self._lock:
            for idx, doc in enumerate(self._docs):
                if self._matches(doc, query):
                    self._docs.pop(idx)
                    self._save()
                    class DeleteResult:
                        deleted_count = 1
                    return DeleteResult()
            class DeleteResult:
                deleted_count = 0
            return DeleteResult()

    def delete_many(self, query):
        with self._lock:
            initial = len(self._docs)
            self._docs = [doc for doc in self._docs if not self._matches(doc, query)]
            deleted = initial - len(self._docs)
            if deleted > 0:
                self._save()
            class DeleteResult:
                deleted_count = deleted
            return DeleteResult()

    def count_documents(self, query=None):
        query = query or {}
        with self._lock:
            return sum(1 for doc in self._docs if self._matches(doc, query))

class DatabaseManager:
    def __init__(self):
        self.is_mongodb = False
        self.client = None
        self.db = None
        self._local_collections = {}
        self._connected = False
        # Connection is deferred — call connect() during app startup (lifespan).

    def connect(self) -> None:
        """Establish the database connection.

        Must be called once during application startup (e.g. FastAPI lifespan).
        In local mode this is a no-op.  In mongodb mode it connects to the
        configured MONGODB_URI and raises RuntimeError on failure.
        """
        if self._connected:
            return
        self._connected = True

        db_mode = settings.DATABASE_MODE

        # --- Secret-safe startup diagnostics ---
        mongodb_uri_configured = bool(
            os.getenv("MONGODB_URI") and os.getenv("MONGODB_URI", "").strip()
        )
        logger.info(
            "Database startup — DATABASE_MODE=%s | MONGODB_URI configured=%s",
            db_mode,
            mongodb_uri_configured,
        )

        if db_mode == "local":
            self.is_mongodb = False
            logger.info("DATABASE_MODE=local — using file-backed document storage (dev/demo only).")
            return

        # DATABASE_MODE=mongodb (production default)
        if not mongodb_uri_configured:
            logger.critical(
                "DATABASE_MODE=mongodb but MONGODB_URI environment variable is NOT set. "
                "Set MONGODB_URI to your MongoDB Atlas connection string."
            )
            raise RuntimeError(
                "MongoDB connection failed: MONGODB_URI environment variable is not configured."
            )

        try:
            client = MongoClient(
                settings.MONGODB_URI,
                serverSelectionTimeoutMS=5000,
                maxPoolSize=10,
                minPoolSize=1,
                maxIdleTimeMS=60000,
            )
            client.server_info()  # force connection check
            self.client = client
            self.db = client[settings.DATABASE_NAME]
            self.is_mongodb = True
            logger.info("MongoDB connection — SUCCESS (DATABASE_MODE=mongodb).")
        except Exception as e:
            logger.critical("MongoDB connection — FAILED.")
            raise RuntimeError(
                "MongoDB connection failed in production mode (DATABASE_MODE=mongodb). "
                "Verify MONGODB_URI is correct and the cluster is reachable."
            ) from e

    def get_collection(self, collection_name: str):
        if self.is_mongodb and self.db is not None:
            try:
                return self.db[collection_name]
            except Exception:
                pass
        if collection_name not in self._local_collections:
            self._local_collections[collection_name] = LocalDocumentCollection(
                collection_name, db_path=settings.DATA_STORE_DIR
            )
        return self._local_collections[collection_name]

db_manager = DatabaseManager()

# Collection Accessors
def get_users_col():
    return db_manager.get_collection("users")

def get_exams_col():
    return db_manager.get_collection("exams")

def get_questions_col():
    return db_manager.get_collection("questions")

def get_attempts_col():
    return db_manager.get_collection("exam_attempts")

def get_events_col():
    return db_manager.get_collection("proctoring_events")

def get_reports_col():
    return db_manager.get_collection("proctoring_reports")

def get_sessions_col():
    """Persistent session/revocation store used for logout and OTP state."""
    return db_manager.get_collection("sessions")
