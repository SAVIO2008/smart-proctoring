# Lazy AI module accessors.
# Singletons are created on first access so that importing this package does not
# eagerly pull in OpenCV, torch, mediapipe, or ultralytics.  This keeps the
# FastAPI import-time footprint small and allows the application to boot on
# Vercel (where OpenCV native libraries are unavailable) as long as no ML
# endpoint is called.

import threading

_lock = threading.Lock()

_cache_face_detector = None
_cache_face_verifier = None
_cache_gaze_detector = None
_cache_person_detector = None
_cache_phone_detector = None
_cache_audio_detector = None
_cache_scoring_engine = None


def _get_face_detector():
    global _cache_face_detector
    if _cache_face_detector is None:
        with _lock:
            if _cache_face_detector is None:
                from backend.ai.face_detection import FaceDetector
                _cache_face_detector = FaceDetector()
    return _cache_face_detector


def _get_face_verifier():
    global _cache_face_verifier
    if _cache_face_verifier is None:
        with _lock:
            if _cache_face_verifier is None:
                from backend.ai.face_verification import FaceVerifier
                _cache_face_verifier = FaceVerifier()
    return _cache_face_verifier


def _get_gaze_detector():
    global _cache_gaze_detector
    if _cache_gaze_detector is None:
        with _lock:
            if _cache_gaze_detector is None:
                from backend.ai.gaze_detection import GazeDetector
                _cache_gaze_detector = GazeDetector()
    return _cache_gaze_detector


def _get_person_detector():
    global _cache_person_detector
    if _cache_person_detector is None:
        with _lock:
            if _cache_person_detector is None:
                from backend.ai.person_detection import PersonPresenceDetector
                _cache_person_detector = PersonPresenceDetector()
    return _cache_person_detector


def _get_phone_detector():
    global _cache_phone_detector
    if _cache_phone_detector is None:
        with _lock:
            if _cache_phone_detector is None:
                from backend.ai.phone_detection import PhoneDetector
                _cache_phone_detector = PhoneDetector()
    return _cache_phone_detector


def _get_audio_detector():
    global _cache_audio_detector
    if _cache_audio_detector is None:
        with _lock:
            if _cache_audio_detector is None:
                from backend.ai.audio_detection import AudioActivityDetector
                _cache_audio_detector = AudioActivityDetector()
    return _cache_audio_detector


def _get_scoring_engine():
    global _cache_scoring_engine
    if _cache_scoring_engine is None:
        with _lock:
            if _cache_scoring_engine is None:
                from backend.ai._scoring_engine import SuspicionScoringEngine
                _cache_scoring_engine = SuspicionScoringEngine()
    return _cache_scoring_engine


# ---------------------------------------------------------------------------
# Public lazy-accessor singletons – drop-in replacements for the old
# module-level instances.  Usage:
#
#     from backend.ai import face_detector
#     faces = face_detector.detect_faces(img)
#
# NOTE: The submodule that was previously ``backend.ai.scoring_engine`` has
# been renamed to ``_scoring_engine`` so its name does not collide with the
# ``scoring_engine`` lazy proxy below.
# ---------------------------------------------------------------------------

class _LazyProxy:
    """Descriptor that resolves the real object on first access."""
    def __init__(self, factory):
        self._factory = factory
        self._obj = None

    def __getattr__(self, name):
        if self._obj is None:
            self._obj = self._factory()
        return getattr(self._obj, name)

    def __call__(self, *args, **kwargs):
        if self._obj is None:
            self._obj = self._factory()
        return self._obj(*args, **kwargs)


face_detector    = _LazyProxy(_get_face_detector)
face_verifier    = _LazyProxy(_get_face_verifier)
gaze_detector    = _LazyProxy(_get_gaze_detector)
person_detector  = _LazyProxy(_get_person_detector)
phone_detector   = _LazyProxy(_get_phone_detector)
audio_detector   = _LazyProxy(_get_audio_detector)
scoring_engine   = _LazyProxy(_get_scoring_engine)


__all__ = [
    "face_detector",
    "face_verifier",
    "gaze_detector",
    "person_detector",
    "phone_detector",
    "audio_detector",
    "scoring_engine",
]