"""A small fixed-window rate limiter.

In-memory, per process, which is fine for a single instance and for tests.
A real deployment would swap the storage for Redis (e.g. Flask-Limiter) so
the limits hold across workers.
"""
import threading
import time
from functools import wraps

from flask import current_app, jsonify, request


class RateLimiter:
    def __init__(self):
        self._buckets: dict[str, tuple[float, int]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window: int) -> bool:
        """Record one hit; return True if still within the limit."""
        now = time.monotonic()
        with self._lock:
            start, count = self._buckets.get(key, (now, 0))
            if now - start >= window:
                start, count = now, 0
            count += 1
            self._buckets[key] = (start, count)
        return count <= limit

    def hits(self, key: str, window: int) -> int:
        now = time.monotonic()
        with self._lock:
            start, count = self._buckets.get(key, (now, 0))
        return 0 if now - start >= window else count

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


def get_limiter() -> RateLimiter:
    return current_app.extensions["limiter"]


def rate_limited(limit: int, window: int, key_func=None):
    """Decorator for view functions. Keyed by client IP unless key_func is given."""
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            ident = key_func() if key_func else request.remote_addr
            key = f"{view.__module__}.{view.__name__}:{ident}"
            if not get_limiter().hit(key, limit, window):
                resp = jsonify({"error": "Too many requests, slow down"})
                resp.status_code = 429
                resp.headers["Retry-After"] = str(window)
                return resp
            return view(*args, **kwargs)
        return wrapper
    return decorator
