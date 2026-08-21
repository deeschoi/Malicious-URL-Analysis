"""Request-level guards for the scan API: rate limits, concurrency, optional auth.

The scanner makes outbound HTTP requests on behalf of whoever calls it, so an
open ``POST /api/scan`` is both a denial-of-service target and an outbound proxy
for someone else. These are process-local limits — good enough for a single
container, and the right shape to swap for Redis if this is ever replicated.
"""

from __future__ import annotations

import hmac
import threading
import time
from collections import defaultdict, deque

from fastapi import Header, HTTPException, Request

from phishing.settings import (
    SCAN_MAX_CONCURRENT,
    SCAN_RATE_PER_MINUTE,
    api_key,
)

WINDOW_SECONDS = 60.0


class RateLimiter:
    """Sliding-window counter keyed by client, with a global in-flight cap."""

    def __init__(self, per_minute: int, max_concurrent: int) -> None:
        self.per_minute = max(0, per_minute)
        self.max_concurrent = max(1, max_concurrent)
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(self.max_concurrent)

    def check(self, client: str, now: float | None = None) -> None:
        """Raise 429 when ``client`` has spent its per-minute budget."""
        if self.per_minute <= 0:
            return
        now = time.monotonic() if now is None else now
        with self._lock:
            hits = self._hits[client]
            cutoff = now - WINDOW_SECONDS
            while hits and hits[0] < cutoff:
                hits.popleft()
            if len(hits) >= self.per_minute:
                retry_after = max(1, int(WINDOW_SECONDS - (now - hits[0])))
                raise HTTPException(
                    status_code=429,
                    detail=(
                        f"Rate limit reached: {self.per_minute} requests per minute. "
                        f"Try again in {retry_after}s."
                    ),
                    headers={"Retry-After": str(retry_after)},
                )
            hits.append(now)
            # Bound memory: a scanner sprayed from many source IPs would
            # otherwise accumulate one deque per address forever.
            if len(self._hits) > 10_000:
                for key in [k for k, v in self._hits.items() if not v][:5_000]:
                    del self._hits[key]

    def slot(self) -> _Slot:
        return _Slot(self._slots)


class _Slot:
    """Context manager that refuses rather than queues when the pool is full."""

    def __init__(self, semaphore: threading.BoundedSemaphore) -> None:
        self._semaphore = semaphore
        self._held = False

    def __enter__(self) -> _Slot:
        if not self._semaphore.acquire(blocking=False):
            raise HTTPException(
                status_code=503,
                detail="Too many scans in flight. Try again in a moment.",
                headers={"Retry-After": "5"},
            )
        self._held = True
        return self

    def __exit__(self, *exc) -> None:
        if self._held:
            self._semaphore.release()
            self._held = False


scan_limiter = RateLimiter(SCAN_RATE_PER_MINUTE, SCAN_MAX_CONCURRENT)


def client_key(request: Request) -> str:
    """Identify the caller for rate-limiting.

    ``X-Forwarded-For`` is honoured only when a trusted proxy is declared,
    because a client can otherwise set it to anything and get a fresh budget
    per request.
    """
    from phishing.settings import env_bool

    if env_bool("SPHINX_TRUST_PROXY_HEADERS"):
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Reject the request unless ``X-API-Key`` matches, when a key is configured.

    No key configured means the route stays open, which is the local-demo
    default. ``compare_digest`` keeps the check constant-time.
    """
    expected = api_key()
    if not expected:
        return
    if not x_api_key or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid X-API-Key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
