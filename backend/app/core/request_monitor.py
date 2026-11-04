"""
Lightweight in-memory log of HTTP requests reaching this backend, used by
the Network IDS module's Live Request Monitor (see
app/modules/network_ids/live_monitor.py).

This is NOT a packet sniffer. A Python web process — and certainly a
Streamlit Community Cloud container — has no access to a raw network
interface, so it can never see TCP/IP packets the way the original
NSL-KDD dataset (captured with tcpdump on a real network) did. What it
CAN see, honestly, is every HTTP request that actually reaches this
FastAPI app. That is exactly what this module records: real request
metadata (method, path, status code, timing, byte counts), nothing
fabricated. live_monitor.py turns these into NSL-KDD-style connection
features; the page itself discloses this distinction plainly so nobody
mistakes an HTTP-layer demo for packet-layer network intrusion detection.

Kept as simple module-level state (a bounded deque + a lock), matching
this codebase's existing style for small pieces of shared runtime state
(see security_headers.py's HEADERS_ENABLED) rather than introducing a
new storage layer for a few hundred in-memory rows.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from threading import Lock

from starlette.middleware.base import BaseHTTPMiddleware

MONITOR_ENABLED = True

_MAX_ENTRIES = 500

# Excluded so the monitor doesn't fill up with its own polling traffic —
# the dashboard calls this endpoint every time someone opens or refreshes
# the Live Request Monitor panel, which would otherwise dominate the
# window with meaningless, self-referential noise instead of real traffic.
_EXCLUDED_PATHS = {"/api/v1/network-ids/live-feed"}


@dataclass
class RequestEntry:
    id: int
    ts: float
    client_ip: str
    method: str
    path: str
    status_code: int
    duration_ms: float
    req_bytes: int
    resp_bytes: int
    authenticated: bool
    # Filled in lazily, at most once, the first time this entry is served
    # by GET /network-ids/live-feed — see live_monitor.classify_entry.
    # Caching here means each real request is ever run through the model
    # at most once, no matter how many times the feed is polled afterward.
    classification: dict | None = None


_log: deque[RequestEntry] = deque(maxlen=_MAX_ENTRIES)
_lock = Lock()
_next_id = 1


def record(*, client_ip: str, method: str, path: str, status_code: int,
           duration_ms: float, req_bytes: int, resp_bytes: int, authenticated: bool) -> None:
    global _next_id
    with _lock:
        entry = RequestEntry(
            id=_next_id, ts=time.time(), client_ip=client_ip, method=method, path=path,
            status_code=status_code, duration_ms=duration_ms, req_bytes=req_bytes,
            resp_bytes=resp_bytes, authenticated=authenticated,
        )
        _next_id += 1
        _log.append(entry)


def all_entries() -> list[RequestEntry]:
    """Oldest-first snapshot — the ordering live_monitor's windowing math
    expects. A plain list copy, so callers can iterate freely without
    holding the lock or racing a concurrent append."""
    with _lock:
        return list(_log)


def clear() -> None:
    with _lock:
        _log.clear()


def set_enabled(enabled: bool) -> None:
    global MONITOR_ENABLED
    MONITOR_ENABLED = enabled


class RequestMonitorMiddleware(BaseHTTPMiddleware):
    """Logs every HTTP request/response pair that reaches this backend.
    Pure observation — never blocks meaningfully, never mutates the
    request or response — and, in keeping with the rest of this project's
    ethics posture (see docs/ETHICS.md), only ever watches traffic to our
    OWN server, never anything external."""

    async def dispatch(self, request, call_next):
        start = time.perf_counter()
        try:
            req_bytes = int(request.headers.get("content-length") or 0)
        except ValueError:
            req_bytes = 0

        response = await call_next(request)

        path = request.url.path
        if MONITOR_ENABLED and path not in _EXCLUDED_PATHS:
            duration_ms = (time.perf_counter() - start) * 1000
            try:
                resp_bytes = int(response.headers.get("content-length") or 0)
            except ValueError:
                resp_bytes = 0
            record(
                client_ip=request.client.host if request.client else "unknown",
                method=request.method,
                path=path,
                status_code=response.status_code,
                duration_ms=duration_ms,
                req_bytes=req_bytes,
                resp_bytes=resp_bytes,
                authenticated="authorization" in request.headers,
            )
        return response
