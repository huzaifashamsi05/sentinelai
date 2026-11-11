"""
Per-(username, source IP) login-failure throttling with exponential backoff.

Replaces the old lockout, which counted failures on the User row itself
(User.failed_login_attempts / locked_until) — keyed by username ALONE. That
meant any anonymous client could lock out the real admin indefinitely by
deliberately failing the password 3 times, from anywhere: a trivial
denial-of-service against the one account that matters most (see F-03 in
the security audit). Counting per (username, ip) instead means an
attacker's own IP backs off while the real admin, logging in from a
different IP, is unaffected.

In-memory only, matching this app's existing single-process assumption
(see core/request_monitor.py, which does the same) — Streamlit Community
Cloud's whole SQLite database is already ephemeral across restarts, so
this adds no new fragility, and it avoids a schema migration for what is
fundamentally request-rate state, not a durable record.

Not implemented: CAPTCHA after N failures (the audit's other suggestion).
Left for future work — it needs a third-party CAPTCHA service and a
frontend flow, more than this fix's scope.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

MAX_ATTEMPTS_BEFORE_BACKOFF = 3
BASE_BACKOFF_SECONDS = 5
MAX_BACKOFF_SECONDS = 300  # 5-minute cap — same ceiling the old lockout used


@dataclass
class _Bucket:
    failures: int = 0
    locked_until: float = 0.0


_buckets: dict[tuple[str, str], _Bucket] = {}


def _key(username: str, ip: str) -> tuple[str, str]:
    return (username, ip)


def seconds_locked(username: str, ip: str) -> int:
    """0 if this (username, ip) pair isn't currently backed off, else the
    whole seconds remaining."""
    bucket = _buckets.get(_key(username, ip))
    if not bucket or bucket.locked_until <= time.monotonic():
        return 0
    return int(bucket.locked_until - time.monotonic()) + 1


def record_failure(username: str, ip: str) -> None:
    bucket = _buckets.setdefault(_key(username, ip), _Bucket())
    bucket.failures += 1
    if bucket.failures >= MAX_ATTEMPTS_BEFORE_BACKOFF:
        # 3rd failure -> 5s, 4th -> 10s, 5th -> 20s, ... capped at 5 minutes.
        exponent = bucket.failures - MAX_ATTEMPTS_BEFORE_BACKOFF
        delay = min(BASE_BACKOFF_SECONDS * (2 ** exponent), MAX_BACKOFF_SECONDS)
        bucket.locked_until = time.monotonic() + delay


def record_success(username: str, ip: str) -> None:
    _buckets.pop(_key(username, ip), None)
