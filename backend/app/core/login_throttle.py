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

---

Second follow-up, after the per-(username, ip) throttle itself started
actually differentiating visitors (see auth.py's _resolve_client_ip): an
attacker who can cheaply get a FRESH identity for every attempt (a new
browser session — the fallback identity when no real forwarded IP is
available — is free to regenerate just by dropping session state) pays
no cost at all from the per-identity bucket, since each attempt lands in
its own brand-new, never-before-seen bucket.

GLOBAL_* below adds a second, identity-INDEPENDENT limiter per username,
counting failures across every identity combined. Deliberately NOT
exponential and capped very low (30s, see GLOBAL_LOCK_SECONDS) — an
unbounded or escalating account-wide lock is exactly the F-03 problem
this module was written to kill in the first place. This one only ever
adds a short, fixed pause, and only after a fairly high failure count
(15 in 15 minutes) that a real user mistyping their password would be
very unlikely to hit, so it meaningfully raises the cost of distributed
guessing without reintroducing a serious denial-of-service lever against
any one account.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

MAX_ATTEMPTS_BEFORE_BACKOFF = 3
BASE_BACKOFF_SECONDS = 5
MAX_BACKOFF_SECONDS = 300  # 5-minute cap — same ceiling the old lockout used

GLOBAL_MAX_FAILURES_PER_USERNAME = 15
GLOBAL_WINDOW_SECONDS = 15 * 60
GLOBAL_LOCK_SECONDS = 30  # short and FIXED on purpose — see module docstring


@dataclass
class _Bucket:
    failures: int = 0
    locked_until: float = 0.0


@dataclass
class _UsernameBucket:
    window_start: float = 0.0
    failures_in_window: int = 0
    locked_until: float = 0.0


_buckets: dict[tuple[str, str], _Bucket] = {}
_username_buckets: dict[str, _UsernameBucket] = {}


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


def seconds_locked_global(username: str) -> int:
    """0 unless this username has hit GLOBAL_MAX_FAILURES_PER_USERNAME
    failures (summed across every identity) within the current window,
    else the whole seconds remaining on that short, fixed pause."""
    bucket = _username_buckets.get(username)
    if not bucket or bucket.locked_until <= time.monotonic():
        return 0
    return int(bucket.locked_until - time.monotonic()) + 1


def record_failure_global(username: str) -> None:
    now = time.monotonic()
    bucket = _username_buckets.setdefault(username, _UsernameBucket())
    if now - bucket.window_start > GLOBAL_WINDOW_SECONDS:
        bucket.window_start = now
        bucket.failures_in_window = 0
    bucket.failures_in_window += 1
    if bucket.failures_in_window >= GLOBAL_MAX_FAILURES_PER_USERNAME:
        bucket.locked_until = now + GLOBAL_LOCK_SECONDS


def record_success_global(username: str) -> None:
    _username_buckets.pop(username, None)
