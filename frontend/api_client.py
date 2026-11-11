"""
Thin client the Streamlit dashboard uses to talk to the FastAPI backend.
Keeps the token in st.session_state and attaches it as a Bearer header on
every call — the dashboard itself holds no business logic, it only
renders what the backend returns (matches the architecture diagram:
Dashboard -> Backend -> modules).
"""
import os
import uuid

import requests
import streamlit as st

BACKEND_URL = os.getenv("SENTINELAI_BACKEND_URL", "http://localhost:8000")
API_PREFIX = "/api/v1"


def _headers() -> dict:
    token = st.session_state.get("token")
    return {"Authorization": f"Bearer {token}"} if token else {}


def _visitor_identity_header() -> dict:
    """Best-effort per-visitor identity, sent so the backend's per-
    (username, ip) login throttle (core/login_throttle.py) can actually
    tell different visitors apart — see the X-Client-Identity comment on
    auth.py's _resolve_client_ip() for the full story: on Streamlit
    Community Cloud this frontend process, not the visitor's browser, is
    what calls the backend, so without this every visitor's request
    looks identical (127.0.0.1) to it.

    Preference order:
    1. The visitor's real IP, if Streamlit's own front door attached an
       X-Forwarded-For header to this script run (st.context.headers).
    2. A random ID generated once per browser session and cached in
       st.session_state — not a real IP, but still a distinct bucket per
       browser tab, which is what actually matters: one attacker
       spamming a login shouldn't be able to lock out every other
       visitor sharing this same deployment.

    Never raises — a header this fails to attach just falls back to the
    backend's old pre-fix behavior (one shared bucket), never worse.
    """
    try:
        headers = st.context.headers
        xff = headers.get("X-Forwarded-For") or headers.get("x-forwarded-for")
        if xff:
            real_ip = xff.split(",")[0].strip()
            if real_ip:
                return {"X-Client-Identity": real_ip}
    except Exception:
        pass

    session_id = st.session_state.get("_client_session_id")
    if not session_id:
        session_id = f"sess-{uuid.uuid4().hex}"
        st.session_state["_client_session_id"] = session_id
    return {"X-Client-Identity": session_id}


def _format_error_detail(detail) -> str:
    """FastAPI's `detail` is a plain string for most errors, but a list of
    Pydantic validation-error dicts for a 422 (e.g. a field that's too
    short) — e.g. [{"loc": ["body", "username"], "msg": "String should
    have at least 3 characters", ...}]. Left alone, that list's raw
    Python repr lands on screen verbatim via st.error(); this turns
    either shape into one clean, human-readable line instead."""
    if isinstance(detail, str):
        return detail
    if isinstance(detail, list):
        parts = []
        for item in detail:
            if isinstance(item, dict):
                loc = item.get("loc", [])
                field = str(loc[-1]) if loc else "value"
                msg = item.get("msg", "invalid value")
                parts.append(f"{field}: {msg}")
            else:
                parts.append(str(item))
        return "; ".join(parts) if parts else "The server rejected that request."
    return str(detail)


def api_get(path: str, params: dict | None = None):
    r = requests.get(f"{BACKEND_URL}{API_PREFIX}{path}", headers=_headers(), params=params, timeout=15)
    return r


def api_post(path: str, json_body: dict | None = None, data: dict | None = None, files: dict | None = None):
    r = requests.post(
        f"{BACKEND_URL}{API_PREFIX}{path}", headers=_headers(), json=json_body, data=data, files=files, timeout=30
    )
    return r


def login(username: str, password: str) -> tuple[bool, str]:
    try:
        r = requests.post(
            f"{BACKEND_URL}{API_PREFIX}/auth/login",
            data={"username": username, "password": password},
            headers=_visitor_identity_header(),
            timeout=15,
        )
    except requests.RequestException as e:
        return False, f"Could not reach backend at {BACKEND_URL}: {e}"

    if r.status_code != 200:
        try:
            detail = r.json().get("detail", r.text)
        except Exception:
            detail = r.text
        return False, _format_error_detail(detail)

    body = r.json()
    st.session_state["token"] = body["access_token"]
    st.session_state["role"] = body["role"]
    st.session_state["username"] = username
    return True, "ok"


def register(username: str, password: str) -> tuple[bool, str]:
    try:
        r = requests.post(
            f"{BACKEND_URL}{API_PREFIX}/auth/register",
            # No role field — self-registration is always Analyst, enforced
            # server-side regardless of what a client sends.
            json={"username": username, "password": password},
            timeout=15,
        )
    except requests.RequestException as e:
        return False, f"Could not reach backend at {BACKEND_URL}: {e}"

    if r.status_code not in (200, 201):
        try:
            detail = r.json().get("detail", r.text)
        except Exception:
            detail = r.text
        return False, _format_error_detail(detail)
    return True, "ok"


def logout():
    for key in ("token", "role", "username"):
        st.session_state.pop(key, None)


def is_logged_in() -> bool:
    return bool(st.session_state.get("token"))


def is_admin() -> bool:
    return st.session_state.get("role") == "admin"


def require_login():
    if not is_logged_in():
        st.warning("Please log in from the Home page first.")
        st.stop()
