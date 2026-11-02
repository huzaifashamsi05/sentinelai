"""
Thin client the Streamlit dashboard uses to talk to the FastAPI backend.
Keeps the token in st.session_state and attaches it as a Bearer header on
every call — the dashboard itself holds no business logic, it only
renders what the backend returns (matches the architecture diagram:
Dashboard -> Backend -> modules).
"""
import os

import requests
import streamlit as st

BACKEND_URL = os.getenv("SENTINELAI_BACKEND_URL", "http://localhost:8000")
API_PREFIX = "/api/v1"


def _headers() -> dict:
    token = st.session_state.get("token")
    return {"Authorization": f"Bearer {token}"} if token else {}


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
            timeout=15,
        )
    except requests.RequestException as e:
        return False, f"Could not reach backend at {BACKEND_URL}: {e}"

    if r.status_code != 200:
        try:
            detail = r.json().get("detail", r.text)
        except Exception:
            detail = r.text
        return False, detail

    body = r.json()
    st.session_state["token"] = body["access_token"]
    st.session_state["role"] = body["role"]
    st.session_state["username"] = username
    return True, "ok"


def register(username: str, password: str, role: str = "analyst") -> tuple[bool, str]:
    try:
        r = requests.post(
            f"{BACKEND_URL}{API_PREFIX}/auth/register",
            json={"username": username, "password": password, "role": role},
            timeout=15,
        )
    except requests.RequestException as e:
        return False, f"Could not reach backend at {BACKEND_URL}: {e}"

    if r.status_code not in (200, 201):
        try:
            detail = r.json().get("detail", r.text)
        except Exception:
            detail = r.text
        return False, detail
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
