"""
Starts the SentinelAI FastAPI backend in a background thread inside the
SAME process as this Streamlit app.

Why: so the whole 6-module platform deploys as ONE free Streamlit
Community Cloud app — no second host/account needed for the backend, no
domain purchase, just "push to GitHub, click deploy".

Every page script calls ensure_backend() near the top (before it makes
any api_client call). It is safe to call from every page on every rerun:

- st.cache_resource makes start_backend_once() a process-wide cache, so
  the actual uvicorn.run() only ever happens once per live Python process,
  no matter which page a visitor lands on first.
- It health-checks SENTINELAI_BACKEND_URL before doing anything. If a
  backend is ALREADY reachable there (e.g. this sandbox's separate dev
  uvicorn process, or a real separate deployment), it does nothing and
  just uses that one — so this is also safe to leave in during local
  development with the two processes run separately.
"""
import os
import sys
import threading
import time
from pathlib import Path

import requests
import streamlit as st

FRONTEND_DIR = Path(__file__).resolve().parent
BACKEND_DIR = FRONTEND_DIR.parent / "backend"
BACKEND_URL = os.getenv("SENTINELAI_BACKEND_URL", "http://localhost:8000")


def _is_up() -> bool:
    try:
        return requests.get(f"{BACKEND_URL}/health", timeout=1).status_code == 200
    except requests.RequestException:
        return False


@st.cache_resource(show_spinner=False)
def start_backend_once() -> bool:
    if os.getenv("SENTINELAI_EMBED_BACKEND", "1") != "1":
        return _is_up()

    if _is_up():
        return True  # something (us, earlier; or a separate dev server) already serves it

    # Streamlit Cloud's only place to set a secret is its "Secrets" UI
    # (st.secrets), not real OS env vars — mirror any into os.environ so
    # the embedded FastAPI backend's config.py (which reads via os.getenv)
    # can still pick up e.g. a production SECRET_KEY if one is set there.
    try:
        for key, value in st.secrets.items():
            os.environ.setdefault(key, str(value))
    except Exception:
        pass  # no secrets.toml at all (e.g. local dev) -> nothing to mirror

    if str(BACKEND_DIR) not in sys.path:
        sys.path.insert(0, str(BACKEND_DIR))

    def _run():
        import uvicorn
        from app.main import app as fastapi_app  # noqa: WPS433 (import-on-thread-start, intentional)

        uvicorn.run(fastapi_app, host="127.0.0.1", port=8000, log_level="warning")

    threading.Thread(target=_run, daemon=True, name="sentinelai-embedded-backend").start()

    for _ in range(40):  # up to ~20s for model bundles to load + server to bind
        if _is_up():
            return True
        time.sleep(0.5)
    return False


def ensure_backend():
    """Call at the top of every Streamlit page, right after set_page_config."""
    if not start_backend_once():
        st.error(
            f"Could not reach the SentinelAI backend (expected at {BACKEND_URL}). "
            "If you're running this locally, start it separately with "
            "`uvicorn app.main:app` from the backend/ folder, or check the deployment logs."
        )
        st.stop()
