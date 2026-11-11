"""
Central configuration for SentinelAI backend.
Reads from environment variables (.env) with sane defaults for local/demo use.
"""
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent  # project root


def _require_secret_key() -> str:
    """SECRET_KEY must come from the environment — never a value checked
    into this public repository. The project used to fall back to the
    literal string "CHANGE_ME_IN_PRODUCTION_SENTINELAI_DEV_KEY" when the
    env var was unset, which meant anyone who read this file (i.e.
    everyone, since the repo is public) could forge a valid admin JWT
    offline with four lines of Python — no access to the server at all
    needed. Refusing to start without a real key closes that off
    entirely instead of just hiding the default better.

    Set SECRET_KEY in Streamlit Cloud's "Secrets" panel (or your shell
    env for local dev) to a long random value, e.g.:
        python3 -c "import secrets; print(secrets.token_urlsafe(64))"
    """
    key = os.getenv("SECRET_KEY")
    if not key:
        sys.exit(
            "FATAL: SECRET_KEY environment variable is not set.\n"
            "SentinelAI refuses to start without one — a JWT signing key must "
            "never fall back to a default value committed in a public repo.\n"
            "Set it in Streamlit Cloud's Secrets panel, or in your shell for "
            "local dev, e.g.:\n"
            '  export SECRET_KEY="$(python3 -c \'import secrets; print(secrets.token_urlsafe(64))\')"'
        )
    return key


class Settings:
    PROJECT_NAME: str = "SentinelAI"
    API_V1_PREFIX: str = "/api/v1"

    # Database (SQLite by default — zero setup, good enough for a demo-scale project)
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/sentinelai.db")

    # Auth
    SECRET_KEY: str = _require_secret_key()
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8  # 8 hours

    # Admin account seeded at startup (see main.py::seed_default_users).
    # No hardcoded fallback password: if ADMIN_PASSWORD isn't set, a random
    # one is generated fresh and printed to the server log once, rather than
    # the same published password ("SentinelAI123") living in this public
    # repo forever. Set ADMIN_PASSWORD in Streamlit Cloud's Secrets panel
    # for a stable login across reboots.
    ADMIN_PASSWORD: str | None = os.getenv("ADMIN_PASSWORD")
    ANALYST_PASSWORD: str = os.getenv("ANALYST_PASSWORD", "AnalystPass123")

    # CORS — restricted to the deployed frontend origin(s) by default.
    # Comma-separated via ALLOWED_ORIGINS if this is ever split across hosts.
    ALLOWED_ORIGINS: list[str] = [
        o.strip()
        for o in os.getenv(
            "ALLOWED_ORIGINS",
            "https://sentinelai-huzaifa.streamlit.app,"
            "http://localhost:8501,http://127.0.0.1:8501",
        ).split(",")
        if o.strip()
    ]

    # Paths
    MODELS_DIR: Path = BASE_DIR / "models"
    DATA_DIR: Path = BASE_DIR / "data"
    REPORTS_DIR: Path = BASE_DIR / "reports"

    # Vuln scanner — safety allowlist.
    # The scanner will ONLY run against hosts in this list (or ones added at
    # runtime by an authenticated Admin who explicitly confirms ownership/authorization).
    # Never used to scan arbitrary third-party/public sites. See docs/ETHICS.md.
    DEFAULT_AUTHORIZED_SCAN_TARGETS: list[str] = [
        "localhost",
        "127.0.0.1",
    ]


settings = Settings()
