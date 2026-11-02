"""
Central configuration for SentinelAI backend.
Reads from environment variables (.env) with sane defaults for local/demo use.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent  # project root

class Settings:
    PROJECT_NAME: str = "SentinelAI"
    API_V1_PREFIX: str = "/api/v1"

    # Database (SQLite by default — zero setup, good enough for a demo-scale project)
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/sentinelai.db")

    # Auth
    SECRET_KEY: str = os.getenv("SECRET_KEY", "CHANGE_ME_IN_PRODUCTION_SENTINELAI_DEV_KEY")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8  # 8 hours

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
