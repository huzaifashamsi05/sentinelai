"""
SentinelAI — unified entry point. Wires together the five module routers
plus auth/alerts under one FastAPI app, which is what the "unified
dashboard" in the architecture talks to.
"""
import secrets

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.security import hash_password
from app.core.security_headers import SecurityHeadersMiddleware
from app.core.request_monitor import RequestMonitorMiddleware
from app.db.database import Base, SessionLocal, engine
from app.db.models import User, UserRole
from app.api import auth, alerts, reports
from app.modules.network_ids import router as network_ids_router
from app.modules.phishing import router as phishing_router
from app.modules.malware import router as malware_router
from app.modules.vuln_scanner import router as vuln_scanner_router
from app.modules.vault import router as vault_router

Base.metadata.create_all(bind=engine)


def _seed_password(username: str, secret_env_name: str, env_value: str | None) -> str:
    """Returns env_value if the secret is set; otherwise generates a fresh
    random password for this run only and prints it to the server log once.

    Used for BOTH seeded accounts (admin and analyst) so neither one's
    login is ever a fixed value checked into this public repo. Analyst
    used to keep a published fallback ("AnalystPass123") on the reasoning
    that the account is low-privilege — true, but it's still a secret
    living in public source, and a follow-up to the November audit called
    that out directly. This closes it the same way F-02 closed the old
    ADMIN_PASSWORD fallback, even though self-registration already lets
    anyone create their own Analyst-role account regardless — it's
    secret-hygiene/consistency, not the account's only way in.
    """
    if env_value:
        return env_value
    password = secrets.token_urlsafe(16)
    print(
        "=" * 72 + "\n"
        f"No {secret_env_name} secret set — generated a random {username} password "
        "for this run only (it will change on the next restart):\n"
        f"    {username} / {password}\n"
        f"Set {secret_env_name} (Streamlit Cloud: Settings -> Secrets) for a "
        "password that stays the same across restarts.\n" + "=" * 72
    )
    return password


def seed_default_users() -> None:
    """Idempotently ensure one admin and one analyst account exist.

    Streamlit Community Cloud's container is ephemeral — the SQLite file
    resets on every redeploy/restart — so without this, a freshly-booted
    deployment would have NO way to log in at all. Only inserts a user if
    that username doesn't already exist, so it's a no-op on a persistent
    local dev DB that already has real accounts.

    Neither seeded password is ever a value checked into this public repo
    (admin used to be "SentinelAI123", analyst "AnalystPass123" — anyone
    who read the README had a working login to the live deployment).
    Each comes from its own secret (ADMIN_PASSWORD / ANALYST_PASSWORD); if
    unset, a fresh random password is generated and printed to the server
    log ONCE so a local/dev run still works, but a stable login across
    restarts requires setting the secret. See _seed_password() above.
    """
    db = SessionLocal()
    try:
        admin_password = _seed_password("admin", "ADMIN_PASSWORD", settings.ADMIN_PASSWORD)
        analyst_password = _seed_password("analyst1", "ANALYST_PASSWORD", settings.ANALYST_PASSWORD)

        defaults = [
            ("admin", admin_password, UserRole.admin),
            ("analyst1", analyst_password, UserRole.analyst),
        ]
        for username, password, role in defaults:
            existing = db.query(User).filter(User.username == username).first()
            if existing:
                continue
            db.add(User(username=username, hashed_password=hash_password(password), role=role))
        db.commit()
    finally:
        db.close()


seed_default_users()

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="AI-powered Security Operations Platform — Network IDS, "
                 "Phishing Detection, Malware Detection, Vulnerability "
                 "Scanning and Secure Vault, unified under one dashboard.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestMonitorMiddleware)

app.include_router(auth.router, prefix=settings.API_V1_PREFIX)
app.include_router(alerts.router, prefix=settings.API_V1_PREFIX)
app.include_router(reports.router, prefix=settings.API_V1_PREFIX)
app.include_router(network_ids_router.router, prefix=settings.API_V1_PREFIX)
app.include_router(phishing_router.router, prefix=settings.API_V1_PREFIX)
app.include_router(malware_router.router, prefix=settings.API_V1_PREFIX)
app.include_router(vuln_scanner_router.router, prefix=settings.API_V1_PREFIX)
app.include_router(vault_router.router, prefix=settings.API_V1_PREFIX)


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "project": settings.PROJECT_NAME}
