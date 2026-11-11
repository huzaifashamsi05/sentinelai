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


def seed_default_users() -> None:
    """Idempotently ensure one admin and one analyst account exist.

    Streamlit Community Cloud's container is ephemeral — the SQLite file
    resets on every redeploy/restart — so without this, a freshly-booted
    deployment would have NO way to log in at all. Only inserts a user if
    that username doesn't already exist, so it's a no-op on a persistent
    local dev DB that already has real accounts.

    The admin password is never a value checked into this public repo
    (that used to be "SentinelAI123" — anyone who read the README had
    full admin access to the live deployment). It comes from the
    ADMIN_PASSWORD secret; if that isn't set, a fresh random password is
    generated and printed to the server log ONCE so a local/dev run still
    works, but a stable login across restarts requires setting the secret.
    The analyst account stays a fixed, published demo credential on
    purpose — it's intentionally low-privilege (every admin-only action
    is blocked for it; see F-04 of the audit) so a public demo login for
    non-owners is an acceptable, documented trade rather than a gap.
    """
    db = SessionLocal()
    try:
        admin_password = settings.ADMIN_PASSWORD
        if not admin_password:
            admin_password = secrets.token_urlsafe(16)
            print(
                "=" * 72 + "\n"
                "No ADMIN_PASSWORD secret set — generated a random admin password "
                "for this run only (it will change on the next restart):\n"
                f"    admin / {admin_password}\n"
                "Set ADMIN_PASSWORD (Streamlit Cloud: Settings -> Secrets) for a "
                "password that stays the same across restarts.\n" + "=" * 72
            )

        defaults = [
            ("admin", admin_password, UserRole.admin),
            ("analyst1", settings.ANALYST_PASSWORD, UserRole.analyst),
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
