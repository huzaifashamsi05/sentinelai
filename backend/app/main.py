"""
SentinelAI — unified entry point. Wires together the five module routers
plus auth/alerts under one FastAPI app, which is what the "unified
dashboard" in the architecture talks to.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.security_headers import SecurityHeadersMiddleware
from app.db.database import Base, engine
from app.api import auth, alerts, reports
from app.modules.network_ids import router as network_ids_router
from app.modules.phishing import router as phishing_router
from app.modules.malware import router as malware_router
from app.modules.vuln_scanner import router as vuln_scanner_router
from app.modules.vault import router as vault_router

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="AI-powered Security Operations Platform — Network IDS, "
                 "Phishing Detection, Malware Detection, Vulnerability "
                 "Scanning and Secure Vault, unified under one dashboard.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # demo-scale project; tighten before any real deployment
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)

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
