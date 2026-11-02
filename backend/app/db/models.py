"""
Shared database models.

`Alert` is the single table every detection module (Network IDS, Phishing,
Malware, Vulnerability Scanner) writes into. The unified dashboard reads
from this ONE table rather than querying five different systems — this is
what makes the platform "unified" rather than five unrelated tools.
"""
import enum
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, DateTime, Text, Enum, Boolean, Float
from sqlalchemy.orm import relationship

from app.db.database import Base


class UserRole(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"


class Severity(str, enum.Enum):
    low = "Low"
    medium = "Medium"
    high = "High"


class ModuleName(str, enum.Enum):
    network_ids = "Network IDS"
    phishing = "Phishing Detector"
    malware = "Malware Scanner"
    vuln_scanner = "Vulnerability Scanner"
    vault = "Secure Vault"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.analyst)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Alert(Base):
    """One row per detection event, from any module. This is the backbone
    of the unified dashboard: every module writes here, the dashboard only
    reads from here."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    module = Column(Enum(ModuleName), nullable=False, index=True)
    title = Column(String(255), nullable=False)          # e.g. "Port scan detected from 10.0.0.5"
    detail = Column(Text, nullable=True)                 # free-text summary
    severity = Column(Enum(Severity), nullable=False, index=True)
    is_malicious = Column(Boolean, nullable=False)        # the model's prediction
    confidence = Column(Float, nullable=True)              # model probability/confidence 0-1
    explanation_json = Column(Text, nullable=True)         # SHAP top-features, serialized JSON
    source_ref = Column(String(255), nullable=True)        # e.g. URL, file hash, src IP — whatever triggered it
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class AuthorizedScanTarget(Base):
    """Hosts an Admin has explicitly confirmed are owned by / authorized for
    this project to scan. The Vulnerability Scanner module refuses to scan
    anything not in this table (plus localhost/127.0.0.1 by default).
    This is the safety gate described in docs/ETHICS.md — it exists so the
    scanner can never be pointed at an arbitrary public site."""
    __tablename__ = "authorized_scan_targets"

    id = Column(Integer, primary_key=True, index=True)
    host = Column(String(255), unique=True, nullable=False)
    added_by = Column(String(64), nullable=False)
    note = Column(String(255), nullable=True)  # e.g. "local DVWA instance", "my own portfolio site"
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AuditLog(Base):
    """Login events, integrity checks, admin actions — required by the
    handbook's 'accountability' control and used for the Secure Vault
    module's audit trail."""
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), nullable=True)
    action = Column(String(128), nullable=False)   # e.g. "login_success", "login_failed", "file_encrypted"
    detail = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
