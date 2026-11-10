"""Pydantic request/response schemas, shared across all module routers."""
from datetime import datetime
from typing import Optional, Any

from pydantic import BaseModel, Field

from app.db.models import UserRole, Severity, ModuleName


# ---------- Auth ----------
class UserCreate(BaseModel):
    # No `role` field on purpose: self-registration must never let the
    # client choose its own privilege level. register() always creates
    # Analyst accounts; Admin exists only via the startup seed (main.py).
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8)


class UserOut(BaseModel):
    id: int
    username: str
    role: UserRole
    model_config = {"from_attributes": True}


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: UserRole


# ---------- Alerts (shared across all modules) ----------
class AlertCreate(BaseModel):
    module: ModuleName
    title: str
    detail: Optional[str] = None
    severity: Severity
    is_malicious: bool
    confidence: Optional[float] = None
    explanation_json: Optional[str] = None
    source_ref: Optional[str] = None


class AlertOut(AlertCreate):
    id: int
    created_at: datetime
    model_config = {"from_attributes": True}


# ---------- Generic prediction response shape used by every ML module ----------
class ExplanationItem(BaseModel):
    feature: str
    value: Any
    impact: float  # SHAP value — positive pushes toward "malicious"


class PredictionResponse(BaseModel):
    is_malicious: bool
    label: str                     # human-readable class, e.g. "DoS", "Phishing", "Benign"
    confidence: float
    severity: Severity
    explanation: list[ExplanationItem]
    alert_id: Optional[int] = None
