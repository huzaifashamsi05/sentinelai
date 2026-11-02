"""
Shared helper every module's router calls to write a detection result into
the common `alerts` table. Keeps the "write an alert" logic in one place
instead of duplicated five times.
"""
import json

from sqlalchemy.orm import Session

from app.db.models import Alert, ModuleName, Severity


def severity_from_confidence(confidence: float) -> Severity:
    if confidence >= 0.85:
        return Severity.high
    if confidence >= 0.6:
        return Severity.medium
    return Severity.low


def record_alert(
    db: Session,
    module: ModuleName,
    title: str,
    is_malicious: bool,
    confidence: float,
    explanation: list[dict],
    detail: str = "",
    source_ref: str = "",
) -> Alert:
    alert = Alert(
        module=module,
        title=title,
        detail=detail,
        severity=severity_from_confidence(confidence) if is_malicious else Severity.low,
        is_malicious=is_malicious,
        confidence=confidence,
        explanation_json=json.dumps(explanation),
        source_ref=source_ref,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert
