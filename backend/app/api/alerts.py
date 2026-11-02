"""
The shared Alert feed every module writes into, and the dashboard reads from.
This is what makes the five modules act as ONE platform instead of five
disconnected tools.
"""
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.models import Alert, ModuleName, Severity
from app.schemas import AlertOut

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
def list_alerts(
    module: Optional[ModuleName] = None,
    severity: Optional[Severity] = None,
    limit: int = Query(default=100, le=1000),
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
):
    q = db.query(Alert)
    if module:
        q = q.filter(Alert.module == module)
    if severity:
        q = q.filter(Alert.severity == severity)
    return q.order_by(Alert.created_at.desc()).limit(limit).all()


@router.get("/stats")
def alert_stats(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    """Counts used by the dashboard's summary tiles."""
    from sqlalchemy import func

    by_module = dict(
        db.query(Alert.module, func.count(Alert.id)).group_by(Alert.module).all()
    )
    by_severity = dict(
        db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    )
    total = db.query(func.count(Alert.id)).scalar()
    malicious = db.query(func.count(Alert.id)).filter(Alert.is_malicious.is_(True)).scalar()
    return {
        "total_events": total,
        "malicious_events": malicious,
        "by_module": {k.value if hasattr(k, "value") else k: v for k, v in by_module.items()},
        "by_severity": {k.value if hasattr(k, "value") else k: v for k, v in by_severity.items()},
    }
