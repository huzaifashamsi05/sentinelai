"""
Network Intrusion Detection API. Classifies a single network-connection
record (the 41 NSL-KDD-style features) as normal or one of DoS/Probe/R2L/U2R,
with a SHAP explanation of which features drove the decision.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.core import request_monitor
from app.db.database import get_db
from app.db.models import ModuleName
from app.modules.ml_common import load_bundle, predict_with_explanation
from app.modules.network_ids.live_monitor import classify_entry
from app.services.alert_service import record_alert

router = APIRouter(prefix="/network-ids", tags=["network-ids"])

MODULE_KEY = "network_ids"


class LiveMonitorToggle(BaseModel):
    enabled: bool


class ConnectionRecord(BaseModel):
    """One network connection, in NSL-KDD's standard 41-feature schema.
    `protocol_type`/`service`/`flag` are raw strings (e.g. 'tcp', 'http',
    'SF') — the router encodes them using the same categories seen in
    training."""
    duration: float = 0
    protocol_type: str = "tcp"
    service: str = "http"
    flag: str = "SF"
    src_bytes: float = 0
    dst_bytes: float = 0
    land: int = 0
    wrong_fragment: int = 0
    urgent: int = 0
    hot: int = 0
    num_failed_logins: int = 0
    logged_in: int = 0
    num_compromised: int = 0
    root_shell: int = 0
    su_attempted: int = 0
    num_root: int = 0
    num_file_creations: int = 0
    num_shells: int = 0
    num_access_files: int = 0
    num_outbound_cmds: int = 0
    is_host_login: int = 0
    is_guest_login: int = 0
    count: int = 0
    srv_count: int = 0
    serror_rate: float = 0
    srv_serror_rate: float = 0
    rerror_rate: float = 0
    srv_rerror_rate: float = 0
    same_srv_rate: float = 0
    diff_srv_rate: float = 0
    srv_diff_host_rate: float = 0
    dst_host_count: int = 0
    dst_host_srv_count: int = 0
    dst_host_same_srv_rate: float = 0
    dst_host_diff_srv_rate: float = 0
    dst_host_same_src_port_rate: float = 0
    dst_host_srv_diff_host_rate: float = 0
    dst_host_serror_rate: float = 0
    dst_host_srv_serror_rate: float = 0
    dst_host_rerror_rate: float = 0
    dst_host_srv_rerror_rate: float = 0


@router.get("/status")
def status():
    bundle = load_bundle(MODULE_KEY)
    return {"model_loaded": bundle is not None}


@router.get("/sample-requests")
def sample_requests():
    """A couple of ready-to-use example payloads — one normal-looking,
    one attack-looking — handy for the live demo and for the dashboard's
    'simulate traffic' button."""
    return {
        "normal_example": {
            "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF",
            "src_bytes": 215, "dst_bytes": 45076, "logged_in": 1, "count": 1,
            "srv_count": 1, "same_srv_rate": 1.0, "dst_host_count": 30, "dst_host_srv_count": 255,
            "dst_host_same_srv_rate": 1.0, "dst_host_srv_diff_host_rate": 0.0,
        },
        "dos_attack_example": {
            "duration": 0, "protocol_type": "tcp", "service": "private", "flag": "S0",
            "src_bytes": 0, "dst_bytes": 0, "count": 123, "srv_count": 6,
            "serror_rate": 1.0, "srv_serror_rate": 1.0, "same_srv_rate": 0.05,
            "diff_srv_rate": 0.07, "dst_host_count": 255, "dst_host_srv_count": 26,
            "dst_host_same_srv_rate": 0.1, "dst_host_serror_rate": 1.0, "dst_host_srv_serror_rate": 1.0,
        },
    }


@router.post("/predict")
def predict(record: ConnectionRecord, db: Session = Depends(get_db), user=Depends(get_current_user)):
    bundle = load_bundle(MODULE_KEY)
    if bundle is None:
        raise HTTPException(status_code=503, detail="Model not trained yet — run ml/network_ids/train.py")

    import joblib
    from pathlib import Path
    from app.core.config import settings

    raw_bundle = joblib.load(Path(settings.MODELS_DIR) / f"{MODULE_KEY}.joblib")
    encoders = raw_bundle["categorical_encoders"]

    def encode(field: str, value: str) -> int:
        classes = encoders[field]
        return classes.index(value) if value in classes else 0

    feature_row = record.model_dump()
    feature_row["protocol_type"] = encode("protocol_type", record.protocol_type)
    feature_row["service"] = encode("service", record.service)
    feature_row["flag"] = encode("flag", record.flag)

    result = predict_with_explanation(bundle, feature_row)
    is_malicious = result["label"] != "normal"

    alert = record_alert(
        db,
        module=ModuleName.network_ids,
        title=f"Traffic classified as {result['label'].upper()}"
        + (f" ({record.src_bytes:.0f}B -> {record.dst_bytes:.0f}B, {record.service})" if is_malicious else ""),
        is_malicious=is_malicious,
        confidence=result["confidence"],
        explanation=result["explanation"],
        detail=f"protocol={record.protocol_type} service={record.service} flag={record.flag}",
        source_ref=f"{record.protocol_type}/{record.service}",
    )

    return {
        "is_malicious": is_malicious,
        "label": result["label"],
        "confidence": result["confidence"],
        "explanation": result["explanation"],
        "alert_id": alert.id,
    }


@router.get("/live-feed")
def live_feed(limit: int = 20, db: Session = Depends(get_db), user=Depends(get_current_user)):
    """Real HTTP requests that have reached this backend, newest first,
    each classified by the same model as the manual form above. See
    live_monitor.py for exactly how an HTTP request becomes an NSL-KDD-style
    feature row, and what's real vs. approximated in that translation.

    Each entry is only ever run through the model ONCE — the result is
    cached on the entry itself (request_monitor.RequestEntry.classification)
    the first time it's served, so polling this endpoint repeatedly doesn't
    repeatedly re-run inference on requests that already have a result."""
    limit = max(1, min(limit, 100))
    entries = request_monitor.all_entries()  # oldest-first
    newest_first = list(reversed(entries))[:limit]

    items = []
    for entry in newest_first:
        if entry.classification is None:
            result = classify_entry(entry, entries)
            entry.classification = result
            if result is not None and result["label"] != "normal":
                record_alert(
                    db,
                    module=ModuleName.network_ids,
                    title=f"Live traffic from {entry.client_ip} classified as {result['label'].upper()}"
                          f" ({entry.method} {entry.path} -> {entry.status_code})",
                    is_malicious=True,
                    confidence=result["confidence"],
                    explanation=result["explanation"],
                    detail="Flagged by the Live Request Monitor (HTTP-layer, not packet-layer).",
                    source_ref=f"{entry.client_ip} {entry.method} {entry.path}",
                )

        c = entry.classification
        items.append({
            "id": entry.id,
            "ts": entry.ts,
            "client_ip": entry.client_ip,
            "method": entry.method,
            "path": entry.path,
            "status_code": entry.status_code,
            "duration_ms": round(entry.duration_ms, 1),
            "src_bytes": entry.req_bytes,
            "dst_bytes": entry.resp_bytes,
            "label": c["label"] if c else None,
            "confidence": c["confidence"] if c else None,
            "feature_row": c["feature_row"] if c else None,
            "explanation": c["explanation"] if c else None,
        })

    return {
        "monitor_enabled": request_monitor.MONITOR_ENABLED,
        "total_logged": len(entries),
        "items": items,
    }


@router.post("/live-feed/toggle")
def toggle_live_feed(payload: LiveMonitorToggle, _user=Depends(require_admin)):
    request_monitor.set_enabled(payload.enabled)
    return {"enabled": request_monitor.MONITOR_ENABLED}


@router.post("/live-feed/clear")
def clear_live_feed(_user=Depends(require_admin)):
    request_monitor.clear()
    return {"message": "cleared"}
