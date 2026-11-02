"""
Network Intrusion Detection API. Classifies a single network-connection
record (the 41 NSL-KDD-style features) as normal or one of DoS/Probe/R2L/U2R,
with a SHAP explanation of which features drove the decision.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.models import ModuleName
from app.modules.ml_common import load_bundle, predict_with_explanation
from app.services.alert_service import record_alert

router = APIRouter(prefix="/network-ids", tags=["network-ids"])

MODULE_KEY = "network_ids"


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
