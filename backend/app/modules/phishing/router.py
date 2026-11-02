"""
Phishing & Malicious URL Detector API. Takes a raw URL, computes the same
lexical features used in training, classifies it, and explains the result
via SHAP.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.models import ModuleName
from app.modules.ml_common import load_bundle, predict_with_explanation
from app.modules.phishing.features import extract_features
from app.services.alert_service import record_alert

router = APIRouter(prefix="/phishing", tags=["phishing"])

MODULE_KEY = "phishing"


class URLCheckRequest(BaseModel):
    url: str = Field(min_length=3, examples=["http://paypal-secure-login.verify-account.ru/signin"])


@router.get("/status")
def status():
    bundle = load_bundle(MODULE_KEY)
    return {"model_loaded": bundle is not None}


@router.get("/sample-requests")
def sample_requests():
    return {
        "benign_example": {"url": "https://www.github.com/anthropics/claude-code"},
        "phishing_example": {"url": "http://paypal-secure-login.verify-account-update.ru/signin.php?id=12345"},
    }


@router.post("/check")
def check_url(payload: URLCheckRequest, db: Session = Depends(get_db), user=Depends(get_current_user)):
    bundle = load_bundle(MODULE_KEY)
    if bundle is None:
        raise HTTPException(status_code=503, detail="Model not trained yet — run ml/phishing/train.py")

    feature_row = extract_features(payload.url)
    result = predict_with_explanation(bundle, feature_row)
    is_malicious = result["label"] == "malicious"

    alert = record_alert(
        db,
        module=ModuleName.phishing,
        title=f"URL classified as {'PHISHING/MALICIOUS' if is_malicious else 'benign'}",
        is_malicious=is_malicious,
        confidence=result["confidence"],
        explanation=result["explanation"],
        detail=payload.url,
        source_ref=payload.url,
    )

    return {
        "url": payload.url,
        "is_malicious": is_malicious,
        "label": result["label"],
        "confidence": result["confidence"],
        "explanation": result["explanation"],
        "alert_id": alert.id,
    }
