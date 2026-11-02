"""Phishing & Malicious URL Detector — stub, filled in next (Task 3)."""
from fastapi import APIRouter

router = APIRouter(prefix="/phishing", tags=["phishing"])


@router.get("/status")
def status():
    return {"model_loaded": False, "note": "under construction"}
