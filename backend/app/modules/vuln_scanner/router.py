"""
Vulnerability Scanner API.

SAFETY GATE: this scanner will only touch hosts that are either
localhost/127.0.0.1, or explicitly present in `authorized_scan_targets`
(added by an Admin who has confirmed ownership/authorization). Every other
host is refused with a 403 before any request is sent. See docs/ETHICS.md.
"""
from urllib.parse import urlparse, urljoin

import requests
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.core import security_headers
from app.db.database import get_db
from app.db.models import AuthorizedScanTarget, ModuleName
from app.modules.vuln_scanner.scan_rules import run_all_checks
from app.services.alert_service import record_alert

router = APIRouter(prefix="/vuln-scanner", tags=["vuln-scanner"])


class AddTargetRequest(BaseModel):
    host: str = Field(description="Hostname only, e.g. 'localhost:3000' or 'my-own-site.test'")
    note: str
    confirmed_authorized: bool = Field(
        description="Must be true — confirms you own this host or have written authorization to test it."
    )


class ScanRequest(BaseModel):
    url: str = Field(description="Full URL including scheme, e.g. http://localhost:3000")


class SecurityHeadersToggle(BaseModel):
    enabled: bool


def _normalize_host(raw: str) -> str:
    """Accept either a bare host ('example.com', 'localhost:3000') or a full
    URL ('https://example.com/') and return just 'host[:port]', so a target
    typed either way is stored/matched consistently. Without this, a target
    added as a full URL (with scheme + trailing slash) would silently never
    match the bare host the scanner checks against at scan time."""
    raw = raw.strip()
    if "://" in raw:
        raw = urlparse(raw).netloc
    return raw.rstrip("/")


def _is_authorized(db: Session, host: str) -> bool:
    from app.core.config import settings

    host = _normalize_host(host)
    hostname = host.split(":")[0]
    if hostname in settings.DEFAULT_AUTHORIZED_SCAN_TARGETS:
        return True
    return db.query(AuthorizedScanTarget).filter(AuthorizedScanTarget.host == host).first() is not None


MAX_SCAN_REDIRECTS = 5


def _authorized_get(db: Session, url: str, timeout: int = 10) -> requests.Response:
    """GET a URL, following redirects by hand and re-checking the
    authorized-targets gate at every hop.

    requests' own allow_redirects=True follows a redirect chain silently —
    an authorized host could 302 somewhere nobody approved, and the scanner
    would happily fetch it. That defeats the whole point of the
    authorized-targets-only safety gate, so every hop (including the
    first) is re-validated before it is fetched.
    """
    current_url = url
    for _ in range(MAX_SCAN_REDIRECTS + 1):
        parsed = urlparse(current_url)
        if not _is_authorized(db, parsed.netloc):
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Redirected to '{parsed.netloc}', which is not an authorized scan target. "
                    "This scanner re-checks authorization at every redirect hop."
                ),
            )
        resp = requests.get(current_url, timeout=timeout, allow_redirects=False)
        if resp.is_redirect and resp.headers.get("Location"):
            current_url = urljoin(current_url, resp.headers["Location"])
            continue
        return resp
    raise HTTPException(status_code=502, detail="Too many redirects while scanning target.")


@router.get("/targets")
def list_targets(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    from app.core.config import settings

    custom = db.query(AuthorizedScanTarget).all()
    return {
        "default_authorized": settings.DEFAULT_AUTHORIZED_SCAN_TARGETS,
        "custom_authorized": [{"host": t.host, "note": t.note, "added_by": t.added_by} for t in custom],
    }


@router.post("/targets", status_code=201)
def add_target(payload: AddTargetRequest, db: Session = Depends(get_db), user=Depends(require_admin)):
    if not payload.confirmed_authorized:
        raise HTTPException(
            status_code=400,
            detail="confirmed_authorized must be true — this scanner only runs against hosts you own or are authorized to test.",
        )
    host = _normalize_host(payload.host)
    existing = db.query(AuthorizedScanTarget).filter(AuthorizedScanTarget.host == host).first()
    if existing:
        return {"message": "already authorized", "host": host}
    target = AuthorizedScanTarget(host=host, added_by=user.username, note=payload.note)
    db.add(target)
    db.commit()
    return {"message": "target authorized", "host": host}


@router.get("/security-headers")
def get_security_headers_state(_user=Depends(get_current_user)):
    """Lets the dashboard show whether the backend's own security headers
    are currently on — used for the module's live before/after demo."""
    return {"enabled": security_headers.HEADERS_ENABLED}


@router.post("/security-headers")
def set_security_headers_state(payload: SecurityHeadersToggle, _user=Depends(require_admin)):
    """Admin-only: turn the backend's own security-headers middleware on/off,
    to reproduce the 'before' state and then demonstrate the fix live —
    always against our own server (localhost), never a third-party site."""
    security_headers.HEADERS_ENABLED = payload.enabled
    return {"enabled": security_headers.HEADERS_ENABLED}


@router.post("/scan")
def scan(payload: ScanRequest, db: Session = Depends(get_db), user=Depends(get_current_user)):
    parsed = urlparse(payload.url)
    if not parsed.scheme or not parsed.netloc:
        raise HTTPException(status_code=400, detail="url must include scheme and host, e.g. http://localhost:3000")

    if not _is_authorized(db, parsed.netloc):
        raise HTTPException(
            status_code=403,
            detail=(
                f"'{parsed.netloc}' is not an authorized scan target. "
                "This scanner only runs against localhost/127.0.0.1 or hosts an Admin has "
                "explicitly authorized via POST /vuln-scanner/targets. "
                "Scanning third-party sites without authorization is not permitted."
            ),
        )

    try:
        resp = _authorized_get(db, payload.url, timeout=10)
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Could not reach target: {e}")

    findings = run_all_checks(payload.url, resp)

    risk_rank = {"High": 3, "Medium": 2, "Low": 1}
    worst = max((f.risk for f in findings), key=lambda r: risk_rank.get(r, 0), default="Low")

    alert = record_alert(
        db,
        module=ModuleName.vuln_scanner,
        title=f"Scan of {parsed.netloc}: {len(findings)} finding(s)",
        is_malicious=len(findings) > 0,
        confidence=1.0,
        explanation=[{"feature": f.check, "value": f.detail, "impact": risk_rank.get(f.risk, 0) / 3} for f in findings],
        detail=f"Worst risk level: {worst}" if findings else "No issues found by current checks",
        source_ref=payload.url,
    )

    return {
        "url": payload.url,
        "status_code": resp.status_code,
        "findings": [f.__dict__ for f in findings],
        "finding_count": len(findings),
        "worst_risk": worst if findings else "None",
        "alert_id": alert.id,
    }
