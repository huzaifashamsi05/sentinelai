"""
Secure Vault API: AES file encryption/decryption, RSA digital signatures,
SHA-256 integrity verification, and audit logging. Matches handbook
Group B's required deliverables.
"""
from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
import io

from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.models import AuditLog, ModuleName, Severity
from app.services.alert_service import record_alert
from app.modules.vault import crypto_utils as cu

router = APIRouter(prefix="/vault", tags=["vault"])


def _log(db: Session, username: str, action: str, detail: str = ""):
    db.add(AuditLog(username=username, action=action, detail=detail))
    db.commit()


@router.post("/encrypt")
async def encrypt_file(
    file: UploadFile = File(...),
    password: str = Form(..., min_length=8),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    plaintext = await file.read()
    blob = cu.aes_encrypt(plaintext, password)
    integrity_hash = cu.sha256_hex(plaintext)

    _log(db, user.username, "file_encrypted", f"file={file.filename} sha256={integrity_hash}")
    record_alert(
        db,
        module=ModuleName.vault,
        title=f"File encrypted: {file.filename}",
        is_malicious=False,
        confidence=1.0,
        explanation=[{"feature": "sha256_at_encryption_time", "value": integrity_hash, "impact": 0}],
        detail="AES-256-GCM, key derived via PBKDF2-HMAC-SHA256 (600k iterations)",
        source_ref=file.filename,
    )

    return StreamingResponse(
        io.BytesIO(blob),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{file.filename}.enc"',
            "X-Original-SHA256": integrity_hash,
        },
    )


@router.post("/decrypt")
async def decrypt_file(
    file: UploadFile = File(...),
    password: str = Form(...),
    expected_sha256: str | None = Form(default=None),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    blob = await file.read()
    try:
        plaintext = cu.aes_decrypt(blob, password)
    except Exception:
        _log(db, user.username, "file_decrypt_failed", f"file={file.filename}")
        raise HTTPException(status_code=400, detail="Decryption failed — wrong password or corrupted file")

    actual_hash = cu.sha256_hex(plaintext)
    tampered = expected_sha256 is not None and actual_hash != expected_sha256

    _log(db, user.username, "file_decrypted", f"file={file.filename} sha256={actual_hash} tampered={tampered}")
    record_alert(
        db,
        module=ModuleName.vault,
        title=f"File integrity check: {file.filename}" if expected_sha256 else f"File decrypted: {file.filename}",
        is_malicious=tampered,
        confidence=1.0,
        explanation=[
            {"feature": "sha256_now", "value": actual_hash, "impact": 0},
            {"feature": "sha256_expected", "value": expected_sha256 or "n/a", "impact": 1.0 if tampered else 0},
        ],
        detail="Integrity check FAILED — file was modified after encryption" if tampered else "Integrity verified",
        source_ref=file.filename,
    )

    if tampered:
        raise HTTPException(status_code=409, detail="Integrity check failed: file was tampered with after encryption")

    return StreamingResponse(
        io.BytesIO(plaintext),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{file.filename}"', "X-SHA256": actual_hash},
    )


@router.post("/hash")
async def hash_file(file: UploadFile = File(...), user=Depends(get_current_user)):
    """Quick SHA-256 of an uploaded file — used for the file-integrity-checker demo."""
    data = await file.read()
    return {"filename": file.filename, "sha256": cu.sha256_hex(data), "size_bytes": len(data)}


@router.post("/keypair/generate")
def generate_keypair(password: str = Form(..., min_length=8), user=Depends(get_current_user)):
    """Generates an RSA-2048 keypair for digital signatures. Private key is
    returned once — the server does not store it.

    F-06: the passphrase used to be optional, so an unencrypted private key
    could come straight back in the HTTP response body — meaning the
    server (and anything that can see its traffic or logs: a reverse
    proxy, access logs, browser history) saw every user's raw signing key.
    Requiring it means the response always carries an encrypted PEM
    (BestAvailableEncryption) instead. True client-side generation, where
    the server never sees the private key at all, would be the ideal fix
    but needs a WebCrypto-based frontend; this is the practical mitigation
    within the current Streamlit-form architecture.
    """
    private_key, public_key = cu.generate_rsa_keypair()
    return {
        "private_key_pem": cu.rsa_private_to_pem(private_key, password).decode(),
        "public_key_pem": cu.rsa_public_to_pem(public_key).decode(),
        "warning": "Save the private key now — it is not stored server-side.",
    }


@router.post("/sign")
async def sign_file(
    file: UploadFile = File(...),
    private_key_pem: str = Form(...),
    key_password: str | None = Form(default=None),
    user=Depends(get_current_user),
):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    data = await file.read()
    try:
        private_key = load_pem_private_key(
            private_key_pem.encode(), password=key_password.encode() if key_password else None
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid private key or password")

    signature = cu.rsa_sign(private_key, data)
    return {"filename": file.filename, "signature_b64": cu.b64(signature), "sha256": cu.sha256_hex(data)}


@router.post("/verify")
async def verify_signature(
    file: UploadFile = File(...),
    signature_b64: str = Form(...),
    public_key_pem: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    data = await file.read()
    try:
        public_key = load_pem_public_key(public_key_pem.encode())
        signature = cu.unb64(signature_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid public key or signature encoding")

    valid = cu.rsa_verify(public_key, data, signature)

    record_alert(
        db,
        module=ModuleName.vault,
        title=f"Signature {'VALID' if valid else 'INVALID'}: {file.filename}",
        is_malicious=not valid,
        confidence=1.0,
        explanation=[{"feature": "rsa_pss_sha256_signature_valid", "value": valid, "impact": 0 if valid else 1.0}],
        source_ref=file.filename,
    )

    return {"filename": file.filename, "signature_valid": valid}
