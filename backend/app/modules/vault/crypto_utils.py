"""
Core cryptographic operations for the Secure Vault module.

Uses only established, audited libraries (`cryptography`) — never a
hand-rolled cipher. This matches the handbook's Group B spec: AES
encryption, RSA digital signatures, SHA-256 integrity verification.
"""
import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization

AES_KEY_SIZE = 32  # AES-256
IV_SIZE = 16  # legacy CBC format only
GCM_NONCE_SIZE = 12

# F-05/F-11: the vault's file format now starts with a version byte.
#   0x02 (current) -> salt(16) || nonce(12) || AES-256-GCM ciphertext+tag
#   anything else  -> legacy salt(16) || iv(16) || AES-256-CBC ciphertext
# GCM is an AEAD cipher: it authenticates the ciphertext, so flipping any
# bit anywhere in the blob makes decryption fail outright (InvalidTag)
# instead of silently returning corrupted plaintext — see F-05 below.
# Legacy CBC decryption is kept ONLY so files encrypted before this fix
# still open; new encryptions never use it.
FORMAT_VERSION_GCM = 0x02
PBKDF2_ITERATIONS = 600_000          # OWASP Password Storage Cheat Sheet current guidance
PBKDF2_ITERATIONS_LEGACY = 200_000   # what files encrypted before this fix actually used


# ---------------- AES (confidentiality) ----------------
def derive_key_from_password(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """PBKDF2-HMAC-SHA256 — turns a user password into a proper AES key."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=AES_KEY_SIZE)


def aes_encrypt(plaintext: bytes, password: str) -> bytes:
    """Returns version(1) || salt(16) || nonce(12) || AES-256-GCM ciphertext+tag.
    Self-contained blob, so decrypting only needs the password."""
    salt = os.urandom(16)
    key = derive_key_from_password(password, salt)
    nonce = os.urandom(GCM_NONCE_SIZE)

    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return bytes([FORMAT_VERSION_GCM]) + salt + nonce + ciphertext


def _aes_decrypt_legacy_cbc(blob: bytes, password: str) -> bytes:
    """Decrypts the OLD (pre-fix) format: salt(16) || iv(16) || ciphertext,
    AES-256-CBC, PBKDF2 at the old 200k iterations. Kept only so files
    encrypted before this fix still open — never used for new encryptions.
    Unauthenticated by construction: this is exactly the weakness F-05
    fixes, which is why it isn't how new files get written any more."""
    salt, iv, ciphertext = blob[:16], blob[16:32], blob[32:]
    key = derive_key_from_password(password, salt, iterations=PBKDF2_ITERATIONS_LEGACY)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def aes_decrypt(blob: bytes, password: str) -> bytes:
    if blob and blob[0] == FORMAT_VERSION_GCM:
        salt = blob[1:17]
        nonce = blob[17:17 + GCM_NONCE_SIZE]
        ciphertext = blob[17 + GCM_NONCE_SIZE:]
        key = derive_key_from_password(password, salt)
        # Raises cryptography.exceptions.InvalidTag on a wrong password OR
        # on ANY tampering — the router's existing `except Exception` turns
        # either into the same "Decryption failed" 400, which is exactly
        # what should happen: GCM makes those two cases indistinguishable
        # from the outside, by design.
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    # No recognised version marker -> a file encrypted before this fix.
    return _aes_decrypt_legacy_cbc(blob, password)


# ---------------- SHA-256 (integrity) ----------------
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------- RSA (digital signatures) ----------------
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_private_to_pem(private_key, password: str | None = None) -> bytes:
    enc = (
        serialization.BestAvailableEncryption(password.encode())
        if password
        else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )


def rsa_public_to_pem(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def rsa_sign(private_key, data: bytes) -> bytes:
    return private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def rsa_verify(public_key, data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(data: str) -> bytes:
    return base64.b64decode(data.encode())
