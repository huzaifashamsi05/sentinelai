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
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization

AES_KEY_SIZE = 32  # AES-256
IV_SIZE = 16


# ---------------- AES (confidentiality) ----------------
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256 — turns a user password into a proper AES key."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000, dklen=AES_KEY_SIZE)


def aes_encrypt(plaintext: bytes, password: str) -> bytes:
    """Returns salt(16) || iv(16) || ciphertext. Self-contained blob,
    so decrypting only needs the password."""
    salt = os.urandom(16)
    key = derive_key_from_password(password, salt)
    iv = os.urandom(IV_SIZE)

    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return salt + iv + ciphertext


def aes_decrypt(blob: bytes, password: str) -> bytes:
    salt, iv, ciphertext = blob[:16], blob[16:32], blob[32:]
    key = derive_key_from_password(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


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
