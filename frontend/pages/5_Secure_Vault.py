"""Secure Vault page: AES encryption, RSA signatures, SHA-256 integrity."""
import streamlit as st
import requests

from _backend_bootstrap import ensure_backend
from api_client import require_login, BACKEND_URL, _headers

st.set_page_config(page_title="Secure Vault — SentinelAI", page_icon="🔐", layout="wide")
ensure_backend()
require_login()

st.title("🔐 Secure Vault")
st.caption("AES-256 file encryption, RSA-2048 digital signatures, SHA-256 integrity verification, audit logging.")

tab_encrypt, tab_decrypt, tab_hash, tab_keys, tab_sign, tab_verify = st.tabs(
    ["Encrypt", "Decrypt / Verify Integrity", "Hash a File", "Generate Keypair", "Sign", "Verify Signature"]
)

with tab_encrypt:
    st.subheader("Encrypt a file (AES-256)")
    file = st.file_uploader("File to encrypt", key="enc_file")
    password = st.text_input("Encryption password (min 8 chars)", type="password", key="enc_pw")
    if st.button("🔒 Encrypt", type="primary") and file and password:
        resp = requests.post(
            f"{BACKEND_URL}/api/v1/vault/encrypt", headers=_headers(),
            files={"file": (file.name, file.getvalue())}, data={"password": password}, timeout=30,
        )
        if resp.status_code == 200:
            original_hash = resp.headers.get("X-Original-SHA256", "")
            st.success("File encrypted.")
            st.code(f"SHA-256 of original file (save this to verify integrity later):\n{original_hash}")
            st.download_button("⬇️ Download encrypted file", data=resp.content, file_name=f"{file.name}.enc")
        else:
            st.error(resp.text)

with tab_decrypt:
    st.subheader("Decrypt a file + verify it wasn't tampered with")
    file = st.file_uploader("Encrypted file (.enc)", key="dec_file")
    password = st.text_input("Decryption password", type="password", key="dec_pw")
    expected_hash = st.text_input("Expected SHA-256 (optional — paste from encryption step to verify integrity)")
    if st.button("🔓 Decrypt", type="primary") and file and password:
        data = {"password": password}
        if expected_hash:
            data["expected_sha256"] = expected_hash
        resp = requests.post(
            f"{BACKEND_URL}/api/v1/vault/decrypt", headers=_headers(),
            files={"file": (file.name, file.getvalue())}, data=data, timeout=30,
        )
        if resp.status_code == 200:
            st.success(f"Decrypted successfully. SHA-256: {resp.headers.get('X-SHA256', '')}")
            out_name = file.name[:-4] if file.name.endswith(".enc") else f"decrypted_{file.name}"
            st.download_button("⬇️ Download decrypted file", data=resp.content, file_name=out_name)
        elif resp.status_code == 409:
            st.error("🚨 INTEGRITY CHECK FAILED — this file was modified after it was encrypted!")
        else:
            st.error(resp.json().get("detail", resp.text))

with tab_hash:
    st.subheader("Quick SHA-256 integrity hash")
    file = st.file_uploader("File to hash", key="hash_file")
    if st.button("Compute SHA-256") and file:
        resp = requests.post(
            f"{BACKEND_URL}/api/v1/vault/hash", headers=_headers(),
            files={"file": (file.name, file.getvalue())}, timeout=30,
        )
        if resp.status_code == 200:
            result = resp.json()
            st.code(f"{result['filename']}  ({result['size_bytes']} bytes)\nSHA-256: {result['sha256']}")
        else:
            st.error(resp.text)

with tab_keys:
    st.subheader("Generate an RSA-2048 keypair")
    key_password = st.text_input("Optional passphrase to protect the private key", type="password", key="keygen_pw")
    if st.button("🔑 Generate Keypair"):
        resp = requests.post(
            f"{BACKEND_URL}/api/v1/vault/keypair/generate", headers=_headers(),
            data={"password": key_password} if key_password else {}, timeout=30,
        )
        if resp.status_code == 200:
            result = resp.json()
            st.warning(result["warning"])
            st.text_area("Private key (save this — not stored server-side)", result["private_key_pem"], height=150)
            st.text_area("Public key (share this with whoever will verify your signatures)", result["public_key_pem"], height=150)
        else:
            st.error(resp.text)

with tab_sign:
    st.subheader("Sign a file")
    file = st.file_uploader("File to sign", key="sign_file")
    priv_key = st.text_area("Your private key (PEM)", height=120, key="sign_priv")
    key_pw = st.text_input("Private key passphrase (if set)", type="password", key="sign_priv_pw")
    if st.button("✍️ Sign") and file and priv_key:
        data = {"private_key_pem": priv_key}
        if key_pw:
            data["key_password"] = key_pw
        resp = requests.post(
            f"{BACKEND_URL}/api/v1/vault/sign", headers=_headers(),
            files={"file": (file.name, file.getvalue())}, data=data, timeout=30,
        )
        if resp.status_code == 200:
            result = resp.json()
            st.success("Signed.")
            st.text_area("Signature (base64) — share this + your public key to let others verify", result["signature_b64"], height=100)
        else:
            st.error(resp.json().get("detail", resp.text))

with tab_verify:
    st.subheader("Verify a signature")
    file = st.file_uploader("Original file", key="verify_file")
    sig_b64 = st.text_area("Signature (base64)", height=100, key="verify_sig")
    pub_key = st.text_area("Signer's public key (PEM)", height=120, key="verify_pub")
    if st.button("✅ Verify") and file and sig_b64 and pub_key:
        resp = requests.post(
            f"{BACKEND_URL}/api/v1/vault/verify", headers=_headers(),
            files={"file": (file.name, file.getvalue())},
            data={"signature_b64": sig_b64, "public_key_pem": pub_key}, timeout=30,
        )
        if resp.status_code == 200:
            result = resp.json()
            if result["signature_valid"]:
                st.success("✅ Signature is VALID — file is authentic and unmodified.")
            else:
                st.error("🚨 Signature is INVALID — file may have been tampered with, or wrong key.")
        else:
            st.error(resp.json().get("detail", resp.text))

st.divider()
st.caption("All actions above are written to the audit log and the unified Alert feed on the Home page.")
