"""Secure Vault page: AES encryption, RSA signatures, SHA-256 integrity."""
import math

import streamlit as st
import requests

from _backend_bootstrap import ensure_backend
from api_client import require_login, BACKEND_URL, _headers

st.set_page_config(page_title="Secure Vault — SentinelAI", page_icon="🔐", layout="wide")
ensure_backend()
require_login()

st.title("🔐 Secure Vault")
st.caption("AES-256 file encryption, RSA-2048 digital signatures, SHA-256 integrity verification, audit logging.")


def _crack_time_estimate(pw: str):
    """Transparent, entropy-based estimate of offline crack time. Not a real
    zxcvbn-style model — just charset size x length, assuming ~10 billion
    guesses/second (a fast offline GPU attack), shown for illustration."""
    if not pw:
        return "", "", 0.0, "#5f6368"
    charset = 0
    if any(c.islower() for c in pw):
        charset += 26
    if any(c.isupper() for c in pw):
        charset += 26
    if any(c.isdigit() for c in pw):
        charset += 10
    if any(not c.isalnum() for c in pw):
        charset += 32
    charset = max(charset, 1)
    entropy_bits = len(pw) * math.log2(charset)
    guesses = (2 ** entropy_bits) / 2
    seconds = guesses / 10_000_000_000

    if seconds < 1:
        time_str = "instantly"
    elif seconds < 60:
        time_str = f"{seconds:.0f} seconds"
    elif seconds < 3600:
        time_str = f"{seconds / 60:.0f} minutes"
    elif seconds < 86400:
        time_str = f"{seconds / 3600:.0f} hours"
    elif seconds < 31536000:
        time_str = f"{seconds / 86400:.0f} days"
    elif seconds < 31536000 * 100:
        time_str = f"{seconds / 31536000:.0f} years"
    else:
        time_str = "centuries"

    if entropy_bits < 28:
        label, score, color = "Very Weak", 0.15, "#e74c3c"
    elif entropy_bits < 36:
        label, score, color = "Weak", 0.35, "#e67e22"
    elif entropy_bits < 60:
        label, score, color = "Fair", 0.55, "#f1c40f"
    elif entropy_bits < 80:
        label, score, color = "Strong", 0.8, "#2ecc71"
    else:
        label, score, color = "Very Strong", 1.0, "#27ae60"
    return label, time_str, score, color


tab_encrypt, tab_decrypt, tab_hash, tab_keys, tab_sign, tab_verify = st.tabs(
    ["Encrypt", "Decrypt / Verify Integrity", "Hash a File", "Generate Keypair", "Sign", "Verify Signature"]
)

with tab_encrypt:
    st.subheader("Encrypt a file (AES-256)")
    file = st.file_uploader("File to encrypt", key="enc_file")
    password = st.text_input("Encryption password (min 8 chars)", type="password", key="enc_pw")
    if password:
        _label, _ctime, _score, _color = _crack_time_estimate(password)
        st.markdown(
            f"""<div style="margin:2px 0 10px 0;">
<div style="background:#2a2d35;border-radius:6px;height:8px;overflow:hidden;">
<div style="width:{_score * 100:.0f}%;background:{_color};height:100%;transition:width .2s ease;"></div>
</div>
<div style="display:flex;justify-content:space-between;margin-top:4px;font-size:0.82rem;">
<span style="color:{_color};font-weight:600;">{_label}</span>
<span style="color:#9aa0a6;">Est. crack time: {_ctime}</span>
</div>
</div>""",
            unsafe_allow_html=True,
        )
        st.caption("Estimate assumes a fast offline attack (~10 billion guesses/sec) — for illustration, not a guarantee.")
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
            st.session_state["vault_demo_blob"] = resp.content
            st.session_state["vault_demo_filename"] = file.name
            st.session_state["vault_demo_hash"] = original_hash
            st.session_state["vault_demo_password"] = password
        else:
            st.error(resp.text)

    if st.session_state.get("vault_demo_blob"):
        st.divider()
        st.subheader("🧪 Live Demo: Simulate Tampering")
        st.caption(
            "Flip a single byte inside the encrypted file and try to decrypt it live — "
            "exactly what happens if an attacker (or a corrupted transfer) modifies the file after encryption."
        )
        if st.button("⚠️ Simulate Tampering & Re-Decrypt"):
            blob = bytearray(st.session_state["vault_demo_blob"])
            header_len = 32  # 16-byte salt + 16-byte IV, before the ciphertext starts
            num_blocks = max(1, (len(blob) - header_len) // 16)
            target_block = max(0, num_blocks - 3)
            flip_offset = header_len + target_block * 16
            blob[flip_offset] ^= 0x01
            tampered_name = f'{st.session_state["vault_demo_filename"]}.enc'
            resp2 = requests.post(
                f"{BACKEND_URL}/api/v1/vault/decrypt", headers=_headers(),
                files={"file": (tampered_name, bytes(blob))},
                data={
                    "password": st.session_state["vault_demo_password"],
                    "expected_sha256": st.session_state["vault_demo_hash"],
                },
                timeout=30,
            )
            if resp2.status_code == 409:
                st.error("🚨 TAMPERING DETECTED — SHA-256 integrity check failed. The file's content changed after it was encrypted.")
            elif resp2.status_code == 400:
                st.error("🚨 TAMPERING DETECTED — the modified file failed to decrypt cleanly (corrupted padding/ciphertext).")
            elif resp2.status_code == 200:
                st.warning("The tampered file still decrypted without error — click Simulate Tampering again.")
            else:
                st.error(resp2.json().get("detail", resp2.text))
            st.caption(
                "Why this gets caught: AES-CBC by itself has no built-in authenticity check — it will happily "
                "decrypt garbage. What actually catches the tampering is the SHA-256 of the original file, "
                "captured the moment you encrypted it, compared against the hash of whatever comes out the "
                "other side of decryption."
            )

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
    priv_key = st.text_area("Your private key (PEM)", height=120, key="sign_priv", help="Tip: after pasting, press Ctrl+Enter or click outside this box before clicking Sign below — otherwise the old value is used.")
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
    sig_b64 = st.text_area("Signature (base64)", height=100, key="verify_sig", help="Tip: after pasting, press Ctrl+Enter or click outside this box before clicking Verify below — otherwise the old value is used.")
    pub_key = st.text_area("Signer's public key (PEM)", height=120, key="verify_pub", help="Tip: after pasting, press Ctrl+Enter or click outside this box before clicking Verify below — otherwise the old value is used.")
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
