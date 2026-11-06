"""Secure Vault page: AES encryption, RSA signatures, SHA-256 integrity.

Rebuild rationale (same platform visual language as the other 4 rebuilt
pages): the 6 crypto operations here are all binary, show-don't-explain
moments (did it encrypt / does it match / is it valid), so they all now
drive ONE shared "vault core" ring+stamp component — the exact same
component family already shipped on Network IDS / Phishing / Malware /
Vulnerability Scanner, just generalized from "verdict" to "operation
confirmation". Every original control, field, and detail panel is kept;
nothing was removed, only visualized and, where real friction existed,
wired to skip a manual re-upload/copy-paste:
  - Encrypt: "Verify Integrity Now" decrypts the just-encrypted blob
    in-memory (no download+re-upload round trip) alongside the existing
    tampering simulation.
  - Generate Keypair -> Sign / Verify Signature: one-click "use this key"
    fills the matching text area instead of manual copy-paste.
  - Sign -> Verify Signature: one-click "use this signature" likewise.
Success UI (download buttons, follow-up actions) is stored in
session_state and rendered outside the triggering `if st.button(...)`
block -- the same fix already applied to the Verify tab's trust
certificate -- so it survives the rerun used to refresh the hero.
"""
import hashlib
import html
import json
import math
from datetime import datetime

import streamlit as st
import streamlit.components.v1 as components
import requests
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

from _backend_bootstrap import ensure_backend
from api_client import require_login, BACKEND_URL, _headers
from theme import inject_global_styles

st.set_page_config(page_title="Secure Vault — SentinelAI", page_icon="🔐", layout="wide")
ensure_backend()
inject_global_styles()
require_login()

st.title("🔐 Secure Vault")
st.caption("AES-256 file encryption, RSA-2048 digital signatures, SHA-256 integrity verification, audit logging.")

st.session_state.setdefault("vault_ledger", [])
st.session_state.setdefault("vault_hero", None)


def _ledger_log(action: str, filename: str, sha256: str = "", status: str = "✅"):
    """Appends one row to this session's live Vault Ledger (newest first)."""
    st.session_state["vault_ledger"].insert(
        0,
        {
            "Time": datetime.now().strftime("%H:%M:%S"),
            "Status": status,
            "Action": action,
            "File": filename or "—",
            "SHA-256": (sha256[:16] + "…") if sha256 else "—",
        },
    )


def _spki_fingerprint(pub_pem: str) -> str:
    """SHA-256 of the key's DER-encoded SubjectPublicKeyInfo — the standard,
    formatting-independent way to fingerprint a public key (unlike hashing
    the raw PEM text, which would change with whitespace/line endings)."""
    try:
        pub = load_pem_public_key(pub_pem.encode())
        der = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return hashlib.sha256(der).hexdigest()
    except Exception:
        return ""


def _crack_time_estimate(pw: str):
    """Transparent, entropy-based estimate of offline crack time. Not a real
    zxcvbn-style model — just charset size x length, assuming ~10 billion
    guesses/second (a fast offline GPU attack), shown for illustration."""
    if not pw:
        return "", "", 0.0, "#6B6355"
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
        label, score, color = "Very Weak", 0.15, "#C62F42"
    elif entropy_bits < 36:
        label, score, color = "Weak", 0.35, "#C97A2B"
    elif entropy_bits < 60:
        label, score, color = "Fair", 0.55, "#FFC65C"
    elif entropy_bits < 80:
        label, score, color = "Strong", 0.8, "#2FE0A8"
    else:
        label, score, color = "Very Strong", 1.0, "#1C9A72"
    return label, time_str, score, color


def _fmt_bytes(n) -> str:
    if n is None:
        return ""
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 / 1024:.1f} MB"


def _key_preview(pem: str) -> str:
    """Short, non-sensitive-looking preview line for a PEM block — just
    enough to recognize it's present without dumping the whole key into
    the hero (the full key is still shown verbatim in its own text_area)."""
    lines = [l for l in pem.strip().splitlines() if l and "-----" not in l]
    if not lines:
        return pem[:28] + "…"
    return lines[0][:28] + "…" + (lines[-1][-8:] if len(lines[-1]) > 8 else "")


_HERO_TEMPLATE = r"""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@500;600;700&family=Manrope:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
  *{box-sizing:border-box}
  html,body{margin:0;background:transparent;overflow:hidden;}
  body{ font-family:'Manrope', system-ui, sans-serif; color:#F4EFE3; padding:2px; }
  .mono{ font-family:'JetBrains Mono', monospace; }
  .display{ font-family:'Cormorant Garamond', Georgia, serif; }

  .console{
    background: linear-gradient(180deg, #0F1115 0%, #07080B 120%);
    border:1px solid #2A2418; border-radius:18px;
    padding: 22px clamp(14px, 3vw, 30px) 20px;
    display:flex; gap:26px; align-items:center; position:relative; overflow:hidden;
    flex-wrap:wrap;
  }
  .console::before{
    content:""; position:absolute; inset:0;
    background: radial-gradient(600px 220px at 88% -15%, color-mix(in srgb, #2FE0A8 10%, transparent), transparent 60%);
    pointer-events:none;
  }

  .ring-col{ flex:0 0 150px; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:8px; position:relative; }
  .ring-wrap{ position:relative; width:108px; height:108px; }
  .ring-wrap svg{ transform:rotate(-90deg); width:108px; height:108px; }
  .ring-bg{ fill:none; stroke:#211C12; stroke-width:6; }
  .ring-fg{ fill:none; stroke:var(--vc,#2FE0A8); stroke-width:6; stroke-linecap:round;
            stroke-dasharray:293; stroke-dashoffset:293; opacity:0;
            transition: stroke-dashoffset 0.8s cubic-bezier(.3,.6,.3,1), opacity 0.3s ease; }
  .stamp{
    position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center;
    gap:2px; transform:scale(0.4); opacity:0; transition: transform 0.45s cubic-bezier(.3,1.4,.4,1), opacity 0.3s ease;
    text-align:center; padding:0 10px;
  }
  .stamp.show{ transform:scale(1); opacity:1; }
  .stamp .word{ font-size:1.0rem; font-weight:700; line-height:1.15; letter-spacing:0.02em; }
  .placeholder{ color:#6B6355; font-size:0.8rem; text-align:center; position:absolute; inset:0; display:flex; align-items:center; justify-content:center; padding:0 12px; }

  .detail{ flex:1 1 280px; min-width:0; display:flex; flex-direction:column; gap:9px; justify-content:center; }
  .fchip{ display:inline-flex; align-items:center; gap:8px; align-self:flex-start; padding:6px 12px; border-radius:9px; background:#07080B; border:1px solid #2A2418; font-size:0.78rem; color:#D9D2C0; max-width:100%; }
  .fchip .fname{ overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:260px; }
  .fchip .sz{ color:#6B6355; flex-shrink:0; }
  .hlabel{ font-size:0.66rem; color:#A39A87; text-transform:uppercase; letter-spacing:0.05em; }
  .hval{ font-family:'JetBrains Mono', monospace; font-size:0.84rem; color:#F4EFE3; word-break:break-all; opacity:0; transform:translateY(3px); transition: all 0.5s ease 0.1s; }
  .hval.show{ opacity:1; transform:translateY(0); }
  .extra{ font-size:0.78rem; color:#A39A87; }

  .keyrow{ display:flex; gap:10px; flex-wrap:wrap; }
  .keycard{ flex:1 1 150px; border-radius:11px; border:1px solid #2A2418; background:#07080B; padding:9px 13px; opacity:0; transform:translateY(6px); transition: all 0.4s cubic-bezier(.3,1.2,.4,1); }
  .keycard.show{ opacity:1; transform:translateY(0); }
  .keycard .klabel{ font-size:0.66rem; text-transform:uppercase; letter-spacing:0.05em; font-weight:600; }
  .keycard .kprev{ font-family:'JetBrains Mono', monospace; font-size:0.72rem; color:#A39A87; margin-top:4px; word-break:break-all; }
  .keycard.pub{ border-color:#2FE0A855; } .keycard.pub .klabel{ color:#2FE0A8; }
  .keycard.priv{ border-color:#FFA94055; } .keycard.priv .klabel{ color:#FFA940; }

  /* Stays a row at every width (never stacks) — this iframe has a fixed
     pixel height with no auto-resize, so a column stack here would clip
     the detail panel instead of just reflowing it. */
  @media (max-width:480px){
    .ring-col{ flex:0 0 78px; }
    .ring-wrap{ width:72px; height:72px; }
    .ring-wrap svg{ width:72px; height:72px; }
    .console{ gap:14px; padding:16px 14px; }
    .fchip .fname{ max-width:120px; }
  }
  @media (prefers-reduced-motion: reduce){ .stamp, .ring-fg, .hval, .keycard{ transition-duration:0.01s !important; } }
</style>

<div class="console">
  <div class="ring-col">
    <div class="ring-wrap">
      <svg viewBox="0 0 108 108">
        <circle class="ring-bg" cx="54" cy="54" r="46.6"></circle>
        <circle class="ring-fg" id="ring" cx="54" cy="54" r="46.6"></circle>
      </svg>
      <div class="stamp" id="stamp"><div class="word display" id="stampWord"></div></div>
      <div class="placeholder" id="placeholder">awaiting an action below</div>
    </div>
  </div>
  <div class="detail" id="detail"></div>
</div>

<script>
(function(){
  const data = __PAYLOAD_JSON__;
  const ring = document.getElementById('ring');
  const stamp = document.getElementById('stamp');
  const stampWord = document.getElementById('stampWord');
  const placeholder = document.getElementById('placeholder');
  const detail = document.getElementById('detail');

  if (!data.hasResult) { return; }

  placeholder.style.display = 'none';
  const color = data.color === 'bad' ? '#E0344F' : (data.color === 'info' ? '#4F9BFF' : '#2FE0A8');
  ring.style.setProperty('--vc', color);
  ring.style.stroke = color;
  stampWord.style.color = color;
  stampWord.textContent = data.word || '';
  const wlen = (data.word || '').length;
  const narrow = window.innerWidth < 480;
  const tiers = narrow ? ['0.46rem', '0.54rem', '0.62rem', '0.7rem'] : ['0.64rem', '0.76rem', '0.88rem', '1.0rem'];
  stampWord.style.fontSize = wlen > 10 ? tiers[0] : wlen > 8 ? tiers[1] : wlen > 6 ? tiers[2] : tiers[3];
  stampWord.style.letterSpacing = wlen > 8 ? '0.01em' : '0.02em';

  setTimeout(() => {
    ring.style.opacity = '1';
    ring.style.strokeDashoffset = '0';
    stamp.classList.add('show');
  }, 90);

  function el(tag, cls){ const e = document.createElement(tag); if (cls) e.className = cls; return e; }
  function span(cls, text){ const s = el('span', cls); if (text != null) s.textContent = text; return s; }

  if (data.filename) {
    const chip = el('div', 'fchip');
    chip.appendChild(span(null, '📄'));
    chip.appendChild(span('fname', data.filename));
    if (data.size != null) chip.appendChild(span('sz', '· ' + (function(n){
      if (n < 1024) return n + ' B';
      if (n < 1024*1024) return (n/1024).toFixed(1) + ' KB';
      return (n/1024/1024).toFixed(1) + ' MB';
    })(data.size)));
    detail.appendChild(chip);
  }

  if (data.keys) {
    const row = el('div', 'keyrow');
    const pub = el('div', 'keycard pub'); pub.id = 'kpub';
    pub.appendChild(span('klabel', 'Public key'));
    pub.appendChild(span('kprev', data.keys.public));
    const priv = el('div', 'keycard priv'); priv.id = 'kpriv';
    priv.appendChild(span('klabel', 'Private key'));
    priv.appendChild(span('kprev', data.keys.private));
    row.appendChild(pub); row.appendChild(priv);
    detail.appendChild(row);
  } else if (data.hash) {
    const wrap = el('div', null);
    wrap.appendChild(span('hlabel', data.hashLabel || 'SHA-256'));
    const val = span('hval mono', data.hash); val.id = 'hval';
    wrap.appendChild(document.createElement('br'));
    wrap.appendChild(val);
    detail.appendChild(wrap);
  }

  if (data.extra) {
    detail.appendChild(span('extra', data.extra));
  }

  setTimeout(() => {
    const hv = document.getElementById('hval'); if (hv) hv.classList.add('show');
    const kp = document.getElementById('kpub'); if (kp) kp.classList.add('show');
    const kr = document.getElementById('kpriv'); if (kr) setTimeout(() => kr.classList.add('show'), 100);
  }, 180);
})();
</script>
"""


def _render_hero(payload: dict | None) -> None:
    html_out = _HERO_TEMPLATE.replace("__PAYLOAD_JSON__", json.dumps(payload or {"hasResult": False}))
    components.html(html_out, height=215, scrolling=False)


_render_hero(st.session_state.get("vault_hero"))

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
<div style="background:#2A2418;border-radius:6px;height:8px;overflow:hidden;">
<div style="width:{_score * 100:.0f}%;background:{_color};height:100%;transition:width .2s ease;"></div>
</div>
<div style="display:flex;justify-content:space-between;margin-top:4px;font-size:0.82rem;">
<span style="color:{_color};font-weight:600;">{_label}</span>
<span style="color:#A39A87;">Est. crack time: {_ctime}</span>
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
            st.session_state["vault_demo_blob"] = resp.content
            st.session_state["vault_demo_filename"] = file.name
            st.session_state["vault_demo_hash"] = original_hash
            st.session_state["vault_demo_password"] = password
            st.session_state["vault_encrypt_ui"] = {
                "filename": file.name, "size": len(resp.content), "hash": original_hash,
            }
            st.session_state["vault_verify_now_ui"] = None
            st.session_state["vault_hero"] = {
                "hasResult": True, "word": "ENCRYPTED", "color": "good",
                "filename": file.name, "size": len(resp.content),
                "hash": original_hash, "hashLabel": "SHA-256 (original file)",
            }
            _ledger_log("Encrypted", file.name, original_hash, "✅")
            st.rerun()
        else:
            st.error(resp.text)
            _ledger_log("Encrypt Failed", file.name, "", "🚨")

    if st.session_state.get("vault_encrypt_ui"):
        r = st.session_state["vault_encrypt_ui"]
        st.success("File encrypted.")
        st.code(f"SHA-256 of original file (save this to verify integrity later):\n{r['hash']}")
        st.download_button(
            "⬇️ Download encrypted file", data=st.session_state["vault_demo_blob"], file_name=f"{r['filename']}.enc",
        )

        st.divider()
        st.subheader("🧪 Live Demo: integrity in action")
        st.caption(
            "Verify it decrypts clean with zero re-upload, or flip a single byte and watch the same check catch it — "
            "exactly what happens if an attacker (or a corrupted transfer) modifies the file after encryption."
        )
        col_ok, col_tamper = st.columns(2)
        with col_ok:
            verify_now_clicked = st.button("✅ Verify Integrity Now")
        with col_tamper:
            tamper_clicked = st.button("⚠️ Simulate Tampering & Re-Decrypt")

        if verify_now_clicked or tamper_clicked:
            blob = bytearray(st.session_state["vault_demo_blob"])
            tampered_label = ""
            if tamper_clicked:
                header_len = 32  # 16-byte salt + 16-byte IV, before the ciphertext starts
                num_blocks = max(1, (len(blob) - header_len) // 16)
                target_block = max(0, num_blocks - 3)
                flip_offset = header_len + target_block * 16
                blob[flip_offset] ^= 0x01
                tampered_label = " (1 byte flipped)"
            check_name = f'{r["filename"]}.enc'
            resp2 = requests.post(
                f"{BACKEND_URL}/api/v1/vault/decrypt", headers=_headers(),
                files={"file": (check_name, bytes(blob))},
                data={
                    "password": st.session_state["vault_demo_password"],
                    "expected_sha256": st.session_state["vault_demo_hash"],
                },
                timeout=30,
            )
            if resp2.status_code == 200:
                st.session_state["vault_verify_now_ui"] = {
                    "status": "ok",
                    "message": f"Decrypted clean — integrity verified{tampered_label or ''}." if not tamper_clicked
                               else "The tampered file still decrypted without error — click Simulate Tampering again.",
                    "kind": "warning" if tamper_clicked else "success",
                }
                st.session_state["vault_hero"] = {
                    "hasResult": True, "word": "VERIFIED", "color": "good",
                    "filename": r["filename"], "size": r["size"],
                    "hash": st.session_state["vault_demo_hash"], "hashLabel": "SHA-256 (matched)",
                }
                _ledger_log("Tampering Simulated" if tamper_clicked else "Integrity Verified", check_name, "", "⚠️" if tamper_clicked else "✅")
            elif resp2.status_code == 409:
                st.session_state["vault_verify_now_ui"] = {
                    "status": "tampered",
                    "message": "🚨 TAMPERING DETECTED — SHA-256 integrity check failed. The file's content changed after it was encrypted.",
                    "kind": "error",
                }
                st.session_state["vault_hero"] = {
                    "hasResult": True, "word": "TAMPERED", "color": "bad",
                    "filename": r["filename"], "size": r["size"], "extra": "File content changed after encryption.",
                }
                _ledger_log("Tampering Simulated", check_name, "", "🚨")
            elif resp2.status_code == 400:
                st.session_state["vault_verify_now_ui"] = {
                    "status": "failed",
                    "message": "🚨 TAMPERING DETECTED — the modified file failed to decrypt cleanly (corrupted padding/ciphertext).",
                    "kind": "error",
                }
                st.session_state["vault_hero"] = {
                    "hasResult": True, "word": "FAILED", "color": "bad",
                    "filename": r["filename"], "size": r["size"], "extra": "Corrupted padding/ciphertext.",
                }
                _ledger_log("Tampering Simulated", check_name, "", "🚨")
            else:
                st.session_state["vault_verify_now_ui"] = {
                    "status": "failed",
                    "message": resp2.json().get("detail", resp2.text),
                    "kind": "error",
                }
                st.session_state["vault_hero"] = {
                    "hasResult": True, "word": "FAILED", "color": "bad",
                    "filename": r["filename"], "size": r["size"],
                }
                _ledger_log("Tampering Simulated", check_name, "", "🚨")
            st.rerun()

        if st.session_state.get("vault_verify_now_ui"):
            v = st.session_state["vault_verify_now_ui"]
            getattr(st, v["kind"])(v["message"])
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
    if st.session_state.get("vault_demo_hash"):
        if st.button("📋 Use hash from my last encryption"):
            st.session_state["dec_expected_hash"] = st.session_state["vault_demo_hash"]
            st.rerun()
    expected_hash = st.text_input(
        "Expected SHA-256 (optional — paste from encryption step to verify integrity)", key="dec_expected_hash",
    )
    if st.button("🔓 Decrypt", type="primary") and file and password:
        data = {"password": password}
        if expected_hash:
            data["expected_sha256"] = expected_hash
        resp = requests.post(
            f"{BACKEND_URL}/api/v1/vault/decrypt", headers=_headers(),
            files={"file": (file.name, file.getvalue())}, data=data, timeout=30,
        )
        out_name = file.name[:-4] if file.name.endswith(".enc") else f"decrypted_{file.name}"
        if resp.status_code == 200:
            actual_hash = resp.headers.get("X-SHA256", "")
            st.session_state["vault_decrypt_ui"] = {
                "status": "ok", "filename": file.name, "out_name": out_name,
                "hash": actual_hash, "blob": resp.content, "checked": bool(expected_hash),
            }
            st.session_state["vault_hero"] = {
                "hasResult": True, "word": "VERIFIED" if expected_hash else "DECRYPTED", "color": "good",
                "filename": file.name, "size": len(resp.content),
                "hash": actual_hash, "hashLabel": "SHA-256",
            }
            _ledger_log("Decrypted", file.name, actual_hash, "✅")
            st.rerun()
        elif resp.status_code == 409:
            st.session_state["vault_decrypt_ui"] = {"status": "tampered", "filename": file.name}
            st.session_state["vault_hero"] = {
                "hasResult": True, "word": "TAMPERED", "color": "bad",
                "filename": file.name, "extra": "File content changed after encryption.",
            }
            _ledger_log("Integrity FAILED", file.name, "", "🚨")
            st.rerun()
        else:
            st.session_state["vault_decrypt_ui"] = {
                "status": "failed", "filename": file.name,
                "detail": resp.json().get("detail", resp.text),
            }
            st.session_state["vault_hero"] = {
                "hasResult": True, "word": "FAILED", "color": "bad", "filename": file.name,
                "extra": "Wrong password or corrupted file.",
            }
            _ledger_log("Decrypt Failed", file.name, "", "🚨")
            st.rerun()

    if st.session_state.get("vault_decrypt_ui"):
        d = st.session_state["vault_decrypt_ui"]
        if d["status"] == "ok":
            st.success(f"Decrypted successfully. SHA-256: {d['hash']}")
            st.download_button("⬇️ Download decrypted file", data=d["blob"], file_name=d["out_name"])
        elif d["status"] == "tampered":
            st.error("🚨 INTEGRITY CHECK FAILED — this file was modified after it was encrypted!")
        else:
            st.error(d["detail"])

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
            st.session_state["vault_hash_ui"] = result
            st.session_state["vault_hero"] = {
                "hasResult": True, "word": "FINGERPRINT", "color": "info",
                "filename": result["filename"], "size": result["size_bytes"],
                "hash": result["sha256"], "hashLabel": "SHA-256",
            }
            _ledger_log("Hashed", result["filename"], result["sha256"], "✅")
            st.rerun()
        else:
            st.error(resp.text)
            _ledger_log("Hash Failed", file.name, "", "🚨")

    if st.session_state.get("vault_hash_ui"):
        result = st.session_state["vault_hash_ui"]
        st.code(f"{result['filename']}  ({result['size_bytes']} bytes)\nSHA-256: {result['sha256']}")

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
            st.session_state["vault_keypair_ui"] = result
            st.session_state["vault_gen_priv"] = result["private_key_pem"]
            st.session_state["vault_gen_pub"] = result["public_key_pem"]
            st.session_state["vault_hero"] = {
                "hasResult": True, "word": "KEYS READY", "color": "good",
                "keys": {
                    "public": _key_preview(result["public_key_pem"]),
                    "private": _key_preview(result["private_key_pem"]),
                },
            }
            _ledger_log("Keypair Generated", "RSA-2048 keypair", "", "✅")
            st.rerun()
        else:
            st.error(resp.text)
            _ledger_log("Keypair Generation Failed", "-", "", "🚨")

    if st.session_state.get("vault_keypair_ui"):
        result = st.session_state["vault_keypair_ui"]
        st.warning(result["warning"])
        st.text_area("Private key (save this — not stored server-side)", result["private_key_pem"], height=150)
        st.text_area("Public key (share this with whoever will verify your signatures)", result["public_key_pem"], height=150)
        st.caption("✓ Auto-filled into the Sign and Verify tabs below — no copy-paste needed.")

with tab_sign:
    st.subheader("Sign a file")
    file = st.file_uploader("File to sign", key="sign_file")
    if st.session_state.get("vault_gen_priv"):
        if st.button("📋 Use generated private key"):
            st.session_state["sign_priv"] = st.session_state["vault_gen_priv"]
            st.rerun()
    priv_key = st.text_area(
        "Your private key (PEM)", height=120, key="sign_priv",
        help="Tip: after pasting, press Ctrl+Enter or click outside this box before clicking Sign below — otherwise the old value is used.",
    )
    key_pw = st.text_input("Private key passphrase (if set)", type="password", key="sign_priv_pw")
    if st.button("✍️ Sign") and file and priv_key:
        file_bytes = file.getvalue()
        data = {"private_key_pem": priv_key}
        if key_pw:
            data["key_password"] = key_pw
        resp = requests.post(
            f"{BACKEND_URL}/api/v1/vault/sign", headers=_headers(),
            files={"file": (file.name, file_bytes)}, data=data, timeout=30,
        )
        if resp.status_code == 200:
            result = resp.json()
            st.session_state["vault_sign_ui"] = result
            st.session_state["vault_gen_sig"] = result["signature_b64"]
            st.session_state["vault_hero"] = {
                "hasResult": True, "word": "SIGNED", "color": "good",
                "filename": result["filename"], "size": len(file_bytes),
                "hash": result["sha256"], "hashLabel": "SHA-256 (signed file)",
                "extra": f"Signature: {result['signature_b64'][:28]}…",
            }
            _ledger_log("Signed", result["filename"], result["sha256"], "✅")
            st.rerun()
        else:
            st.error(resp.json().get("detail", resp.text))
            _ledger_log("Sign Failed", file.name, "", "🚨")

    if st.session_state.get("vault_sign_ui"):
        result = st.session_state["vault_sign_ui"]
        st.success("Signed.")
        st.text_area("Signature (base64) — share this + your public key to let others verify", result["signature_b64"], height=100)
        st.caption("✓ Signature auto-filled into the Verify Signature tab below.")

with tab_verify:
    st.subheader("Verify a signature")
    file = st.file_uploader("Original file", key="verify_file")
    col_sig, col_pub = st.columns(2)
    with col_sig:
        if st.session_state.get("vault_gen_sig"):
            if st.button("📋 Use last signature"):
                st.session_state["verify_sig"] = st.session_state["vault_gen_sig"]
                st.rerun()
    with col_pub:
        if st.session_state.get("vault_gen_pub"):
            if st.button("📋 Use generated public key"):
                st.session_state["verify_pub"] = st.session_state["vault_gen_pub"]
                st.rerun()
    sig_b64 = st.text_area(
        "Signature (base64)", height=100, key="verify_sig",
        help="Tip: after pasting, press Ctrl+Enter or click outside this box before clicking Verify below — otherwise the old value is used.",
    )
    pub_key = st.text_area(
        "Signer's public key (PEM)", height=120, key="verify_pub",
        help="Tip: after pasting, press Ctrl+Enter or click outside this box before clicking Verify below — otherwise the old value is used.",
    )
    if st.button("✅ Verify") and file and sig_b64 and pub_key:
        resp = requests.post(
            f"{BACKEND_URL}/api/v1/vault/verify", headers=_headers(),
            files={"file": (file.name, file.getvalue())},
            data={"signature_b64": sig_b64, "public_key_pem": pub_key}, timeout=30,
        )
        if resp.status_code == 200:
            result = resp.json()
            if result["signature_valid"]:
                _ledger_log("Signature VALID", file.name, "", "✅")
                file_sha = hashlib.sha256(file.getvalue()).hexdigest()
                key_fp = _spki_fingerprint(pub_key)
                # Stored rather than rendered inline: a st.download_button click
                # below triggers its own rerun, on which "✅ Verify" is no longer
                # True — if the certificate lived inside this if-block it would
                # vanish the instant Download is clicked. Storing it and always
                # re-rendering from session_state keeps it on screen across that
                # rerun.
                st.session_state["vault_cert"] = {
                    "file_name": file.name,
                    "file_sha256": file_sha,
                    "key_fp": key_fp,
                    "verified_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
                st.session_state["vault_hero"] = {
                    "hasResult": True, "word": "VALID", "color": "good",
                    "filename": file.name, "hash": file_sha, "hashLabel": "SHA-256",
                }
            else:
                st.session_state["vault_cert"] = None
                st.session_state["vault_hero"] = {
                    "hasResult": True, "word": "INVALID", "color": "bad",
                    "filename": file.name, "extra": "Signature does not match this file and key.",
                }
                st.error("🚨 Signature is INVALID — file may have been tampered with, or wrong key.")
                _ledger_log("Signature INVALID", file.name, "", "🚨")
            st.rerun()
        else:
            st.session_state["vault_cert"] = None
            st.error(resp.json().get("detail", resp.text))
            _ledger_log("Verify Failed", file.name, "", "🚨")

    if st.session_state.get("vault_cert"):
        cert = st.session_state["vault_cert"]
        st.success("✅ Signature is VALID — file is authentic and unmodified.")
        st.divider()
        # cert['file_name'] comes from the uploaded file's own .name — fully
        # user-controlled — so it MUST be HTML-escaped before going into this
        # unsafe_allow_html block. Without this, a file named e.g.
        # "<img src=x onerror=alert(1)>.txt" would execute as real HTML on
        # this page (a self-XSS reflected into the uploader's own session).
        # The other fields here are server-computed hex digests/timestamps,
        # not user input, so they don't need the same treatment.
        safe_file_name = html.escape(cert["file_name"])
        st.markdown(
            f"""<div style="border:1px solid #2FE0A8;border-radius:10px;padding:18px 22px;background:linear-gradient(135deg,#0C2A20,#0F1115);">
<div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;">
<span style="font-size:1.5rem;">🛡️</span>
<span style="font-size:1.08rem;font-weight:700;color:#2FE0A8;">Trust Certificate — Signature Verified</span>
</div>
<table style="width:100%;font-size:0.86rem;color:#D9D2C0;border-collapse:collapse;">
<tr><td style="padding:4px 0;color:#A39A87;width:180px;vertical-align:top;">File</td><td>{safe_file_name}</td></tr>
<tr><td style="padding:4px 0;color:#A39A87;vertical-align:top;">File SHA-256</td><td style="font-family:monospace;word-break:break-all;">{cert['file_sha256']}</td></tr>
<tr><td style="padding:4px 0;color:#A39A87;vertical-align:top;">Signature algorithm</td><td>RSA-2048 + PSS + SHA-256</td></tr>
<tr><td style="padding:4px 0;color:#A39A87;vertical-align:top;">Key fingerprint (SPKI SHA-256)</td><td style="font-family:monospace;word-break:break-all;">{cert['key_fp']}</td></tr>
<tr><td style="padding:4px 0;color:#A39A87;vertical-align:top;">Verified at</td><td>{cert['verified_at']}</td></tr>
</table>
</div>""",
            unsafe_allow_html=True,
        )
        st.caption(
            "A valid signature proves the file exactly matches what this key holder signed — it does not "
            "by itself prove who the key holder is. Only trust a public key you received directly from the signer."
        )
        cert_text = (
            "SENTINELAI SECURE VAULT — DIGITAL SIGNATURE TRUST CERTIFICATE\n"
            "================================================================\n"
            f"File:                 {cert['file_name']}\n"
            f"File SHA-256:         {cert['file_sha256']}\n"
            "Signature algorithm:  RSA-2048 + PSS + SHA-256\n"
            f"Key fingerprint:      {cert['key_fp']}\n"
            "                      (SHA-256 of the DER-encoded SubjectPublicKeyInfo)\n"
            f"Verified at:          {cert['verified_at']}\n"
            "Result:               VALID — signature matches file and public key\n"
            "\n"
            "Note: this certificate proves the signature is mathematically valid for\n"
            "this exact file and the public key supplied at verification time. It does\n"
            "NOT independently prove the real-world identity behind that key — only\n"
            "trust a public key you received directly from the signer.\n"
        )
        st.download_button(
            "⬇️ Download Trust Certificate (.txt)",
            data=cert_text,
            file_name=f"trust_certificate_{cert['file_name']}.txt",
            mime="text/plain",
        )

st.divider()
with st.expander(
    f"🗂️ Session Vault Ledger — {len(st.session_state['vault_ledger'])} action(s) this session",
    expanded=False,
):
    if st.session_state["vault_ledger"]:
        st.dataframe(st.session_state["vault_ledger"], hide_index=True, use_container_width=True)
        if st.button("🧹 Clear Ledger"):
            st.session_state["vault_ledger"] = []
            st.rerun()
    else:
        st.caption(
            "No actions logged yet this session — every encrypt, decrypt, hash, sign, verify, "
            "keypair, and tampering-simulation action will appear here automatically, newest first."
        )

st.caption("All actions above are written to the audit log and the unified Alert feed on the Home page.")
