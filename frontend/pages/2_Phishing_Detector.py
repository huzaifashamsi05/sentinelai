"""
Phishing & Malicious URL Detector page.

Rebuilt per direction change: the Red Flags Checklist (a 3-column list of
titles + paragraph captions) and the plain URL Anatomy chip row are
replaced by one live "scan" scene — the real URL gets split into its real
pieces, the pieces that actually tripped a real signal light up, and a
verdict stamps down with a confidence ring. Same model, same backend, same
honest "lexical/structural, no network calls" scope, same brand-
impersonation rule-based check — only the presentation changed. SHAP and
the full feature-by-feature explanation are kept, folded into one
collapsed, opt-in section instead of being open by default.
"""
import json
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st
import streamlit.components.v1 as components

from _backend_bootstrap import ensure_backend
from api_client import api_get, api_post, require_login
from theme import TOPAZ, inject_global_styles, page_header, sidebar_brand

st.set_page_config(page_title="Phishing Detector — SentinelAI", page_icon="🎣", layout="wide")
ensure_backend()
inject_global_styles()
sidebar_brand()
require_login()

page_header(
    "🎣", "EMAIL & URL SECURITY", "Phishing & Malicious URL Detector",
    "Paste a link, watch it get X-rayed — no network calls, just the shape of the URL itself.",
    TOPAZ,
)

status = api_get("/phishing/status").json()
if not status.get("model_loaded"):
    st.error("Model not loaded on the backend yet.")
    st.stop()

samples = api_get("/phishing/sample-requests").json()

_FEATURE_EXPLAIN = {
    "has_ip_address": {
        "pill": "IP address", "title": "Uses a raw IP address instead of a domain",
        "why": "Legitimate sites almost always have a registered domain name. A URL pointing "
               "straight at an IP address (e.g. http://192.168.1.1/login) is a strong red flag.",
    },
    "has_at_symbol": {
        "pill": "hidden “@”", "title": "Contains an \"@\" symbol",
        "why": "Browsers ignore everything before an \"@\" in a URL's authority section — attackers "
               "abuse this to show a trusted-looking prefix while the real destination is hidden after it.",
    },
    "has_https_token_in_path": {
        "pill": "fake https", "title": "The word \"https\" appears in the path, not the scheme",
        "why": "Putting the literal word \"https\" inside the path or query (not as the actual scheme) "
               "is a trick to make a link look secure at a glance when it isn't.",
    },
    "has_suspicious_keyword": {
        "pill": "risky wording", "title": "Contains a high-risk keyword",
        "why": "Words like \"login\", \"verify\", \"secure\", \"account\", or \"bank\" are common phishing "
               "bait, designed to create urgency or impersonate an account-security notice.",
    },
    "is_url_shortener": {
        "pill": "shortener", "title": "Uses a URL-shortener domain",
        "why": "Shorteners (bit.ly, tinyurl.com, ...) hide the real destination entirely until you click — "
               "legitimate and malicious links both use them, but it removes your ability to pre-screen the link.",
    },
    "has_double_slash_redirect": {
        "pill": "hidden redirect", "title": "Has an extra \"//\" later in the URL",
        "why": "A second \"//\" partway through a URL can be used to smuggle in an open-redirect to a "
               "different destination than the one you'd expect from the start of the link.",
    },
    "url_length": {"title": "Overall URL length", "why": "Phishing URLs are often padded with extra characters to obscure the real destination."},
    "hostname_length": {"title": "Hostname length", "why": "An unusually long hostname can indicate a deliberately obfuscated or auto-generated domain."},
    "path_length": {"title": "Path length", "why": "A long, convoluted path can be used to bury or disguise the true nature of a link."},
    "num_dots": {"title": "Number of dots", "why": "Extra dots mean extra subdomain levels — a common lookalike-domain technique."},
    "num_hyphens": {"title": "Number of hyphens", "why": "Hyphens are frequently used to fake a brand name, e.g. \"paypal-secure-login\"."},
    "num_underscores": {"title": "Number of underscores", "why": "Underscores are rare in legitimate domains, more common in auto-generated or obfuscated ones."},
    "num_slashes": {"title": "Number of slashes", "why": "An unusually deep path structure can be used to hide the real target of a link."},
    "num_digits": {"title": "Number of digits", "why": "A high digit count can indicate a randomly-generated or algorithmically-produced malicious domain."},
    "num_special_chars": {"title": "Special characters (@ % = & ? ~)", "why": "These are often used in redirect tricks or to obfuscate a URL's true target."},
    "num_subdomains": {"title": "Number of subdomains", "why": "Many subdomains is a classic lookalike-domain technique — stacking words before the real (attacker-owned) domain."},
    "digit_ratio": {"title": "Proportion of the URL that's digits", "why": "Same rationale as digit count — a high ratio often signals an obfuscated or auto-generated URL."},
}

_PILL_ORDER = [
    "has_ip_address", "has_at_symbol", "has_https_token_in_path",
    "has_suspicious_keyword", "is_url_shortener", "has_double_slash_redirect",
]


def _render_shap_chart(explanation: list[dict]) -> None:
    exp_df = pd.DataFrame(explanation)
    exp_df["direction"] = exp_df["impact"].apply(lambda x: "Pushes toward phishing" if x > 0 else "Pushes toward benign")
    fig = px.bar(
        exp_df.sort_values("impact"), x="impact", y="feature", orientation="h",
        color="direction", color_discrete_map={"Pushes toward phishing": "#E0344F", "Pushes toward benign": "#2FE0A8"},
    )
    fig.update_layout(
        height=260, yaxis_title="", xaxis_title="SHAP impact", margin=dict(t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font={"color": "#F4EFE3"},
        legend_title_text="",
    )
    st.plotly_chart(fig, use_container_width=True)


_SCAN_TEMPLATE = r"""
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
    padding: 24px clamp(14px, 3vw, 30px) 22px;
    display:flex; gap:24px; align-items:stretch; position:relative; overflow:hidden;
    flex-wrap:wrap;
  }
  .console::before{
    content:""; position:absolute; inset:0;
    background: radial-gradient(600px 220px at 12% -15%, color-mix(in srgb, #2FE0A8 10%, transparent), transparent 60%);
    pointer-events:none;
  }

  .left{ flex:1 1 320px; min-width:0; display:flex; flex-direction:column; gap:16px; position:relative; }

  .url-row{ display:flex; flex-wrap:wrap; align-items:center; gap:6px; }
  .seg{
    border-radius:9px; padding:7px 11px; font-size:0.82rem; border:1px solid #2A2418;
    background:#0F1115; color:#A39A87; transition: all 0.35s ease; min-width:0;
  }
  .seg .k{ font-size:0.62rem; text-transform:lowercase; color:#6B6355; display:block; margin-bottom:1px; }
  .seg .v{ font-family:'JetBrains Mono', monospace; color:#D9D2C0; word-break:break-all; }
  .seg.flagged{
    border-color:#E0344F; background:color-mix(in srgb, #E0344F 12%, #0F1115);
    box-shadow:0 0 14px -4px #E0344F88;
  }
  .seg.flagged .v{ color:#E8B4BE; }
  .seg.clean{ border-color:#2FE0A855; }
  .seg.scheme{ flex:0 0 auto; opacity:0.75; }
  .seg.path{ flex:1 1 160px; }

  .pills{ display:flex; flex-wrap:wrap; gap:7px; }
  .pill{
    display:flex; align-items:center; gap:6px; padding:5px 10px 5px 8px; border-radius:999px;
    border:1px solid #2A2418; background:#0F1115; font-size:0.72rem; color:#6B6355;
    transition: all 0.3s ease; cursor:default;
  }
  .pill .dot{ width:7px; height:7px; border-radius:50%; background:#3A3020; flex-shrink:0; transition: all 0.3s ease; }
  .pill.on{ border-color:#E0344F; color:#E8B4BE; background:color-mix(in srgb, #E0344F 10%, #0F1115); }
  .pill.on .dot{ background:#E0344F; box-shadow:0 0 6px 1px #E0344F99; animation: pill-pulse 1.6s ease-in-out infinite; }
  @keyframes pill-pulse{ 0%,100%{ opacity:1 } 50%{ opacity:0.55 } }

  .imp-row{ display:flex; align-items:center; gap:10px; font-size:0.78rem; }
  .imp-chip{ border-radius:9px; padding:6px 11px; border:1px solid #2A2418; background:#0F1115; }
  .imp-chip .k{ font-size:0.62rem; color:#6B6355; display:block; }
  .imp-chip.bad{ border-color:#FFA940; background:color-mix(in srgb, #FFA940 10%, #0F1115); color:#F0D9A6; }
  .imp-chip.real{ color:#D9D2C0; }
  .imp-arrow{ color:#FFA940; font-size:1rem; }

  .right{
    flex:0 0 150px; display:flex; flex-direction:column; align-items:center; justify-content:center;
    gap:8px; position:relative;
  }
  .ring-wrap{ position:relative; width:112px; height:112px; }
  .ring-wrap svg{ transform:rotate(-90deg); width:112px; height:112px; }
  .ring-bg{ fill:none; stroke:#211C12; stroke-width:6; }
  .ring-fg{ fill:none; stroke:var(--vc,#2FE0A8); stroke-width:6; stroke-linecap:round;
            stroke-dasharray:301; stroke-dashoffset:301; opacity:0;
            transition: stroke-dashoffset 0.9s cubic-bezier(.3,.6,.3,1), opacity 0.3s ease; }
  .stamp{
    position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center;
    gap:2px; transform:scale(0.4); opacity:0; transition: transform 0.45s cubic-bezier(.3,1.4,.4,1), opacity 0.3s ease;
  }
  .stamp.show{ transform:scale(1); opacity:1; }
  .stamp svg{ width:30px; height:30px; }
  .stamp .word{ font-size:0.74rem; font-weight:600; letter-spacing:0.02em; }
  .conf{ font-size:0.72rem; color:#A39A87; }
  .conf .n{ font-family:'JetBrains Mono', monospace; color:#D9D2C0; font-weight:600; }

  .placeholder{ color:#6B6355; font-size:0.82rem; text-align:center; }

  @media (max-width:560px){
    .console{ flex-direction:column; }
    .right{ flex:0 0 auto; }
  }
  @media (prefers-reduced-motion: reduce){
    .stamp, .ring-fg, .pill, .seg{ transition-duration:0.01s !important; }
  }
</style>

<div class="console">
  <div class="left">
    <div class="url-row" id="urlRow"></div>
    <div class="pills" id="pills"></div>
    <div class="imp-row" id="impRow" style="display:none;"></div>
  </div>
  <div class="right">
    <div class="ring-wrap">
      <svg viewBox="0 0 112 112">
        <circle class="ring-bg" cx="56" cy="56" r="48"></circle>
        <circle class="ring-fg" id="ring" cx="56" cy="56" r="48"></circle>
      </svg>
      <div class="stamp" id="stamp">
        <svg id="stampIcon" viewBox="0 0 24 24" fill="none" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"></svg>
        <div class="word display" id="stampWord"></div>
      </div>
      <div class="placeholder" id="placeholder" style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;padding:0 14px;">paste a url above</div>
    </div>
    <div class="conf" id="confLine" style="visibility:hidden;">confidence <span class="n" id="confN">0%</span></div>
  </div>
</div>

<script>
(function(){
  const data = __PAYLOAD_JSON__;
  const urlRow = document.getElementById('urlRow');
  const pillsEl = document.getElementById('pills');
  const impRow = document.getElementById('impRow');
  const ring = document.getElementById('ring');
  const stamp = document.getElementById('stamp');
  const stampIcon = document.getElementById('stampIcon');
  const stampWord = document.getElementById('stampWord');
  const placeholder = document.getElementById('placeholder');
  const confLine = document.getElementById('confLine');
  const confN = document.getElementById('confN');

  function seg(kind, label, value, cls){
    const d = document.createElement('div');
    d.className = 'seg ' + cls + (kind === 'scheme' ? ' scheme' : kind === 'path' ? ' path' : '');
    const k = document.createElement('span'); k.className = 'k'; k.textContent = label;
    const v = document.createElement('span'); v.className = 'v'; v.textContent = value;
    d.appendChild(k); d.appendChild(v);
    return d;
  }

  if (!data.hasResult) {
    urlRow.appendChild(seg('scheme', 'scheme', '—', 'clean'));
    urlRow.appendChild(seg('host', 'address', 'waiting for a url', 'clean'));
  } else {
    urlRow.appendChild(seg('scheme', 'scheme', data.scheme || '(none)', 'clean'));
    urlRow.appendChild(seg('host', data.isIp ? 'ip address' : 'address', data.host || '(none)', data.hostFlagged ? 'flagged' : 'clean'));
    if (data.path) urlRow.appendChild(seg('path', 'path', data.path + (data.query ? ('?' + data.query) : ''), data.pathFlagged ? 'flagged' : 'clean'));
  }

  (data.pills || []).forEach(p => {
    const el = document.createElement('div');
    el.className = 'pill' + (p.on ? ' on' : '');
    el.title = p.why || '';
    const dot = document.createElement('span'); dot.className = 'dot';
    const label = document.createElement('span'); label.textContent = p.label;
    el.appendChild(dot); el.appendChild(label);
    pillsEl.appendChild(el);
  });

  if (data.impersonation) {
    impRow.style.display = 'flex';
    const claims = document.createElement('div'); claims.className = 'imp-chip bad';
    claims.innerHTML = '<span class="k">claims to be</span>';
    const claimsV = document.createElement('span'); claimsV.textContent = data.impersonation.brand; claims.appendChild(claimsV);
    const arrow = document.createElement('span'); arrow.className = 'imp-arrow'; arrow.textContent = '≠';
    const real = document.createElement('div'); real.className = 'imp-chip real';
    real.innerHTML = '<span class="k">actually</span>';
    const realV = document.createElement('span'); realV.textContent = data.impersonation.registered_domain; real.appendChild(realV);
    impRow.appendChild(claims); impRow.appendChild(arrow); impRow.appendChild(real);
  }

  if (data.hasResult) {
    placeholder.style.display = 'none';
    confLine.style.visibility = 'visible';
    const malicious = data.isMalicious;
    const color = malicious ? '#E0344F' : '#2FE0A8';
    ring.style.setProperty('--vc', color);
    ring.style.stroke = color;
    stampWord.style.color = color;
    stampIcon.setAttribute('stroke', color);
    stampWord.textContent = malicious ? 'PHISHING' : 'SAFE';
    stampIcon.innerHTML = malicious
      ? '<path d="M18 6 6 18M6 6l12 12"/>'
      : '<path d="M20 6 9 17l-5-5"/>';

    const pct = Math.max(0, Math.min(1, data.confidence));
    setTimeout(() => {
      ring.style.opacity = '1';
      ring.style.strokeDashoffset = (301 * (1 - pct)).toFixed(1);
      stamp.classList.add('show');
      let shown = 0;
      const target = Math.round(pct * 100);
      const start = performance.now(), dur = 700;
      function step(t){
        const p = Math.min(1, (t - start) / dur);
        const val = Math.round(target * (1 - Math.pow(1 - p, 3)));
        if (val !== shown) { shown = val; confN.textContent = val + '%'; }
        if (p < 1) requestAnimationFrame(step);
      }
      requestAnimationFrame(step);
    }, 120);
  }
})();
</script>
"""


def _render_scan(result: dict | None, checked_url: str | None) -> None:
    payload = {"hasResult": False}
    if result:
        parts = result["url_parts"]
        fr = result["feature_row"]
        imp = result.get("impersonation")
        host_flagged = bool(fr.get("has_ip_address") or fr.get("is_url_shortener") or fr.get("has_at_symbol") or imp)
        path_flagged = bool(fr.get("has_https_token_in_path") or fr.get("has_double_slash_redirect"))
        host_display = parts.get("hostname") or "(none)"
        if not parts.get("is_ip_based"):
            sub = parts.get("subdomain")
            domain = f'{parts.get("registered_domain", "")}.{parts["tld"]}' if parts.get("tld") else parts.get("registered_domain", "")
            host_display = f"{sub}.{domain}" if sub else domain

        payload = {
            "hasResult": True,
            "scheme": parts.get("scheme"),
            "host": host_display,
            "isIp": bool(parts.get("is_ip_based")),
            "hostFlagged": host_flagged,
            "path": parts.get("path") or "",
            "query": parts.get("query") or "",
            "pathFlagged": path_flagged,
            "pills": [
                {"label": _FEATURE_EXPLAIN[f]["pill"], "on": bool(fr.get(f)), "why": _FEATURE_EXPLAIN[f]["title"]}
                for f in _PILL_ORDER
            ],
            "impersonation": (
                {"brand": imp["brand"].title(), "registered_domain": imp["registered_domain"]} if imp else None
            ),
            "isMalicious": bool(result["is_malicious"]),
            "confidence": float(result["confidence"]),
        }
    else:
        payload["pills"] = [{"label": _FEATURE_EXPLAIN[f]["pill"], "on": False, "why": _FEATURE_EXPLAIN[f]["title"]} for f in _PILL_ORDER]

    html = _SCAN_TEMPLATE.replace("__PAYLOAD_JSON__", json.dumps(payload))
    # Generous enough to cover the wrapped (narrow-viewport) layout, where the
    # right-hand ring column drops below the left column and the pill row can
    # wrap to 2-3 lines — a little extra whitespace on a wide desktop view is
    # a smaller cost than clipped content on a phone.
    components.html(html, height=400 if not (result and result.get("impersonation")) else 460, scrolling=False)


st.session_state.setdefault("phish_ledger", [])


def _ledger_log(checked_url: str, label: str, confidence: float, impersonation: dict | None) -> None:
    display_url = checked_url if len(checked_url) <= 55 else checked_url[:52] + "..."
    st.session_state["phish_ledger"].insert(0, {
        "Time": datetime.now().strftime("%H:%M:%S"),
        "URL": display_url,
        "Verdict": "🚨 malicious" if label == "malicious" else "✅ benign",
        "Confidence": f"{confidence:.0%}",
        "Impersonates": impersonation["brand"].title() if impersonation else "—",
    })


def _check_url(checked_url: str) -> dict | None:
    resp = api_post("/phishing/check", json_body={"url": checked_url})
    if resp.status_code != 200:
        st.error(f"Check failed: {resp.text}")
        return None
    result = resp.json()
    _ledger_log(checked_url, result["label"], result["confidence"], result.get("impersonation"))
    return result


c1, c2 = st.columns([3, 1])
with c2:
    st.write("")
    st.write("")
    if st.button("Try benign example", use_container_width=True):
        st.session_state["phish_url_input"] = samples.get("benign_example", {}).get("url", "")
        st.rerun()
    if st.button("Try phishing example", use_container_width=True):
        st.session_state["phish_url_input"] = samples.get("phishing_example", {}).get("url", "")
        st.rerun()
with c1:
    url = st.text_input("Enter a URL to check", placeholder="https://example.com/login", key="phish_url_input")

if st.button("🔍 Check URL", type="primary") and url:
    with st.spinner("Scanning..."):
        result = _check_url(url)
    if result:
        st.session_state["phish_last_result"] = result
        st.session_state["phish_last_url"] = url

_last_result = st.session_state.get("phish_last_result")
_last_url = st.session_state.get("phish_last_url")
_render_scan(_last_result, _last_url)

if _last_result:
    with st.expander("Why the model decided this (SHAP)", expanded=False):
        _render_shap_chart(_last_result["explanation"])
        for item in _last_result["explanation"]:
            info = _FEATURE_EXPLAIN.get(item["feature"])
            if not info:
                continue
            direction = "pushed toward **phishing**" if item["impact"] > 0 else "pushed toward **benign**"
            st.markdown(f"- **{info['title']}** (value: `{item['value']}`) — {direction}. {info['why']}")

    report_lines = [
        "SENTINELAI PHISHING & MALICIOUS URL CHECK — REPORT",
        "=" * 55,
        f"URL:         {_last_url}",
        f"Checked at:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Verdict:     {'PHISHING / MALICIOUS' if _last_result['is_malicious'] else 'BENIGN'}",
        f"Confidence:  {_last_result['confidence']:.0%}",
        "",
    ]
    imp = _last_result.get("impersonation")
    if imp:
        report_lines += [
            f"Brand impersonation flag: resembles {imp['brand'].title()}, but registered domain is "
            f"'{imp['registered_domain']}' (separate rule-based check, not part of the ML model's decision).",
            "",
        ]
    report_lines.append("Top contributing features (SHAP):")
    for item in _last_result["explanation"]:
        info = _FEATURE_EXPLAIN.get(item["feature"], {})
        direction = "toward phishing" if item["impact"] > 0 else "toward benign"
        report_lines.append(f"  - {info.get('title', item['feature'])} (value: {item['value']}) — {direction}")

    st.download_button(
        "⬇️ Download Check Report (.txt)",
        data="\n".join(report_lines),
        file_name="phishing_check_report.txt",
        mime="text/plain",
    )
    st.caption("This event has been recorded in the unified Alert feed on the Home page.")

st.divider()
with st.expander(f"🗂️ Session Check History — {len(st.session_state['phish_ledger'])} check(s) this session", expanded=False):
    if st.session_state["phish_ledger"]:
        st.dataframe(st.session_state["phish_ledger"], hide_index=True, use_container_width=True)
        if st.button("🧹 Clear History"):
            st.session_state["phish_ledger"] = []
            st.rerun()
    else:
        st.caption("No URLs checked yet this session — check one above.")

with st.expander("ℹ️ How this works / limitations"):
    st.markdown("""
    - Features are purely **lexical/structural** (URL length, special characters, suspicious
      keywords, IP-address hosts, URL shorteners, etc.) — computed instantly, no DNS/WHOIS lookups.
    - Trained on ~340K labeled URLs (public dataset), with additional legitimate bare-domain
      examples added to correct a blind spot found during testing (see project report).
    - The **brand-impersonation check** (flagging e.g. "paypal" in a hostname that isn't paypal.com)
      is a separate, rule-based heuristic layered on top for interpretability — it is **not** part of
      the trained model's decision, and is disclosed as such wherever it appears.
    - Known limitation: generic keyword matching (e.g. "security") can occasionally flag
      legitimate pages that happen to contain those words — this is disclosed in the project report.
    """)
