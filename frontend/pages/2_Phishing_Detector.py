"""Phishing & Malicious URL Detector page."""
import html
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

from _backend_bootstrap import ensure_backend
from api_client import api_get, api_post, require_login

st.set_page_config(page_title="Phishing Detector — SentinelAI", page_icon="🎣", layout="wide")
ensure_backend()
require_login()

st.title("🎣 Phishing & Malicious URL Detector")
st.caption("Classifies a URL using lexical/structural features — no network calls, works instantly on any URL.")

status = api_get("/phishing/status").json()
if not status.get("model_loaded"):
    st.error("Model not loaded on the backend yet.")
    st.stop()

samples = api_get("/phishing/sample-requests").json()

# Plain-English gloss for every feature the model sees. Used two ways below:
# the 6 boolean ones drive the Red Flags Checklist directly; all of them are
# available to explain whichever features the SHAP chart surfaces as top
# contributors for a given URL (which can include the continuous ones).
_FEATURE_EXPLAIN = {
    "has_ip_address": {
        "title": "Uses a raw IP address instead of a domain",
        "why": "Legitimate sites almost always have a registered domain name. A URL pointing "
               "straight at an IP address (e.g. http://192.168.1.1/login) is a strong red flag.",
    },
    "has_at_symbol": {
        "title": "Contains an \"@\" symbol",
        "why": "Browsers ignore everything before an \"@\" in a URL's authority section — attackers "
               "abuse this to show a trusted-looking prefix while the real destination is hidden after it.",
    },
    "has_https_token_in_path": {
        "title": "The word \"https\" appears in the path, not the scheme",
        "why": "Putting the literal word \"https\" inside the path or query (not as the actual scheme) "
               "is a trick to make a link look secure at a glance when it isn't.",
    },
    "has_suspicious_keyword": {
        "title": "Contains a high-risk keyword",
        "why": "Words like \"login\", \"verify\", \"secure\", \"account\", or \"bank\" are common phishing "
               "bait, designed to create urgency or impersonate an account-security notice.",
    },
    "is_url_shortener": {
        "title": "Uses a URL-shortener domain",
        "why": "Shorteners (bit.ly, tinyurl.com, ...) hide the real destination entirely until you click — "
               "legitimate and malicious links both use them, but it removes your ability to pre-screen the link.",
    },
    "has_double_slash_redirect": {
        "title": "Has an extra \"//\" later in the URL",
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

_CHECKLIST_FEATURES = [
    "has_ip_address", "has_at_symbol", "has_https_token_in_path",
    "has_suspicious_keyword", "is_url_shortener", "has_double_slash_redirect",
]


def _render_shap_chart(explanation: list[dict]) -> None:
    exp_df = pd.DataFrame(explanation)
    exp_df["direction"] = exp_df["impact"].apply(lambda x: "Pushes toward phishing" if x > 0 else "Pushes toward benign")
    fig = px.bar(
        exp_df.sort_values("impact"), x="impact", y="feature", orientation="h",
        color="direction", color_discrete_map={"Pushes toward phishing": "#D64545", "Pushes toward benign": "#4A90D9"},
    )
    fig.update_layout(height=280, yaxis_title="", xaxis_title="SHAP impact", margin=dict(t=10, b=10))
    st.plotly_chart(fig, use_container_width=True)


def _render_url_anatomy(parts: dict, impersonation: dict | None) -> None:
    # Every value here comes from parsing a URL the user typed in, and this
    # is rendered via unsafe_allow_html — so every value MUST be HTML-escaped
    # before interpolation. Without this, a URL whose path/query happens to
    # contain "<script>..." or similar would execute as real HTML on this
    # page (a self-XSS, reflected into the user's own session) — exactly the
    # kind of bug a security-education project shouldn't ship with.
    def chip(label: str, value: str, bg: str = "#2d3748", border: str = "#4a5568") -> str:
        safe_value = html.escape(str(value))
        return (
            f'<span style="background:{bg};border:1px solid {border};border-radius:6px;'
            f'padding:3px 10px;margin:2px 4px 2px 0;display:inline-block;font-family:monospace;'
            f'font-size:0.85em;">{label}: <b>{safe_value}</b></span>'
        )

    chips = [chip("scheme", parts.get("scheme") or "(none)")]
    if parts.get("is_ip_based"):
        chips.append(chip("host", parts.get("hostname", ""), bg="#5a3a1a", border="#d69e2e"))
    else:
        if parts.get("subdomain"):
            flagged = bool(impersonation)
            chips.append(chip(
                "subdomain", parts["subdomain"],
                bg="#5a1f1f" if flagged else "#2d3748",
                border="#e53e3e" if flagged else "#4a5568",
            ))
        domain_display = f'{parts.get("registered_domain", "")}.{parts["tld"]}' if parts.get("tld") else parts.get("registered_domain", "")
        chips.append(chip("domain", domain_display or "(none)"))
    if parts.get("path"):
        chips.append(chip("path", parts["path"]))
    if parts.get("query"):
        chips.append(chip("query", parts["query"]))

    st.markdown(" ".join(chips), unsafe_allow_html=True)

    if parts.get("is_ip_based"):
        st.caption("⚠️ This is a raw IP address, not a registered domain — legitimate sites almost never link this way.")

    if impersonation:
        st.warning(
            f"⚠️ **Looks like it's impersonating {impersonation['brand'].title()}** — the hostname contains "
            f"\"{impersonation['brand']}\", but the actual registered domain is "
            f"**{impersonation['registered_domain']}**, not {impersonation['brand']}.com. This is a separate, "
            f"rule-based check — not part of the ML model's verdict above."
        )


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
    """One-time side effect: calls the API and logs the ledger row. Kept
    separate from rendering so a later rerun (e.g. clicking the download
    button below) never re-calls the API or double-logs the ledger."""
    resp = api_post("/phishing/check", json_body={"url": checked_url})
    if resp.status_code != 200:
        st.error(f"Check failed: {resp.text}")
        return None
    result = resp.json()
    _ledger_log(checked_url, result["label"], result["confidence"], result.get("impersonation"))
    return result


def _display_result(result: dict, checked_url: str) -> None:
    """Pure rendering, no side effects — safe to call on every rerun,
    including the one triggered by clicking the download button below."""
    if result["is_malicious"]:
        st.error(f"🚨 **PHISHING / MALICIOUS** — confidence {result['confidence']:.0%}")
    else:
        st.success(f"✅ **Benign** — confidence {result['confidence']:.0%}")

    st.markdown("##### URL Anatomy")
    _render_url_anatomy(result["url_parts"], result.get("impersonation"))

    st.markdown("##### 🚩 Red Flags Checklist")
    feature_row = result["feature_row"]
    cols = st.columns(3)
    for i, feat in enumerate(_CHECKLIST_FEATURES):
        info = _FEATURE_EXPLAIN[feat]
        flagged = bool(feature_row.get(feat))
        with cols[i % 3]:
            st.markdown(f"{'🚩' if flagged else '✅'} **{info['title']}**")
            if flagged:
                st.caption(info["why"])

    st.markdown("##### Why the model decided this (SHAP)")
    _render_shap_chart(result["explanation"])
    with st.expander("What do these mean?"):
        for item in result["explanation"]:
            info = _FEATURE_EXPLAIN.get(item["feature"])
            if not info:
                continue
            direction = "pushed toward **phishing**" if item["impact"] > 0 else "pushed toward **benign**"
            st.markdown(f"- **{info['title']}** (value: `{item['value']}`) — {direction}. {info['why']}")

    report_lines = [
        "SENTINELAI PHISHING & MALICIOUS URL CHECK — REPORT",
        "=" * 55,
        f"URL:         {checked_url}",
        f"Checked at:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Verdict:     {'PHISHING / MALICIOUS' if result['is_malicious'] else 'BENIGN'}",
        f"Confidence:  {result['confidence']:.0%}",
        "",
    ]
    imp = result.get("impersonation")
    if imp:
        report_lines += [
            f"Brand impersonation flag: resembles {imp['brand'].title()}, but registered domain is "
            f"'{imp['registered_domain']}' (separate rule-based check, not part of the ML model's decision).",
            "",
        ]
    report_lines.append("Top contributing features (SHAP):")
    for item in result["explanation"]:
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
    with st.spinner("Analyzing URL..."):
        result = _check_url(url)
    if result:
        st.session_state["phish_last_result"] = result
        st.session_state["phish_last_url"] = url

if "phish_last_result" in st.session_state:
    _display_result(st.session_state["phish_last_result"], st.session_state["phish_last_url"])

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
