"""Phishing & Malicious URL Detector page."""
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

c1, c2 = st.columns([3, 1])
with c1:
    url = st.text_input("Enter a URL to check", placeholder="https://example.com/login")
with c2:
    st.write("")
    st.write("")
    if st.button("Try benign example"):
        url = samples.get("benign_example", {}).get("url", "")
        st.session_state["_url_prefill"] = url
    if st.button("Try phishing example"):
        url = samples.get("phishing_example", {}).get("url", "")
        st.session_state["_url_prefill"] = url

if "_url_prefill" in st.session_state and not url:
    url = st.session_state["_url_prefill"]

if st.button("🔍 Check URL", type="primary") and url:
    with st.spinner("Analyzing URL..."):
        resp = api_post("/phishing/check", json_body={"url": url})

    if resp.status_code != 200:
        st.error(f"Check failed: {resp.text}")
    else:
        result = resp.json()
        if result["is_malicious"]:
            st.error(f"🚨 **PHISHING / MALICIOUS** — confidence {result['confidence']:.0%}")
        else:
            st.success(f"✅ **Benign** — confidence {result['confidence']:.0%}")

        st.subheader("Why the model decided this (SHAP)")
        exp_df = pd.DataFrame(result["explanation"])
        exp_df["direction"] = exp_df["impact"].apply(lambda x: "Pushes toward phishing" if x > 0 else "Pushes toward benign")
        fig = px.bar(
            exp_df.sort_values("impact"), x="impact", y="feature", orientation="h",
            color="direction", color_discrete_map={"Pushes toward phishing": "#D64545", "Pushes toward benign": "#4A90D9"},
        )
        fig.update_layout(height=300, yaxis_title="", xaxis_title="SHAP impact")
        st.plotly_chart(fig, use_container_width=True)
        st.caption("This event has been recorded in the unified Alert feed on the Home page.")

with st.expander("ℹ️ How this works / limitations"):
    st.markdown("""
    - Features are purely **lexical/structural** (URL length, special characters, suspicious
      keywords, IP-address hosts, URL shorteners, etc.) — computed instantly, no DNS/WHOIS lookups.
    - Trained on ~340K labeled URLs (public dataset), with additional legitimate bare-domain
      examples added to correct a blind spot found during testing (see project report).
    - Known limitation: generic keyword matching (e.g. "security") can occasionally flag
      legitimate pages that happen to contain those words — this is disclosed in the project report.
    """)
