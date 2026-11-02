"""
Network Intrusion Detection page. Demonstrates the handbook-required
before/after narrative: show "normal" traffic pass through clean, then a
DoS-style attack flagged with an explanation.
"""
import plotly.express as px
import streamlit as st
import pandas as pd

from api_client import api_get, api_post, require_login

st.set_page_config(page_title="Network IDS — SentinelAI", page_icon="🌐", layout="wide")
require_login()

st.title("🌐 Network Intrusion Detection")
st.caption("Classifies a network connection as Normal, DoS, Probe, R2L or U2R, trained on the NSL-KDD benchmark.")

status = api_get("/network-ids/status").json()
if not status.get("model_loaded"):
    st.error("Model not loaded on the backend yet.")
    st.stop()

samples_resp = api_get("/network-ids/sample-requests")
samples = samples_resp.json() if samples_resp.status_code == 200 else {}

scenario = st.radio(
    "Load a scenario (or edit fields manually below)",
    ["Normal traffic", "DoS attack", "Custom"],
    horizontal=True,
)

defaults = {}
if scenario == "Normal traffic":
    defaults = samples.get("normal_example", {})
elif scenario == "DoS attack":
    defaults = samples.get("dos_attack_example", {})

with st.form("ids_form"):
    c1, c2, c3 = st.columns(3)
    with c1:
        protocol_type = st.selectbox("Protocol", ["tcp", "udp", "icmp"], index=0)
        service = st.text_input("Service", value=defaults.get("service", "http"))
        flag = st.text_input("Flag", value=defaults.get("flag", "SF"))
    with c2:
        src_bytes = st.number_input("Source bytes", value=float(defaults.get("src_bytes", 0)))
        dst_bytes = st.number_input("Destination bytes", value=float(defaults.get("dst_bytes", 0)))
        count = st.number_input("Count (connections to same host)", value=int(defaults.get("count", 1)))
    with c3:
        serror_rate = st.slider("SYN error rate", 0.0, 1.0, float(defaults.get("serror_rate", 0.0)))
        same_srv_rate = st.slider("Same-service rate", 0.0, 1.0, float(defaults.get("same_srv_rate", 1.0)))
        dst_host_count = st.number_input("Dest. host count", value=int(defaults.get("dst_host_count", 1)))

    submitted = st.form_submit_button("🔍 Classify Traffic", type="primary", use_container_width=True)

if submitted:
    payload = {
        "protocol_type": protocol_type, "service": service, "flag": flag,
        "src_bytes": src_bytes, "dst_bytes": dst_bytes, "count": count,
        "serror_rate": serror_rate, "same_srv_rate": same_srv_rate,
        "dst_host_count": dst_host_count,
    }
    with st.spinner("Running model..."):
        resp = api_post("/network-ids/predict", json_body=payload)

    if resp.status_code != 200:
        st.error(f"Prediction failed: {resp.text}")
    else:
        result = resp.json()
        if result["is_malicious"]:
            st.error(f"🚨 **{result['label'].upper()}** detected — confidence {result['confidence']:.0%}")
        else:
            st.success(f"✅ Traffic classified as **{result['label'].upper()}** — confidence {result['confidence']:.0%}")

        st.subheader("Why the model decided this (SHAP)")
        exp_df = pd.DataFrame(result["explanation"])
        exp_df["direction"] = exp_df["impact"].apply(lambda x: "Pushes toward attack" if x > 0 else "Pushes toward normal")
        fig = px.bar(
            exp_df.sort_values("impact"), x="impact", y="feature", orientation="h",
            color="direction", color_discrete_map={"Pushes toward attack": "#D64545", "Pushes toward normal": "#4A90D9"},
        )
        fig.update_layout(height=300, yaxis_title="", xaxis_title="SHAP impact")
        st.plotly_chart(fig, use_container_width=True)
        st.caption("This event has been recorded in the unified Alert feed on the Home page.")
