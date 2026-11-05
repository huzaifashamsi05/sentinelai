"""
Network Intrusion Detection page. Demonstrates the handbook-required
before/after narrative: show "normal" traffic pass through clean, then a
DoS-style attack flagged with an explanation.
"""
from datetime import datetime

import plotly.express as px
import streamlit as st
import pandas as pd

from _backend_bootstrap import ensure_backend
from api_client import api_get, api_post, is_admin, require_login
from theme import SEVERITY, inject_global_styles, intro, translate

st.set_page_config(page_title="Network IDS — SentinelAI", page_icon="🌐", layout="wide")
ensure_backend()
require_login()
inject_global_styles()

st.title("🌐 Network Intrusion Detection")
st.caption("Classifies a network connection as Normal, DoS, Probe, R2L or U2R, trained on the NSL-KDD benchmark.")

intro(
    "🛡️", "What this page actually does",
    "A real company's network logs thousands of connection attempts a day — almost all completely ordinary, "
    "but a few are the first sign of an attack: a flood of junk traffic meant to knock a service offline, "
    "someone probing for an unlocked door, or an attempt to break in outright. This page runs the same kind "
    "of classifier a Security Operations Center (SOC) relies on: it looks at a connection's characteristics "
    "and, in a split second, sorts it into <b>Normal</b> or one of four known attack patterns — then shows "
    "exactly <i>which</i> signals drove that call, not just the label. Pick a scenario below, or build your "
    "own, and watch it decide.",
)


def _render_shap_chart(explanation: list[dict], height: int = 260) -> None:
    exp_df = pd.DataFrame(explanation)
    exp_df["direction"] = exp_df["impact"].apply(lambda x: "Pushes toward attack" if x > 0 else "Pushes toward normal")
    fig = px.bar(
        exp_df.sort_values("impact"), x="impact", y="feature", orientation="h",
        color="direction", color_discrete_map={"Pushes toward attack": SEVERITY["High"], "Pushes toward normal": SEVERITY["Low"]},
    )
    fig.update_layout(
        height=height, yaxis_title="", xaxis_title="SHAP impact", margin=dict(t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font={"color": "#ECEDF2"},
        legend_title_text="",
    )
    st.plotly_chart(fig, use_container_width=True)

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
            translate(
                f"<b>In plain terms:</b> this connection's pattern matches what a "
                f"<b>{result['label'].upper()}</b> attack usually looks like, and the model is "
                f"{result['confidence']:.0%} sure of that read. A SOC analyst seeing this would investigate "
                f"immediately rather than wait for it to show up in tomorrow's log review."
            )
        else:
            st.success(f"✅ Traffic classified as **{result['label'].upper()}** — confidence {result['confidence']:.0%}")
            translate(
                f"<b>In plain terms:</b> nothing about this connection matches a known attack pattern — it "
                f"reads as ordinary traffic, and the model is {result['confidence']:.0%} confident in that call."
            )

        st.subheader("Why the model decided this (SHAP)")
        st.caption(
            "Each bar is one signal the model weighed. Longer blue bars pushed it toward **normal**; longer "
            "red bars pushed it toward **attack**. This is what makes it explainable instead of a black box."
        )
        _render_shap_chart(result["explanation"], height=300)
        st.caption("This event has been recorded in the unified Alert feed on the Home page.")

st.divider()

intro(
    "🔴", "Watching traffic as it happens",
    "This table shows real HTTP requests hitting this very app's own backend, each one classified the "
    "instant it arrives by the exact same model used above. It's a live, miniature version of what a SOC's "
    "monitoring dashboard does around the clock: catch a suspicious pattern the moment it happens, not after "
    "someone happens to notice it in a log days later.",
)

with st.expander("🔬 For the technically curious — what \"live\" really means here", expanded=False):
    st.markdown("""
- **This is HTTP-layer monitoring, not packet-layer.** A Python web app — and especially a Streamlit
  Community Cloud container — has no access to a raw network interface, so it can never capture TCP/IP
  packets the way NSL-KDD's original 1999 dataset was built (from `tcpdump` on a real network). What it
  *can* see honestly is every HTTP request that actually reaches this backend — so that's exactly what
  this watches. Nothing below is fabricated traffic.
- **`protocol_type`/`service` are literally true** (every request here really is `tcp`/`http`), not guessed.
  **`flag`** (the original dataset's raw TCP connection-state) is approximated from the HTTP status code,
  since the web framework never exposes raw TCP flags to application code.
- **`count`/`srv_count` and every rate derived from them reuse NSL-KDD's own definition** — a real rolling
  count over the last 2 seconds of real logged requests — just computed from real HTTP events instead of
  real packets. **`dst_host_*`** reuses NSL-KDD's other definition the same way, over the last 100 real
  logged requests to this host.
- Because the dashboard and backend share one container, every request shares the same loopback IP — so
  `count` effectively measures *this app's overall request rate* rather than filtering per visitor. Doesn't
  change the demonstration, just worth knowing.
- The model itself was trained on simulated 1999 packet-level traffic, not HTTP semantics — so an HTTP
  pattern that *looks* like an attack to a human (e.g. a login burst) won't always match its learned
  decision boundary the way a textbook NSL-KDD attack would. That's an honest limitation of reusing a
  packet-trained model on HTTP-layer signals, not a bug in this page.
- Like the Vulnerability Scanner, this only ever watches traffic to **this app's own backend** — never
  anything external.
""")

live_col1, live_col2, live_col3, live_col4 = st.columns([2, 1, 1, 1])
with live_col1:
    feed_limit = st.slider("Entries to show", 5, 50, 15, key="live_feed_limit")
with live_col2:
    refresh_clicked = st.button("🔄 Refresh Feed", use_container_width=True)
with live_col3:
    burst_clicked = st.button(
        "💥 Generate Demo Burst", use_container_width=True, disabled=not is_admin(),
        help="Fires a quick round of real requests at several of this backend's own endpoints — a "
             "reconnaissance/probe-style pattern — so you can watch the live classification respond. No "
             "traffic to test with? Start here. Admin only." if is_admin() else
             "Fires real demo traffic so you have something to watch below. Admin only.",
    )
with live_col4:
    clear_clicked = st.button(
        "🧹 Clear Feed", use_container_width=True, disabled=not is_admin(),
        help="Admin only." if not is_admin() else "Wipes the in-memory feed below (does not touch the Alert feed history on the Home page).",
    )

_DEMO_BURST_ENDPOINTS = [
    "/network-ids/sample-requests", "/phishing/status", "/phishing/sample-requests",
    "/malware/status", "/alerts", "/alerts/stats",
    "/vuln-scanner/targets", "/vuln-scanner/security-headers",
]

if clear_clicked and is_admin():
    api_post("/network-ids/live-feed/clear")
    st.toast("Live feed cleared.", icon="🧹")

if burst_clicked and is_admin():
    with st.spinner("Firing a quick burst across this backend's own endpoints..."):
        for ep in _DEMO_BURST_ENDPOINTS:
            try:
                api_get(ep)
            except Exception:
                pass
    st.toast("Burst sent — showing fresh classifications below.", icon="💥")

feed_resp = api_get("/network-ids/live-feed", params={"limit": feed_limit})
if feed_resp.status_code != 200:
    st.error(f"Could not load the live feed: {feed_resp.text}")
else:
    feed = feed_resp.json()

    status_col1, status_col2, status_col3 = st.columns([1, 1, 2])
    with status_col1:
        st.metric("Monitor status", "🟢 Live" if feed["monitor_enabled"] else "⏸️ Paused")
    with status_col2:
        st.metric("Requests logged", feed["total_logged"])
    with status_col3:
        if is_admin():
            pause_label = "⏸️ Pause Monitor" if feed["monitor_enabled"] else "▶️ Resume Monitor"
            if st.button(pause_label):
                api_post("/network-ids/live-feed/toggle", json_body={"enabled": not feed["monitor_enabled"]})
                st.rerun()

    items = feed["items"]
    if not items:
        st.info(
            "Nothing logged yet — no non-admin visitor has browsed the app this session. "
            + ("Click **Generate Demo Burst** above, then **Refresh Feed**, to see it in action right now."
               if is_admin() else "Ask an admin to generate a demo burst, or just browse around the app and click Refresh.")
        )
    else:
        _LABEL_EMOJI = {"normal": "✅ normal", "dos": "🔴 DoS", "probe": "🟠 probe", "r2l": "🟣 R2L", "u2r": "⚫ U2R"}

        st.caption("🔴🟠🟣⚫ rows below are the ones that look suspicious — everything else is ordinary traffic.")

        rows = []
        for item in items:
            rows.append({
                "Time": datetime.fromtimestamp(item["ts"]).strftime("%H:%M:%S"),
                "Method": item["method"],
                "Path": item["path"],
                "Status": item["status_code"],
                "Count (2s)": item["feature_row"]["count"] if item["feature_row"] else "—",
                "Classification": _LABEL_EMOJI.get(item["label"], item["label"] or "…"),
                "Confidence": f"{item['confidence']:.0%}" if item["confidence"] is not None else "—",
            })
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)

        flagged = [it for it in items if it["label"] and it["label"] != "normal"]
        if flagged:
            st.subheader(f"🔍 Flagged entries — why the model decided this ({len(flagged)})")
            st.caption(
                "Each one below didn't look like ordinary traffic. Expand it to see, in order of importance, "
                "exactly which signals pushed the model's call — the same explainability used in the form above."
            )
            for item in flagged:
                with st.expander(
                    f"{_LABEL_EMOJI.get(item['label'], item['label'])} — {item['method']} {item['path']} "
                    f"({item['status_code']}) at {datetime.fromtimestamp(item['ts']).strftime('%H:%M:%S')} "
                    f"— confidence {item['confidence']:.0%}"
                ):
                    _render_shap_chart(item["explanation"], height=220)
                    st.caption("Feature row computed for this request (pre-encoding):")
                    st.json(item["feature_row"], expanded=False)
        st.caption("Non-normal classifications above have been recorded in the unified Alert feed on the Home page.")
