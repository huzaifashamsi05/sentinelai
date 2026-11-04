"""
SentinelAI Unified Dashboard — entry point.
Login/registration, then a command-center overview of all five modules:
platform risk index, activity timeline, per-module health, top risk
signals, the live alert feed, and the PDF report generator.
"""
from datetime import datetime, timezone

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from _backend_bootstrap import ensure_backend
from api_client import api_get, api_post, is_admin, is_logged_in, login, logout, register

st.set_page_config(page_title="SentinelAI", page_icon="🛡️", layout="wide")
ensure_backend()

SEVERITY_COLOR = {"High": "#D64545", "Medium": "#E0A030", "Low": "#4A90D9"}
MODULE_ICON = {
    "Network IDS": "🌐",
    "Phishing Detector": "🎣",
    "Malware Scanner": "🦠",
    "Vulnerability Scanner": "🔍",
    "Secure Vault": "🔐",
}
MODULE_ORDER = list(MODULE_ICON.keys())
RISK_WEIGHT = {"High": 10, "Medium": 5, "Low": 2}


def login_screen():
    st.markdown(
        """<div style="text-align:center;padding:36px 0 8px 0;">
<div style="font-size:3rem;line-height:1;">🛡️</div>
<div style="font-size:2.1rem;font-weight:800;color:#e8eaed;margin-top:6px;">SentinelAI</div>
<div style="color:#9aa0a6;font-size:1rem;margin-top:4px;">AI-Powered Security Operations Platform</div>
</div>""",
        unsafe_allow_html=True,
    )

    col_l, col_mid, col_r = st.columns([1, 1.3, 1])
    with col_mid:
        st.markdown(
            """<div style="border:1px solid #2a2d35;border-radius:14px;padding:22px 26px 10px 26px;
background:linear-gradient(160deg,#171a21,#12161c);">""",
            unsafe_allow_html=True,
        )
        tab_login, tab_register = st.tabs(["Log in", "Register"])

        with tab_login:
            with st.form("login_form"):
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                submitted = st.form_submit_button("Log in", use_container_width=True)
            if submitted:
                ok, msg = login(username, password)
                if ok:
                    st.success(f"Welcome, {username}.")
                    st.rerun()
                else:
                    st.error(msg)

        with tab_register:
            with st.form("register_form"):
                new_username = st.text_input("Choose a username")
                new_password = st.text_input("Choose a password (min 8 chars)", type="password")
                role = st.selectbox("Role", ["analyst", "admin"])
                reg_submitted = st.form_submit_button("Create account", use_container_width=True)
            if reg_submitted:
                ok, msg = register(new_username, new_password, role)
                if ok:
                    st.success("Account created — switch to the Log in tab.")
                else:
                    st.error(msg)
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown(
            """<div style="display:flex;justify-content:center;gap:10px;flex-wrap:wrap;margin-top:18px;">
<span style="background:#1a1d2355;border:1px solid #2a2d35;border-radius:999px;padding:5px 14px;font-size:0.8rem;color:#9aa0a6;">🌐 Network IDS</span>
<span style="background:#1a1d2355;border:1px solid #2a2d35;border-radius:999px;padding:5px 14px;font-size:0.8rem;color:#9aa0a6;">🎣 Phishing Detector</span>
<span style="background:#1a1d2355;border:1px solid #2a2d35;border-radius:999px;padding:5px 14px;font-size:0.8rem;color:#9aa0a6;">🦠 Malware Scanner</span>
<span style="background:#1a1d2355;border:1px solid #2a2d35;border-radius:999px;padding:5px 14px;font-size:0.8rem;color:#9aa0a6;">🔍 Vulnerability Scanner</span>
<span style="background:#1a1d2355;border:1px solid #2a2d35;border-radius:999px;padding:5px 14px;font-size:0.8rem;color:#9aa0a6;">🔐 Secure Vault</span>
</div>""",
            unsafe_allow_html=True,
        )


def _relative_time(ts: pd.Timestamp) -> str:
    age = pd.Timestamp.now(tz="UTC") - ts
    secs = age.total_seconds()
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{int(secs // 60)}m ago"
    if secs < 86400:
        return f"{int(secs // 3600)}h ago"
    return f"{int(secs // 86400)}d ago"


def _metric_card(icon: str, label: str, value, color: str):
    st.markdown(
        f"""<div style="border:1px solid {color}40;border-radius:12px;padding:16px 18px;
background:linear-gradient(135deg,{color}16,#12161c);height:100%;">
<div style="font-size:1.4rem;">{icon}</div>
<div style="font-size:1.8rem;font-weight:800;color:{color};margin-top:6px;">{value}</div>
<div style="font-size:0.8rem;color:#9aa0a6;margin-top:2px;">{label}</div>
</div>""",
        unsafe_allow_html=True,
    )


def _compute_risk_index(df: pd.DataFrame) -> tuple[int, dict]:
    """Transparent 0-100 platform risk index — NOT a certified audit score.
    Every malicious event across all five modules costs points, weighted by
    severity and the model's own confidence, with older events discounted
    (a resolved issue from three weeks ago shouldn't permanently scar the
    score the way something flagged an hour ago should)."""
    breakdown = {"High": 0, "Medium": 0, "Low": 0}
    if df.empty:
        return 100, breakdown
    malicious = df[df["is_malicious"] == True]  # noqa: E712
    if malicious.empty:
        return 100, breakdown
    now = pd.Timestamp.now(tz="UTC")
    penalty = 0.0
    for _, row in malicious.iterrows():
        age_days = (now - row["created_at"]).total_seconds() / 86400
        recency = 1.0 if age_days <= 7 else (0.6 if age_days <= 30 else 0.3)
        conf = row["confidence"] if pd.notna(row["confidence"]) else 0.75
        weight = RISK_WEIGHT.get(row["severity"], 2)
        penalty += weight * conf * recency
        breakdown[row["severity"]] = breakdown.get(row["severity"], 0) + 1
    score = max(0, round(100 - penalty))
    return score, breakdown


def _risk_band(score: int) -> tuple[str, str]:
    if score >= 90:
        return "#2ecc71", "Excellent"
    if score >= 75:
        return "#8ec63f", "Good"
    if score >= 50:
        return "#f1c40f", "Fair"
    if score >= 25:
        return "#f39c12", "At Risk"
    return "#e74c3c", "Critical"


def _hex_to_rgba(hex_color: str, alpha: float) -> str:
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"


def _risk_gauge(score: int, color: str):
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"font": {"size": 38, "color": color}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "#555", "tickfont": {"color": "#9aa0a6"}},
                "bar": {"color": color},
                "bgcolor": "#1a1d23",
                "borderwidth": 0,
                "steps": [
                    {"range": [0, 25], "color": _hex_to_rgba("#e74c3c", 0.2)},
                    {"range": [25, 50], "color": _hex_to_rgba("#f39c12", 0.2)},
                    {"range": [50, 75], "color": _hex_to_rgba("#f1c40f", 0.2)},
                    {"range": [75, 90], "color": _hex_to_rgba("#8ec63f", 0.2)},
                    {"range": [90, 100], "color": _hex_to_rgba("#2ecc71", 0.2)},
                ],
            },
        )
    )
    fig.update_layout(
        height=210, margin=dict(l=20, r=20, t=20, b=10),
        paper_bgcolor="rgba(0,0,0,0)", font={"color": "#e8eaed"},
    )
    return fig


def _module_health_strip(df: pd.DataFrame):
    now = pd.Timestamp.now(tz="UTC")
    cols = st.columns(5)
    for i, mod in enumerate(MODULE_ORDER):
        mod_df = df[df["module"] == mod]
        total = len(mod_df)
        if total:
            last_ts = mod_df["created_at"].max()
            last_str = _relative_time(last_ts)
            recent = (now - last_ts).total_seconds() < 86400
            has_high_malicious = (
                (mod_df["is_malicious"] == True) & (mod_df["severity"] == "High")  # noqa: E712
            ).any()
            accent = "#e74c3c" if has_high_malicious else ("#2ecc71" if recent else "#6c7580")
        else:
            last_str = "No activity yet"
            accent = "#3a3f47"
        with cols[i]:
            st.markdown(
                f"""<div style="border:1px solid {accent}50;border-radius:12px;padding:14px 10px;
background:linear-gradient(160deg,{accent}14,#12161c);text-align:center;min-height:132px;">
<div style="font-size:1.5rem;">{MODULE_ICON[mod]}</div>
<div style="font-weight:700;font-size:0.78rem;color:#e8eaed;margin-top:4px;line-height:1.2;">{mod}</div>
<div style="font-size:1.4rem;font-weight:800;color:{accent};margin-top:6px;">{total}</div>
<div style="font-size:0.7rem;color:#9aa0a6;">events · {last_str}</div>
</div>""",
                unsafe_allow_html=True,
            )


def _activity_timeline(df: pd.DataFrame):
    if df.empty:
        st.info("No events yet — activity will appear here once a module logs something.")
        return
    span = df["created_at"].max() - df["created_at"].min()
    if span >= pd.Timedelta(days=2):
        freq, fmt = "D", "%b %d"
    elif span >= pd.Timedelta(hours=3):
        freq, fmt = "h", "%b %d, %H:00"
    elif span >= pd.Timedelta(minutes=10):
        freq, fmt = "min", "%H:%M"
    else:
        freq, fmt = "s", "%H:%M:%S"
    work = df.copy()
    work["bucket"] = work["created_at"].dt.floor(freq)
    grouped = work.groupby(["bucket", "module"]).size().reset_index(name="count")
    # A categorical (string-label) x-axis renders robustly whether the data
    # spans months or clusters inside a single minute — a continuous
    # datetime axis degenerates into meaningless sub-second tick labels
    # when every event falls in (or near) the same bucket.
    grouped["label"] = grouped["bucket"].dt.strftime(fmt)
    label_order = grouped.sort_values("bucket")["label"].unique().tolist()
    fig = px.bar(
        grouped, x="label", y="count", color="module",
        category_orders={"label": label_order},
        color_discrete_sequence=["#4A90D9", "#E0A030", "#9b59b6", "#2ecc71", "#D64545"],
    )
    fig.update_layout(
        height=300, legend_title_text="", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        xaxis_title="", yaxis_title="Events", font={"color": "#e8eaed"}, barmode="stack",
        margin=dict(l=10, r=10, t=10, b=10),
    )
    st.plotly_chart(fig, use_container_width=True)


def _top_risk_signals(df: pd.DataFrame, n: int = 5):
    malicious = df[df["is_malicious"] == True].copy()  # noqa: E712
    if malicious.empty:
        st.success("✅ No malicious events flagged across any module right now.")
        return
    sev_rank = {"High": 0, "Medium": 1, "Low": 2}
    malicious["_sev_rank"] = malicious["severity"].map(sev_rank).fillna(3)
    malicious["_conf_fill"] = malicious["confidence"].fillna(0)
    top = malicious.sort_values(
        ["_sev_rank", "_conf_fill", "created_at"], ascending=[True, False, False]
    ).head(n)
    for _, row in top.iterrows():
        color = SEVERITY_COLOR.get(row["severity"], "#9aa0a6")
        conf_str = f"{row['confidence'] * 100:.0f}%" if pd.notna(row["confidence"]) else "—"
        icon = MODULE_ICON.get(row["module"], "🛡️")
        st.markdown(
            f"""<div style="display:flex;align-items:center;gap:14px;border:1px solid {color}55;
border-radius:10px;padding:11px 16px;background:linear-gradient(135deg,{color}14,#12161c);margin-bottom:8px;">
<div style="font-size:1.25rem;">{icon}</div>
<div style="flex:1;min-width:0;">
<div style="font-weight:700;color:#e8eaed;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{row['title']}</div>
<div style="font-size:0.76rem;color:#9aa0a6;margin-top:2px;">{row['module']} · {_relative_time(row['created_at'])}</div>
</div>
<div style="text-align:right;flex-shrink:0;">
<span style="background:{color}22;color:{color};border:1px solid {color}55;border-radius:999px;padding:3px 10px;font-size:0.76rem;">{row['severity']}</span>
<div style="font-size:0.74rem;color:#9aa0a6;margin-top:4px;">{conf_str} confidence</div>
</div>
</div>""",
            unsafe_allow_html=True,
        )


def overview_screen():
    st.markdown(
        """<div style="padding:4px 0 10px 0;">
<span style="font-size:2rem;">🛡️</span>
<span style="font-size:1.9rem;font-weight:800;color:#e8eaed;"> SentinelAI — Security Overview</span>
</div>""",
        unsafe_allow_html=True,
    )
    with st.sidebar:
        st.markdown(
            f"""<div style="border:1px solid #2a2d35;border-radius:10px;padding:12px 14px;background:#171a21;">
<div style="font-size:0.78rem;color:#9aa0a6;">LOGGED IN AS</div>
<div style="font-weight:700;color:#e8eaed;font-size:1rem;">{st.session_state.get('username')}</div>
<div style="font-size:0.78rem;color:#9aa0a6;margin-top:4px;">Role: {st.session_state.get('role')}</div>
</div>""",
            unsafe_allow_html=True,
        )
        st.write("")
        if st.button("Log out", use_container_width=True):
            logout()
            st.rerun()

    stats_resp = api_get("/alerts/stats")
    if stats_resp.status_code != 200:
        st.error("Could not load stats from backend.")
        return
    stats = stats_resp.json()

    # One fetch of recent alert history powers the risk index, timeline,
    # module health, top risk signals, and the live feed table below —
    # avoids re-querying the backend once per widget.
    history_resp = api_get("/alerts", params={"limit": 1000})
    df = pd.DataFrame(history_resp.json()) if history_resp.status_code == 200 else pd.DataFrame()
    if not df.empty:
        df["created_at"] = pd.to_datetime(df["created_at"], utc=True)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        _metric_card("📊", "Total Events", stats.get("total_events", 0), "#4A90D9")
    with col2:
        _metric_card("🚨", "Malicious / High-Risk", stats.get("malicious_events", 0), "#D64545")
    with col3:
        _metric_card("🧩", "Modules Reporting", len(stats.get("by_module", {})), "#2ecc71")
    with col4:
        high_count = stats.get("by_severity", {}).get("High", 0)
        _metric_card("⚠️", "High-Severity Alerts", high_count, "#E0A030")

    st.divider()

    st.subheader("🎯 Platform Risk Index")
    score, breakdown = _compute_risk_index(df)
    band_color, band_label = _risk_band(score)
    g1, g2 = st.columns([1, 2])
    with g1:
        st.plotly_chart(_risk_gauge(score, band_color), use_container_width=True)
    with g2:
        st.markdown(
            f"""<div style="padding-top:18px;">
<span style="font-size:1.6rem;font-weight:800;color:{band_color};">{band_label}</span>
<span style="color:#9aa0a6;"> — {score}/100</span>
</div>""",
            unsafe_allow_html=True,
        )
        st.caption(
            f"Factors in {breakdown['High']} High, {breakdown['Medium']} Medium and {breakdown['Low']} Low "
            "malicious events from the last 1,000 logged, weighted by the detecting model's own confidence. "
            "Events older than 7 days count for less, and anything past 30 days barely moves the score — "
            "a resolved issue from weeks ago shouldn't permanently scar it the way a fresh one should. "
            "This is a transparent heuristic across all five modules, not a certified security audit."
        )

    st.divider()

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Events by Module")
        by_module = stats.get("by_module", {})
        if by_module:
            mdf = pd.DataFrame({"Module": list(by_module.keys()), "Events": list(by_module.values())})
            fig = px.bar(mdf, x="Module", y="Events", color="Module")
            fig.update_layout(showlegend=False, height=320, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No events yet — try a module from the sidebar.")

    with c2:
        st.subheader("Events by Severity")
        by_severity = stats.get("by_severity", {})
        if by_severity:
            sdf = pd.DataFrame({"Severity": list(by_severity.keys()), "Count": list(by_severity.values())})
            fig = px.pie(
                sdf, names="Severity", values="Count",
                color="Severity", color_discrete_map=SEVERITY_COLOR, hole=0.4,
            )
            fig.update_layout(height=320, paper_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No events yet.")

    st.divider()
    st.subheader("📈 Activity Timeline")
    _activity_timeline(df)

    st.divider()
    st.subheader("🧭 Module Health")
    _module_health_strip(df)

    st.divider()
    st.subheader("🔥 Top Risk Signals")
    st.caption("The highest-severity, highest-confidence, most-recent malicious events across every module — what needs attention right now.")
    _top_risk_signals(df)

    st.divider()
    st.subheader("Live Alert Feed")

    colf1, colf2, colf3, colf4 = st.columns([2, 2, 1, 1])
    module_filter = colf1.selectbox("Filter by module", ["All"] + list(stats.get("by_module", {}).keys()))
    severity_filter = colf2.selectbox("Filter by severity", ["All", "High", "Medium", "Low"])
    if colf3.button("🔄 Refresh", use_container_width=True):
        st.rerun()

    feed_df = df.copy()
    if not feed_df.empty:
        if module_filter != "All":
            feed_df = feed_df[feed_df["module"] == module_filter]
        if severity_filter != "All":
            feed_df = feed_df[feed_df["severity"] == severity_filter]

    if not feed_df.empty:
        feed_df = feed_df.sort_values("created_at", ascending=False)
        display_df = feed_df[["created_at", "module", "title", "severity", "is_malicious", "confidence"]].copy()
        display_df["created_at"] = display_df["created_at"].dt.strftime("%Y-%m-%d %H:%M:%S")
        display_df.columns = ["Time", "Module", "Title", "Severity", "Malicious", "Confidence"]

        def highlight_severity(row):
            color = SEVERITY_COLOR.get(row["Severity"], "#FFFFFF")
            return [f"background-color: {color}22"] * len(row)

        st.dataframe(
            display_df.style.apply(highlight_severity, axis=1).format({"Confidence": "{:.0%}"}),
            use_container_width=True, height=400,
        )
        colf4.download_button(
            "⬇️ Export CSV", data=display_df.to_csv(index=False).encode("utf-8"),
            file_name="sentinelai_alerts.csv", mime="text/csv", use_container_width=True,
        )
    else:
        st.info("No alerts match the current filter.")

    st.divider()
    st.subheader("📄 Generate Report")
    st.caption("One-click executive summary PDF of recent events, with SHAP explanations for every flagged item.")
    if st.button("Generate PDF Report", type="primary"):
        with st.spinner("Generating report..."):
            report_resp = api_get("/reports/generate")
            if report_resp.status_code == 200:
                st.download_button(
                    "⬇️ Download Report",
                    data=report_resp.content,
                    file_name="sentinelai_report.pdf",
                    mime="application/pdf",
                )
            else:
                st.error("Could not generate report.")


if not is_logged_in():
    login_screen()
else:
    overview_screen()
