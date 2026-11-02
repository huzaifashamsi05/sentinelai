"""
SentinelAI Unified Dashboard — entry point.
Login/registration, then a live overview of all five modules' alerts.
"""
import pandas as pd
import plotly.express as px
import streamlit as st

from api_client import api_get, api_post, is_admin, is_logged_in, login, logout, register

st.set_page_config(page_title="SentinelAI", page_icon="🛡️", layout="wide")

SEVERITY_COLOR = {"High": "#D64545", "Medium": "#E0A030", "Low": "#4A90D9"}


def login_screen():
    st.title("🛡️ SentinelAI")
    st.caption("AI-Powered Security Operations Platform")

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


def overview_screen():
    st.title("🛡️ SentinelAI — Security Overview")
    with st.sidebar:
        st.markdown(f"**Logged in as:** {st.session_state.get('username')}")
        st.markdown(f"**Role:** {st.session_state.get('role')}")
        if st.button("Log out"):
            logout()
            st.rerun()

    stats_resp = api_get("/alerts/stats")
    if stats_resp.status_code != 200:
        st.error("Could not load stats from backend.")
        return
    stats = stats_resp.json()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Events", stats.get("total_events", 0))
    col2.metric("Malicious / High-Risk", stats.get("malicious_events", 0))
    col3.metric("Modules Reporting", len(stats.get("by_module", {})))
    high_count = stats.get("by_severity", {}).get("High", 0)
    col4.metric("High-Severity Alerts", high_count)

    st.divider()

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Events by Module")
        by_module = stats.get("by_module", {})
        if by_module:
            df = pd.DataFrame({"Module": list(by_module.keys()), "Events": list(by_module.values())})
            fig = px.bar(df, x="Module", y="Events", color="Module")
            fig.update_layout(showlegend=False, height=350)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No events yet — try a module from the sidebar.")

    with c2:
        st.subheader("Events by Severity")
        by_severity = stats.get("by_severity", {})
        if by_severity:
            df = pd.DataFrame({"Severity": list(by_severity.keys()), "Count": list(by_severity.values())})
            fig = px.pie(
                df, names="Severity", values="Count",
                color="Severity", color_discrete_map=SEVERITY_COLOR, hole=0.4,
            )
            fig.update_layout(height=350)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No events yet.")

    st.divider()
    st.subheader("Live Alert Feed")

    colf1, colf2, colf3 = st.columns([2, 2, 2])
    module_filter = colf1.selectbox(
        "Filter by module", ["All"] + list(stats.get("by_module", {}).keys())
    )
    severity_filter = colf2.selectbox("Filter by severity", ["All", "High", "Medium", "Low"])
    if colf3.button("🔄 Refresh"):
        st.rerun()

    params = {"limit": 100}
    if module_filter != "All":
        params["module"] = module_filter
    if severity_filter != "All":
        params["severity"] = severity_filter

    alerts_resp = api_get("/alerts", params=params)
    if alerts_resp.status_code == 200:
        alerts = alerts_resp.json()
        if alerts:
            df = pd.DataFrame(alerts)
            df["created_at"] = pd.to_datetime(df["created_at"]).dt.strftime("%Y-%m-%d %H:%M:%S")
            display_df = df[["created_at", "module", "title", "severity", "is_malicious", "confidence"]]
            display_df.columns = ["Time", "Module", "Title", "Severity", "Malicious", "Confidence"]

            def highlight_severity(row):
                color = SEVERITY_COLOR.get(row["Severity"], "#FFFFFF")
                return [f"background-color: {color}22"] * len(row)

            st.dataframe(
                display_df.style.apply(highlight_severity, axis=1).format({"Confidence": "{:.0%}"}),
                use_container_width=True, height=400,
            )
        else:
            st.info("No alerts match the current filter.")
    else:
        st.error("Could not load alerts.")

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
