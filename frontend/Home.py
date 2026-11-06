"""
SentinelAI Unified Dashboard — entry point.
Login/registration, then a command-center overview of all five modules:
platform risk index, activity timeline, per-module health, top risk
signals, the live alert feed, and the PDF report generator.

Visual rebuild: this is the page that ties the whole platform together, so
it now speaks the same visual language already shipped across all five
module pages — the ring+stamp "verdict" component (Network IDS, Phishing
Detector, Malware Scanner, Vulnerability Scanner, Secure Vault all use a
version of it) reappears here, scaled up, as the Platform Risk Index hero.
Unlike those pages, the score is known server-side the moment this script
runs, so the reveal is a pure CSS @keyframes animation with the target
dash-offset baked in at render time — no components.html() iframe, no JS,
and therefore none of the fixed-height iframe-clipping class of bug that
shipped (and got fixed) on Secure Vault's mobile layout.

Every module gets its own identity color (MODULE_COLOR) used consistently
across the module-health strip, the activity timeline, and the events-by-
module chart, so the dashboard reads as one coherent system rather than a
pile of generic plotly defaults. The raw, sortable data grid still exists
for power users (filters + CSV export) — it is just tucked into a "Raw
data & export" expander below a visual card feed, per the standing rule:
complexity gets hidden in presentation, never removed from the product.
"""
import math
from datetime import datetime, timezone

import pandas as pd
import plotly.express as px
import streamlit as st

from _backend_bootstrap import ensure_backend
from api_client import api_get, api_post, is_admin, is_logged_in, login, logout, register
from theme import gem_svg, inject_global_styles, luxury_splash, page_header, sidebar_brand

st.set_page_config(page_title="SentinelAI", page_icon="🛡️", layout="wide")
ensure_backend()
inject_global_styles()
luxury_splash()
sidebar_brand()

# ---------------------------------------------------------------------------
# Shared design tokens — one identity color per module, reused everywhere a
# module needs to be told apart from the others (health strip, timeline,
# events-by-module chart). Severity colors match the exact hex values
# already shipped on the Vulnerability Scanner page so a "High" reads as
# the same red everywhere in the platform.
# ---------------------------------------------------------------------------
SEVERITY_COLOR = {"High": "#E0344F", "Medium": "#FFA940", "Low": "#4F9BFF"}
MODULE_ICON = {
    "Network IDS": "🌐",
    "Phishing Detector": "🎣",
    "Malware Scanner": "🦠",
    "Vulnerability Scanner": "🔍",
    "Secure Vault": "🔐",
}
MODULE_COLOR = {
    "Network IDS": "#4F9BFF",
    "Phishing Detector": "#FFA940",
    "Malware Scanner": "#E0344F",
    "Vulnerability Scanner": "#9B5FE0",
    "Secure Vault": "#2FE0A8",
}
MODULE_ORDER = list(MODULE_ICON.keys())
RISK_WEIGHT = {"High": 10, "Medium": 5, "Low": 2}

# Every column the overview screen's helpers index into df[...] with. Needed
# because pd.DataFrame([]) (what the API returns right after a reboot, or
# for a brand-new demo session with zero alerts logged anywhere yet) has
# ZERO columns, not just zero rows — so df["module"] etc. raise a bare
# KeyError rather than behaving like "no matching rows". Most of the
# helpers below already guard with `if df.empty: return`, but that guard
# is only as good as every call site remembering to add it; forcing these
# columns to exist at the one place df is built makes every downstream
# df["..."] safe by construction instead of by convention.
_ALERT_COLUMNS = ["created_at", "module", "title", "severity", "is_malicious", "confidence"]

_FONTS_CSS = """
<style>
  .sv-display{ font-family:'Cormorant Garamond', Georgia, serif; }
  .sv-mono{ font-family:'JetBrains Mono', monospace; }
  @keyframes sv-livepulse{ 0%,100%{ opacity:1; } 50%{ opacity:0.35; } }
</style>
"""
st.markdown(_FONTS_CSS, unsafe_allow_html=True)


def _hex_to_rgba(hex_color: str, alpha: float) -> str:
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"


def login_screen():
    st.markdown(
        f"""<div style="text-align:center;padding:48px 0 14px 0;">
<div style="position:relative;width:92px;height:92px;margin:0 auto;">
<div style="position:absolute;inset:0;border-radius:50%;border:1px solid #D4AF3755;
animation:sv-livepulse 2.4s ease-in-out infinite;"></div>
<div style="position:absolute;inset:9px;border-radius:50%;border:1px solid #D4AF3733;"></div>
<div style="position:absolute;inset:18px;border-radius:50%;
background:radial-gradient(circle at 35% 30%, #F2D88933, #0F1115 72%);
border:1px solid #D4AF3766;box-shadow:0 0 28px -4px #D4AF3755, inset 0 0 14px #D4AF3722;
display:flex;align-items:center;justify-content:center;">{gem_svg(40, "loginGem")}</div>
</div>
<h1 class="sv-display" style="font-size:2.5rem;margin:14px 0 0 0;">SentinelAI</h1>
<div style="color:#A39A87;font-size:0.92rem;letter-spacing:0.14em;text-transform:uppercase;margin-top:2px;">
AI-Powered Security Operations Platform</div>
</div>""",
        unsafe_allow_html=True,
    )

    col_l, col_mid, col_r = st.columns([1, 1.3, 1])
    with col_mid:
        st.markdown(
            """<div style="border:1px solid #D4AF3740;border-radius:18px;padding:24px 28px 10px 28px;
background:linear-gradient(160deg,#161920,#0F1115 70%);box-shadow:0 24px 70px -24px #000000cc;">""",
            unsafe_allow_html=True,
        )
        tab_login, tab_register = st.tabs(["Log in", "Register"])

        with tab_login:
            with st.form("login_form"):
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                submitted = st.form_submit_button("Log in", use_container_width=True, type="primary")
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
                reg_submitted = st.form_submit_button("Create account", use_container_width=True, type="primary")
            if reg_submitted:
                ok, msg = register(new_username, new_password, role)
                if ok:
                    st.success("Account created — switch to the Log in tab.")
                else:
                    st.error(msg)
        st.markdown("</div>", unsafe_allow_html=True)

        pills = "".join(
            f"""<span style="background:{MODULE_COLOR[m]}18;border:1px solid {MODULE_COLOR[m]}55;
border-radius:999px;padding:5px 14px;font-size:0.8rem;color:{MODULE_COLOR[m]};">{MODULE_ICON[m]} {m}</span>"""
            for m in MODULE_ORDER
        )
        st.markdown(
            f"""<div style="display:flex;justify-content:center;gap:10px;flex-wrap:wrap;margin-top:18px;">
{pills}
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
        f"""<div style="border:1px solid {color}40;border-radius:14px;padding:16px 18px;
background:linear-gradient(135deg,{_hex_to_rgba(color, 0.10)},#0F1115 70%);height:100%;">
<div style="font-size:1.4rem;">{icon}</div>
<div class="sv-display" style="font-size:1.8rem;font-weight:700;color:{color};margin-top:6px;">{value}</div>
<div style="font-size:0.8rem;color:#A39A87;margin-top:2px;">{label}</div>
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
        return "#2FE0A8", "Excellent"
    if score >= 75:
        return "#7DCB6B", "Good"
    if score >= 50:
        return "#FFA940", "Fair"
    if score >= 25:
        return "#E8863D", "At Risk"
    return "#E0344F", "Critical"


# Ring geometry for the Platform Risk Index hero — same proportions as the
# ring+stamp verdict component already shipped across every module page,
# scaled up to be the dashboard's own centerpiece.
_RING_R = 58
_RING_C = round(2 * math.pi * _RING_R, 1)


def _risk_ring_html(score: int, color: str, label: str) -> str:
    offset = round(_RING_C * (1 - score / 100), 1)
    size = (_RING_R + 12) * 2
    c = size / 2
    return f"""
<style>
@keyframes sv-risk-reveal {{
  from {{ stroke-dashoffset:{_RING_C}; opacity:0; }}
  to {{ stroke-dashoffset:{offset}; opacity:1; }}
}}
</style>
<div style="position:relative;width:{size}px;height:{size}px;flex-shrink:0;">
  <svg viewBox="0 0 {size} {size}" style="transform:rotate(-90deg);width:{size}px;height:{size}px;">
    <circle cx="{c}" cy="{c}" r="{_RING_R}" fill="none" stroke="#211C12" stroke-width="10"/>
    <circle cx="{c}" cy="{c}" r="{_RING_R}" fill="none" stroke="{color}" stroke-width="10"
            stroke-linecap="round" stroke-dasharray="{_RING_C}" stroke-dashoffset="{_RING_C}"
            style="animation:sv-risk-reveal 1.1s cubic-bezier(.3,.6,.3,1) forwards;"/>
  </svg>
  <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;">
    <div class="sv-display" style="font-weight:700;font-size:2.5rem;line-height:1;color:{color};">{score}</div>
    <div style="font-size:0.72rem;letter-spacing:0.05em;text-transform:uppercase;color:#A39A87;margin-top:5px;">{label}</div>
  </div>
</div>"""


def _risk_index_card(df: pd.DataFrame):
    score, breakdown = _compute_risk_index(df)
    band_color, band_label = _risk_band(score)
    chips = "".join(
        f"""<span style="background:{SEVERITY_COLOR[s]}22;color:{SEVERITY_COLOR[s]};
border:1px solid {SEVERITY_COLOR[s]}55;border-radius:999px;padding:4px 13px;font-size:0.78rem;margin-right:8px;">
{breakdown.get(s, 0)} {s}</span>"""
        for s in ["High", "Medium", "Low"]
    )
    st.markdown(
        f"""<div style="border:1px solid {band_color}40;border-radius:18px;
padding:28px 30px;background:linear-gradient(135deg,{_hex_to_rgba(band_color, 0.10)},#0F1115 65%);
display:flex;align-items:center;gap:32px;flex-wrap:wrap;">
{_risk_ring_html(score, band_color, band_label)}
<div style="flex:1;min-width:240px;">
<div class="sv-display" style="font-size:1.25rem;font-weight:700;color:{band_color};">{band_label} standing</div>
<div style="color:#A39A87;font-size:0.88rem;margin-top:4px;">Platform risk score — {score} / 100, across every module</div>
<div style="margin-top:16px;">{chips}</div>
</div>
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


def _sparkline(counts: list[int], color: str, width: int = 74, height: int = 22) -> str:
    n = len(counts)
    if n == 0:
        return ""
    peak = max(counts) or 1
    bar_w = width / n
    gap = bar_w * 0.24
    bars = []
    for i, cnt in enumerate(counts):
        h = max(2.0, (cnt / peak) * (height - 2))
        x = i * bar_w + gap / 2
        w = bar_w - gap
        y = height - h
        fill = color if cnt > 0 else "#2A2418"
        bars.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="1.4" fill="{fill}"/>')
    return f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}">{"".join(bars)}</svg>'


def _module_health_strip(df: pd.DataFrame):
    now = pd.Timestamp.now(tz="UTC")
    today = now.normalize()
    day_slots = [today - pd.Timedelta(days=d) for d in range(6, -1, -1)]
    cols = st.columns(5)
    for i, mod in enumerate(MODULE_ORDER):
        mod_df = df[df["module"] == mod]
        total = len(mod_df)
        ident = MODULE_COLOR[mod]
        if total:
            last_ts = mod_df["created_at"].max()
            last_str = _relative_time(last_ts)
            recent = (now - last_ts).total_seconds() < 86400
            has_high_malicious = (
                (mod_df["is_malicious"] == True) & (mod_df["severity"] == "High")  # noqa: E712
            ).any()
            accent = "#E0344F" if has_high_malicious else (ident if recent else "#6B6355")
            day_counts = mod_df["created_at"].dt.normalize()
            counts = [int((day_counts == d).sum()) for d in day_slots]
        else:
            last_str = "No activity yet"
            accent = "#4A4538"
            counts = [0] * 7
        spark = _sparkline(counts, accent if total else "#2A2418")
        with cols[i]:
            st.markdown(
                f"""<div style="border:1px solid {accent}50;border-radius:14px;padding:14px 12px;
background:linear-gradient(160deg,{_hex_to_rgba(accent, 0.09)},#0F1115 75%);text-align:center;min-height:158px;
display:flex;flex-direction:column;justify-content:space-between;">
<div>
<div style="font-size:1.5rem;">{MODULE_ICON[mod]}</div>
<div style="font-weight:700;font-size:0.78rem;color:#F4EFE3;margin-top:4px;line-height:1.2;">{mod}</div>
<div class="sv-display" style="font-size:1.4rem;font-weight:700;color:{accent};margin-top:6px;">{total}</div>
<div style="font-size:0.7rem;color:#A39A87;">events · {last_str}</div>
</div>
<div style="display:flex;justify-content:center;margin-top:8px;">{spark}</div>
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
        color_discrete_map=MODULE_COLOR,
    )
    fig.update_layout(
        height=300, legend_title_text="", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        xaxis_title="", yaxis_title="Events", font={"family": "Manrope, sans-serif", "color": "#D9D2C0"},
        barmode="stack", margin=dict(l=10, r=10, t=10, b=10),
    )
    st.plotly_chart(fig, use_container_width=True)


def _alert_card(row: pd.Series) -> str:
    severity = row["severity"]
    color = SEVERITY_COLOR.get(severity, "#A39A87")
    conf_str = f"{row['confidence'] * 100:.0f}%" if pd.notna(row["confidence"]) else "—"
    icon = MODULE_ICON.get(row["module"], "🛡️")
    flag = (
        '<span style="color:#E0344F;font-size:0.72rem;">⚠ malicious</span>'
        if row.get("is_malicious")
        else '<span style="color:#2FE0A8;font-size:0.72rem;">✓ clear</span>'
    )
    return f"""<div style="display:flex;align-items:center;gap:14px;border:1px solid {color}55;
border-left:3px solid {color};border-radius:10px;padding:11px 16px;
background:linear-gradient(135deg,{_hex_to_rgba(color, 0.08)},#0F1115 80%);margin-bottom:8px;">
<div style="font-size:1.25rem;">{icon}</div>
<div style="flex:1;min-width:0;">
<div style="font-weight:700;color:#F4EFE3;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{row['title']}</div>
<div style="font-size:0.76rem;color:#A39A87;margin-top:2px;">{row['module']} · {_relative_time(row['created_at'])} · {flag}</div>
</div>
<div style="text-align:right;flex-shrink:0;">
<span style="background:{color}22;color:{color};border:1px solid {color}55;border-radius:999px;padding:3px 10px;font-size:0.76rem;">{severity}</span>
<div style="font-size:0.74rem;color:#A39A87;margin-top:4px;">{conf_str} confidence</div>
</div>
</div>"""


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
    st.markdown("".join(_alert_card(row) for _, row in top.iterrows()), unsafe_allow_html=True)


def overview_screen():
    page_header(
        gem_svg(26, "ovwGem"),
        "COMMAND CENTER",
        "Security Overview",
        "Live risk posture across every module — Network IDS, Phishing Detector, Malware Scanner, Vulnerability Scanner, and Secure Vault, in one feed.",
    )
    with st.sidebar:
        st.markdown(
            f"""<div style="border:1px solid #D4AF3740;border-radius:12px;padding:12px 14px;
background:linear-gradient(160deg,#161920,#0F1115);">
<div style="font-size:0.72rem;color:#A39A87;letter-spacing:0.08em;">LOGGED IN AS</div>
<div style="font-weight:700;color:#F4EFE3;font-size:1rem;">{st.session_state.get('username')}</div>
<div style="font-size:0.78rem;color:#A39A87;margin-top:4px;">Role: {st.session_state.get('role')}</div>
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
    if df.empty:
        # pd.DataFrame([]) / pd.DataFrame() have no columns at all — give it
        # the real schema so every df["..."] below is a safe "no rows" read
        # instead of a KeyError. See _ALERT_COLUMNS above for why.
        df = pd.DataFrame(columns=_ALERT_COLUMNS)
    else:
        df["created_at"] = pd.to_datetime(df["created_at"], utc=True)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        _metric_card("📊", "Total Events", stats.get("total_events", 0), "#4F9BFF")
    with col2:
        _metric_card("🚨", "Malicious / High-Risk", stats.get("malicious_events", 0), "#E0344F")
    with col3:
        _metric_card("🧩", "Modules Reporting", len(stats.get("by_module", {})), "#2FE0A8")
    with col4:
        high_count = stats.get("by_severity", {}).get("High", 0)
        _metric_card("⚠️", "High-Severity Alerts", high_count, "#FFA940")

    st.markdown(
        f"""<div style="display:flex;align-items:center;gap:8px;padding:10px 2px 0 2px;">
<span style="width:8px;height:8px;border-radius:50%;background:#2FE0A8;box-shadow:0 0 6px 2px #2FE0A899;
display:inline-block;animation:sv-livepulse 1.8s ease-in-out infinite;"></span>
<span style="font-size:0.8rem;color:#A39A87;">{len(stats.get('by_module', {}))} of 5 modules reporting · dashboard live</span>
</div>""",
        unsafe_allow_html=True,
    )

    st.divider()

    st.subheader("🎯 Platform Risk Index")
    _risk_index_card(df)

    st.divider()

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Events by Module")
        by_module = stats.get("by_module", {})
        if by_module:
            mdf = pd.DataFrame({"Module": list(by_module.keys()), "Events": list(by_module.values())})
            fig = px.bar(mdf, x="Module", y="Events", color="Module", color_discrete_map=MODULE_COLOR)
            fig.update_layout(
                showlegend=False, height=320, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font={"family": "Manrope, sans-serif", "color": "#D9D2C0"},
            )
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
            fig.update_layout(
                height=320, paper_bgcolor="rgba(0,0,0,0)",
                font={"family": "Manrope, sans-serif", "color": "#D9D2C0"},
            )
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

        colf4.download_button(
            "⬇️ Export CSV", data=display_df.to_csv(index=False).encode("utf-8"),
            file_name="sentinelai_alerts.csv", mime="text/csv", use_container_width=True,
        )

        shown = st.session_state.setdefault("home_feed_n", 12)
        st.markdown("".join(_alert_card(row) for _, row in feed_df.head(shown).iterrows()), unsafe_allow_html=True)
        if len(feed_df) > shown:
            if st.button(f"Show more ({len(feed_df) - shown} remaining)", use_container_width=True):
                st.session_state["home_feed_n"] = shown + 12
                st.rerun()

        with st.expander("📊 Raw data & full export"):
            def highlight_severity(row):
                color = SEVERITY_COLOR.get(row["Severity"], "#F4EFE3")
                return [f"background-color: {color}22"] * len(row)

            st.dataframe(
                display_df.style.apply(highlight_severity, axis=1).format({"Confidence": "{:.0%}"}),
                use_container_width=True, height=400,
            )
    else:
        st.info("No alerts match the current filter.")

    st.divider()
    st.subheader("📄 Generate Report")
    st.markdown(
        """<div style="border:1px solid #2A2418;border-radius:14px;padding:16px 20px;
background:linear-gradient(135deg,#4F9BFF14,#0F1115 75%);">
<div style="color:#A39A87;font-size:0.86rem;">One-click executive summary PDF of recent events, with SHAP explanations for every flagged item.</div>
</div>""",
        unsafe_allow_html=True,
    )
    st.write("")
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
