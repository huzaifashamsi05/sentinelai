"""
Shared design system for every SentinelAI page.

Why this file exists: six build phases each styled their own page
independently — one gradient-card dict per page (Home.py's SEVERITY_COLOR,
Vulnerability Scanner's _RISK_COLOR, etc.), no shared typography, and the
app's buttons/sliders/tabs were still running on Streamlit's stock default
accent color (#FF4B4B) because nobody ever set a theme. The result: every
page *works*, but nothing visually says "one deliberately designed
product" rather than "six separate demos stapled together."

This module is the fix: one color/spacing system, one typography choice,
and a small set of reusable building blocks (intro explainer boxes,
plain-language "translate the result" callouts, chips, styling hooks for
Streamlit's own native widgets) that every page imports instead of
reinventing. Call `inject_global_styles()` once, near the top of every
page, right after `st.set_page_config()`.

(The native Streamlit hamburger/menu toolbar that every visitor sees is
hidden platform-wide via `client.toolbarMode = "minimal"` in
.streamlit/config.toml — no per-page code needed. The separate "Share /
star / GitHub / Deploy / Manage app" bar you see when testing live is
Streamlit Community Cloud's owner-only admin chrome: it only renders for
whoever is logged into the Streamlit Cloud account that owns this app, so
an actual visitor opening the public link never sees it.)
"""
import streamlit as st

# ---------------------------------------------------------------------
# Canonical color tokens — the single source of truth. Do not define a
# local severity/risk color dict in a page again; import SEVERITY from
# here instead.
# ---------------------------------------------------------------------
ACCENT = "#6C63FF"        # brand accent — primary CTA / interactive color
                            # (deliberately violet-indigo, not "danger red"
                            # or any severity color, so a button never
                            # visually reads as a risk signal)
ACCENT_LINE = "#6C63FF55"
INK = "#ECEDF2"            # primary text on dark background
MUTED = "#98A1B3"          # secondary / caption text
SURFACE = "#12151c"        # card background
SURFACE_RAISED = "#171b24"
SURFACE_LINE = "#272c38"   # card border

SEVERITY = {
    "High": "#E35D6A",
    "Medium": "#E3A23B",
    "Low": "#4FA3D1",
}
SUCCESS = "#3DC47E"
CRITICAL = SEVERITY["High"]


def hex_to_rgba(hex_color: str, alpha: float) -> str:
    """Plotly's go.Indicator gauge steps (and a few other props) reject
    8-digit hex-with-alpha strings — this is the shared fix every page
    should use instead of re-deriving it."""
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"


def inject_global_styles():
    st.markdown(
        f"""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

        html, body, [class*="css"], [data-testid="stAppViewContainer"] {{
            font-family: 'Inter', -apple-system, sans-serif;
        }}
        h1, h2, h3 {{ letter-spacing: -0.02em; font-weight: 800 !important; }}
        p, li, label, [data-testid="stCaptionContainer"] {{ line-height: 1.55; }}

        /* ---- explainer / "what this does" box ---- */
        .sai-intro {{
            border: 1px solid {ACCENT_LINE};
            border-radius: 14px;
            background: linear-gradient(135deg, {ACCENT}1f, {SURFACE} 65%);
            padding: 18px 22px;
            margin: 4px 0 20px 0;
        }}
        .sai-intro h4 {{
            margin: 0 0 6px 0; font-size: 1.05rem; font-weight: 700; color: {INK};
        }}
        .sai-intro p {{
            margin: 0; color: {INK}; opacity: 0.92; font-size: 0.95rem; line-height: 1.6;
        }}
        .sai-intro p + p {{ margin-top: 8px; }}

        /* ---- plain-language result translation callout ---- */
        .sai-translate {{
            border-left: 3px solid {ACCENT};
            background: {ACCENT}14;
            padding: 11px 15px;
            border-radius: 0 10px 10px 0;
            font-size: 0.92rem;
            color: {INK};
            margin: 10px 0 16px 0;
            line-height: 1.55;
        }}

        /* ---- generic card ---- */
        .sai-card {{
            border: 1px solid {SURFACE_LINE};
            border-radius: 12px;
            background: {SURFACE};
            padding: 16px 18px;
        }}

        /* ---- chip ---- */
        .sai-chip {{
            display: inline-block; padding: 3px 11px; border-radius: 999px;
            font-size: 0.78rem; font-weight: 600; white-space: nowrap;
        }}

        /* ---- restyle Streamlit's own native widgets so the accent is
           deliberate everywhere, not the stock default ---- */
        [data-testid="stForm"] {{
            border: 1px solid {SURFACE_LINE} !important;
            border-radius: 16px !important;
            padding: 22px 24px 10px 24px !important;
            background: {SURFACE} !important;
        }}
        [data-testid="stMetric"] {{
            background: {SURFACE};
            border: 1px solid {SURFACE_LINE};
            border-radius: 12px;
            padding: 14px 16px 10px 16px;
        }}
        [data-testid="stMetricLabel"] {{ color: {MUTED} !important; }}
        div[data-testid="stExpander"] {{
            border: 1px solid {SURFACE_LINE} !important;
            border-radius: 12px !important;
            background: {SURFACE_RAISED} !important;
        }}
        button[kind="primary"], button[kind="secondary"] {{
            border-radius: 10px !important;
            font-weight: 600 !important;
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def intro(icon: str, title: str, body: str):
    """The 'what this does and why it matters' box — plain language,
    meant to be read by someone with zero security background, placed
    before any technical form/output on a page."""
    st.markdown(
        f'<div class="sai-intro"><h4>{icon} {title}</h4><p>{body}</p></div>',
        unsafe_allow_html=True,
    )


def translate(text_html: str):
    """One-line plain-language translation of a technical result —
    placed immediately after a verdict/number so a non-technical reader
    knows what it actually means, not just what it says."""
    st.markdown(f'<div class="sai-translate">{text_html}</div>', unsafe_allow_html=True)


def chip(text: str, color: str) -> str:
    """Returns chip HTML (compose into a larger st.markdown call, since
    Streamlit can't lay out several small custom elements inline on one
    line across separate st.markdown calls)."""
    return f'<span class="sai-chip" style="background:{color}22;border:1px solid {color}55;color:{color}">{text}</span>'
