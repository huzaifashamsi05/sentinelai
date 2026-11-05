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
import hashlib
import math

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

# Network IDS's five NSL-KDD classes need their own palette — R2L/U2R have
# no equivalent in the generic High/Medium/Low SEVERITY dict above. Kept
# here (not local to one page) so any module that shows these labels (live
# tables, radar blips, reference cards) draws from one source.
ATTACK_COLORS = {
    "normal": SUCCESS,
    "dos": SEVERITY["High"],
    "probe": SEVERITY["Medium"],
    "r2l": "#A78BFA",
    "u2r": "#6B7280",
}


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

        /* ---- live-feel micro-motion: every metric "arrives" instead of
           just appearing, so a page that updates live actually feels
           live. Streamlit re-renders the whole element on every rerun,
           so this quietly replays every refresh — no JS/state needed. ---- */
        [data-testid="stMetricValue"] {{
            animation: sai-arrive 0.45s ease-out;
        }}
        @keyframes sai-arrive {{
            0% {{ opacity: 0.25; transform: translateY(3px) scale(0.97); }}
            100% {{ opacity: 1; transform: translateY(0) scale(1); }}
        }}

        /* ---- radar sweep (used by radar_sweep()) ---- */
        .sai-radar {{
            position: relative; border-radius: 50%;
            background: radial-gradient(circle, {SURFACE_RAISED} 0%, {SURFACE} 100%);
            border: 1px solid {SURFACE_LINE};
            overflow: hidden; margin: 0 auto;
        }}
        .sai-radar .sai-radar-ring {{
            position: absolute; border: 1px solid {SURFACE_LINE}; border-radius: 50%;
            top: 50%; left: 50%; transform: translate(-50%, -50%);
        }}
        .sai-radar .sai-radar-sweep {{
            position: absolute; inset: 0;
            background: conic-gradient(from 0deg, {ACCENT}4d, transparent 70deg, transparent 360deg);
            animation: sai-sweep 4s linear infinite;
        }}
        @keyframes sai-sweep {{ from {{ transform: rotate(0deg); }} to {{ transform: rotate(360deg); }} }}
        .sai-radar .sai-blip {{
            position: absolute; border-radius: 50%; transform: translate(-50%, -50%);
            animation: sai-ping 0.9s ease-out;
        }}
        @keyframes sai-ping {{
            0% {{ opacity: 0; transform: translate(-50%, -50%) scale(0.3); }}
            40% {{ opacity: 1; }}
            100% {{ opacity: 1; transform: translate(-50%, -50%) scale(1); }}
        }}

        /* ---- colored-stripe table rows (used by styled_table()) ---- */
        .sai-table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
        .sai-table th {{
            text-align: left; color: {MUTED}; font-weight: 600; font-size: 0.78rem;
            text-transform: uppercase; letter-spacing: 0.04em;
            padding: 6px 10px; border-bottom: 1px solid {SURFACE_LINE};
        }}
        .sai-table td {{
            padding: 7px 10px; border-bottom: 1px solid {SURFACE_LINE}11; color: {INK};
        }}
        .sai-table tr:last-child td {{ border-bottom: none; }}

        /* ---- packet-flow travel animation (used by packet_flow()) ---- */
        .sai-flow {{ display: flex; align-items: center; margin: 6px 0 22px 0; }}
        .sai-flow-node {{
            text-align: center; font-size: 1.5rem; flex-shrink: 0; width: 64px;
        }}
        .sai-flow-node span {{
            display: block; font-size: 0.68rem; color: {MUTED}; margin-top: 2px;
            text-transform: uppercase; letter-spacing: 0.04em;
        }}
        .sai-flow-track {{
            flex: 1; height: 2px; margin: 0 14px; position: relative;
            background: repeating-linear-gradient(90deg, {SURFACE_LINE} 0 6px, transparent 6px 12px);
        }}
        .sai-flow-dot {{
            position: absolute; top: 50%; left: 0; width: 11px; height: 11px;
            border-radius: 50%; margin-top: -5.5px;
            animation: sai-travel 1.1s cubic-bezier(.3,.6,.3,1) forwards;
        }}
        @keyframes sai-travel {{
            from {{ left: 0%; }}
            to {{ left: calc(100% - 11px); }}
        }}
        .sai-flow-node.sai-flow-dest {{
            animation: sai-glow 0.7s ease 1.0s both;
            border-radius: 50%;
        }}
        @keyframes sai-glow {{
            0% {{ filter: drop-shadow(0 0 0px transparent); }}
            50% {{ filter: drop-shadow(0 0 10px var(--glow)); }}
            100% {{ filter: drop-shadow(0 0 3px var(--glow)); }}
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


def styled_table(columns: list[str], rows: list[dict], row_colors: list[str | None] | None = None) -> None:
    """A plain HTML table standing in for st.dataframe wherever a row's
    category should be visible at a glance, not just read from text: each
    row can carry a colored left-edge stripe. `rows` is a list of dicts
    keyed by `columns`; `row_colors` is one hex color (or None for "no
    stripe", e.g. an unremarkable row) per row in `rows`."""
    row_colors = row_colors or [None] * len(rows)
    head = "".join(f"<th>{c}</th>" for c in columns)
    body = []
    for row, color in zip(rows, row_colors):
        style = f' style="box-shadow: inset 4px 0 0 0 {color};"' if color else ""
        cells = "".join(f"<td>{row.get(c, '')}</td>" for c in columns)
        body.append(f"<tr{style}>{cells}</tr>")
    st.markdown(
        f'<table class="sai-table"><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table>',
        unsafe_allow_html=True,
    )


def radar_sweep(blips: list[dict], size: int = 200, rings: int = 3) -> None:
    """A SOC-style radar: concentric rings and a continuously rotating
    sweep (pure CSS, purely decorative) with one static dot per recent
    event. Each item in `blips` is a dict with:
      - `key`: any stable string (e.g. a timestamp+path) — hashed with
        md5 to a deterministic angle, so a given event sits still across
        reruns instead of jittering every refresh
      - `recency`: 0.0 (oldest shown) .. 1.0 (most recent) — mapped to
        radius, so newer events sit nearer the center
      - `color`: hex color
      - `label`: hover title text
    Position is illustrative only — not a real geography or network
    location — callers should caption that near the visualization.
    """
    ring_html = "".join(
        f'<div class="sai-radar-ring" style="width:{round(size * (i + 1) / rings)}px;'
        f'height:{round(size * (i + 1) / rings)}px;"></div>'
        for i in range(rings)
    )
    blip_html = []
    for b in blips:
        digest = hashlib.md5(str(b.get("key", "")).encode()).hexdigest()
        angle = int(digest[:8], 16) % 360
        recency = max(0.0, min(1.0, b.get("recency", 0.5)))
        radius_frac = 0.14 + (1.0 - recency) * 0.34  # newer -> nearer center
        r = radius_frac * size / 2
        cx = size / 2 + r * math.cos(math.radians(angle))
        cy = size / 2 + r * math.sin(math.radians(angle))
        dot = 7 + recency * 6
        color = b.get("color", ACCENT)
        title = b.get("label", "")
        blip_html.append(
            f'<div class="sai-blip" title="{title}" '
            f'style="left:{cx:.1f}px; top:{cy:.1f}px; width:{dot:.0f}px; height:{dot:.0f}px; '
            f'background:{color}; box-shadow:0 0 7px {color};"></div>'
        )
    st.markdown(
        f'<div class="sai-radar" style="width:{size}px;height:{size}px;">'
        f'{ring_html}<div class="sai-radar-sweep"></div>{"".join(blip_html)}</div>',
        unsafe_allow_html=True,
    )


def packet_flow(verdict_color: str, verdict_label: str = "Verdict",
                 source_icon: str = "💻", dest_icon: str = "🛡️", source_label: str = "Connection") -> None:
    """A small animated strip shown right after a classification: a dot
    travels from a source icon to a destination icon, which glows in the
    verdict's color on arrival. Purely illustrative motion — it dramatizes
    the decision that already happened, it isn't a literal packet trace."""
    st.markdown(
        f"""
        <div class="sai-flow">
          <div class="sai-flow-node">{source_icon}<span>{source_label}</span></div>
          <div class="sai-flow-track">
            <div class="sai-flow-dot" style="background:{verdict_color}; box-shadow:0 0 8px {verdict_color};"></div>
          </div>
          <div class="sai-flow-node sai-flow-dest" style="--glow:{verdict_color};">{dest_icon}<span>{verdict_label}</span></div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def info_cards(cards: list[dict], highlight_key: str | None = None) -> None:
    """A row of small reference cards (icon/title/one-line description) —
    e.g. a legend for a classifier's output categories. Pass `highlight_key`
    matching one card's `key` to visually light that one up (e.g. the
    category a just-run classification landed on). Each card dict:
    {key, icon, title, desc, color}."""
    cols = st.columns(len(cards))
    for col, card in zip(cols, cards):
        is_hl = highlight_key is not None and card.get("key") == highlight_key
        color = card.get("color", ACCENT)
        border = f"2px solid {color}" if is_hl else f"1px solid {SURFACE_LINE}"
        bg = f"linear-gradient(135deg, {color}26, {SURFACE} 70%)" if is_hl else SURFACE
        glow = f"box-shadow: 0 0 14px {color}55;" if is_hl else ""
        with col:
            st.markdown(
                f"""
                <div class="sai-card" style="border:{border}; background:{bg}; {glow}
                     text-align:center; padding:12px 8px; transition: all 0.3s ease;">
                    <div style="font-size:1.4rem;">{card.get('icon', '')}</div>
                    <div style="font-weight:700; font-size:0.85rem; color:{INK}; margin-top:2px;">{card.get('title', '')}</div>
                    <div style="font-size:0.75rem; color:{MUTED}; margin-top:2px;">{card.get('desc', '')}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
