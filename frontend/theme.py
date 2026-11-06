"""
Shared design system for every SentinelAI page — "Jeweled Obsidian".

Why this file exists: six build phases each styled their own page
independently — one gradient-card dict per page (Home.py's SEVERITY_COLOR,
Vulnerability Scanner's _RISK_COLOR, etc.), no shared typography, and the
app's buttons/sliders/tabs were still running on Streamlit's stock default
accent color because nobody ever set a theme. The result: every page
*works*, but nothing visually says "one deliberately designed product"
rather than "six separate demos stapled together."

This module is the fix: one color/spacing system, one typography choice,
and a small set of reusable building blocks (intro explainer boxes,
plain-language "translate the result" callouts, chips, a splash screen,
styling hooks for Streamlit's own native widgets) that every page imports
instead of reinventing. Call `inject_global_styles()` once, near the top
of every page, right after `st.set_page_config()`.

Design language: an obsidian-black surface with champagne-gold trim — a
private-vault / luxury-watch-brand feel — and each of the five modules
carries its own precious-gem identity color (already the app's existing
module-color system, just rendered as a jewel instead of a flat hex):
Network IDS = Sapphire, Phishing Detector = Topaz, Malware Scanner = Ruby,
Vulnerability Scanner = Amethyst, Secure Vault = Emerald. Severity reuses
the same three gems (High=Ruby, Medium=Topaz, Low=Sapphire) so the whole
platform reads as one consistent jeweled language, not an arbitrary
rainbow.

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
from pathlib import Path

import streamlit as st

_ASSET_DIR = Path(__file__).resolve().parent / "assets"

# ---------------------------------------------------------------------
# Canonical color tokens — the single source of truth. Do not define a
# local severity/risk/module color dict in a page again; import from here.
# ---------------------------------------------------------------------

# ---- Obsidian surface scale (darkest -> lightest) ----
OBSIDIAN_0 = "#07080B"     # app background (deepest)
OBSIDIAN_1 = "#0F1115"     # card / panel surface
OBSIDIAN_2 = "#161920"     # raised surface (expanders, hover states)

# ---- Gold — the brand's precious-metal trim, not a severity color ----
GOLD_BRIGHT = "#F2D889"    # foil highlight
GOLD = "#D4AF37"           # core gold — primary CTA / interactive color
GOLD_DEEP = "#9C7A24"      # shadow gold
GOLD_LINE = "#D4AF3740"    # hairline border, low-opacity gold

# ---- Ink / text ----
INK = "#F4EFE3"            # primary text — warm ivory, not stark white
INK_SECONDARY = "#D9D2C0"  # secondary text, still warm-toned
MUTED = "#A39A87"          # caption / meta text
MUTED_DIM = "#6B6355"      # disabled / "no data" text

# ---- Borders ----
SURFACE = OBSIDIAN_1
SURFACE_RAISED = OBSIDIAN_2
SURFACE_LINE = "#2A2418"   # warm bronze-charcoal hairline (replaces cool slate)

# ---- Backward-compatible brand accent (now gold, not violet) ----
ACCENT = GOLD
ACCENT_LINE = GOLD_LINE

# ---- Gem identity colors — bright (glow/text) + deep (gradient shadow) ----
SAPPHIRE = "#4F9BFF"       # Network IDS, severity "Low"
SAPPHIRE_DEEP = "#1C4FA0"
TOPAZ = "#FFA940"          # Phishing Detector, severity "Medium"
TOPAZ_DEEP = "#9C6B12"
RUBY = "#E0344F"           # Malware Scanner, severity "High"
RUBY_DEEP = "#8E1B35"
AMETHYST = "#9B5FE0"       # Vulnerability Scanner, NSL-KDD "r2l"
AMETHYST_DEEP = "#5B2C8C"
EMERALD = "#2FE0A8"        # Secure Vault, "success" / live-pulse
EMERALD_DEEP = "#0E6B4F"
QUARTZ = "#8A8371"         # NSL-KDD "u2r" — smoky quartz, the rare/unknown class

SEVERITY = {
    "High": RUBY,
    "Medium": TOPAZ,
    "Low": SAPPHIRE,
}
SUCCESS = EMERALD
CRITICAL = SEVERITY["High"]

# Network IDS's five NSL-KDD classes need their own palette — R2L/U2R have
# no equivalent in the generic High/Medium/Low SEVERITY dict above. Kept
# here (not local to one page) so any module that shows these labels (live
# tables, radar blips, reference cards) draws from one source.
ATTACK_COLORS = {
    "normal": SUCCESS,
    "dos": SEVERITY["High"],
    "probe": SEVERITY["Medium"],
    "r2l": AMETHYST,
    "u2r": QUARTZ,
}

# The five modules' own gem identity — the single source every page should
# import instead of redefining its own MODULE_COLOR dict.
MODULE_GEMS = {
    "Network IDS": SAPPHIRE,
    "Phishing Detector": TOPAZ,
    "Malware Scanner": RUBY,
    "Vulnerability Scanner": AMETHYST,
    "Secure Vault": EMERALD,
}


def hex_to_rgba(hex_color: str, alpha: float) -> str:
    """Plotly's go.Indicator gauge steps (and a few other props) reject
    8-digit hex-with-alpha strings — this is the shared fix every page
    should use instead of re-deriving it."""
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"


# ---------------------------------------------------------------------
# The brand mark — one faceted-diamond glyph (same silhouette the splash
# screen draws), reused everywhere the app needs a logo instead of the
# generic 🛡️ emoji: the login screen, the dashboard header, and the
# sidebar's own logo slot (via `sidebar_brand()` below). One function
# generates it at any size, so every appearance is pixel-consistent.
# ---------------------------------------------------------------------
def _gem_facets_svg(id_prefix: str, cx: float, cy: float, r: float) -> str:
    top, right, bottom, left = (cx, cy - r), (cx + r, cy), (cx, cy + r), (cx - r, cy)

    def pt(p):
        return f"{p[0]:.1f},{p[1]:.1f}"

    return f"""<defs>
      <linearGradient id="{id_prefix}TL" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stop-color="{GOLD_BRIGHT}"/><stop offset="100%" stop-color="{GOLD}"/>
      </linearGradient>
      <linearGradient id="{id_prefix}TR" x1="1" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="{GOLD}"/><stop offset="100%" stop-color="{GOLD_DEEP}"/>
      </linearGradient>
      <linearGradient id="{id_prefix}BR" x1="1" y1="1" x2="0" y2="0">
        <stop offset="0%" stop-color="{GOLD_DEEP}"/><stop offset="100%" stop-color="#6B5418"/>
      </linearGradient>
      <linearGradient id="{id_prefix}BL" x1="0" y1="1" x2="1" y2="0">
        <stop offset="0%" stop-color="{GOLD}"/><stop offset="100%" stop-color="{GOLD_DEEP}"/>
      </linearGradient>
    </defs>
    <polygon points="{pt(top)} {pt(right)} {cx:.1f},{cy:.1f}" fill="url(#{id_prefix}TR)"/>
    <polygon points="{pt(top)} {pt(left)} {cx:.1f},{cy:.1f}" fill="url(#{id_prefix}TL)"/>
    <polygon points="{pt(right)} {pt(bottom)} {cx:.1f},{cy:.1f}" fill="url(#{id_prefix}BR)"/>
    <polygon points="{pt(left)} {pt(bottom)} {cx:.1f},{cy:.1f}" fill="url(#{id_prefix}BL)"/>
    <polygon points="{pt(top)} {pt(right)} {pt(bottom)} {pt(left)}"
             fill="none" stroke="{GOLD_BRIGHT}" stroke-opacity="0.6" stroke-width="1"/>"""


def gem_svg(size: int = 48, id_prefix: str = "gem") -> str:
    """Inline SVG markup for the faceted-diamond brand mark at any pixel
    size. `id_prefix` must be unique per call site on a given page (SVG
    gradient ids must not collide if two gems render in the same DOM —
    e.g. the splash gem and the login-screen gem can both be present)."""
    r = size * 0.42
    c = size / 2
    inner = _gem_facets_svg(id_prefix, c, c, r)
    return f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" xmlns="http://www.w3.org/2000/svg">{inner}</svg>'


def _write_logo_assets():
    """Regenerates the two static logo files `sidebar_brand()` points
    `st.logo()` at. Written from the same facet geometry as `gem_svg()`
    (not hand-duplicated SVG) so the sidebar logo and every inline gem
    stay visually identical, and so a future palette tweak here updates
    the logo files automatically on next server start. SVG text uses a
    system serif, not the Cormorant Garamond web font: `st.logo()` renders
    the file inside an isolated <img>, which does not fetch external
    @import stylesheets, so a web-font reference would silently fall back
    anyway — Georgia renders identically every time instead."""
    _ASSET_DIR.mkdir(parents=True, exist_ok=True)
    icon_svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48">'
        + _gem_facets_svg("logoIcon", 24, 24, 20)
        + "</svg>"
    )
    (_ASSET_DIR / "logo_icon.svg").write_text(icon_svg, encoding="utf-8")

    full_svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 232 48">
      <defs>
        <linearGradient id="logoFullText" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stop-color="{GOLD_BRIGHT}"/><stop offset="100%" stop-color="{GOLD}"/>
        </linearGradient>
      </defs>
      {_gem_facets_svg("logoFull", 24, 24, 19)}
      <text x="56" y="32" font-family="Georgia, 'Times New Roman', serif" font-size="27"
            font-weight="700" letter-spacing="0.3" fill="url(#logoFullText)">SentinelAI</text>
    </svg>"""
    (_ASSET_DIR / "logo_full.svg").write_text(full_svg, encoding="utf-8")


_write_logo_assets()


def sidebar_brand():
    """Puts the faceted-diamond + "SentinelAI" lockup in the sidebar's
    native logo slot, which Streamlit renders *above* the page nav list —
    the one piece of sidebar real estate no amount of CSS can reach any
    other way. Call once per page, right after `inject_global_styles()`."""
    st.logo(
        str(_ASSET_DIR / "logo_full.svg"),
        icon_image=str(_ASSET_DIR / "logo_icon.svg"),
        size="large",
    )


def page_header(icon: str, eyebrow: str, title: str, subtitle: str, color: str = None):
    """The one page-header component every page should call instead of
    hand-rolling `st.title()` + `st.caption()`: a small color-badged icon,
    an uppercase gem-colored eyebrow label, the serif title in that same
    gem's foil gradient (so each module's header visually announces its
    identity before you've read a word), a one-line subtitle, and a
    thin gradient rule to close the block."""
    color = color or GOLD
    deep = GOLD_DEEP if color == GOLD else f"{color}"
    st.markdown(
        f"""
        <div class="sai-page-header">
          <div class="sai-page-header-row">
            <div class="sai-page-header-badge" style="background:radial-gradient(circle at 32% 28%, {color}40, {OBSIDIAN_1} 75%);
                 border:1px solid {color}66; box-shadow:0 0 18px -4px {color}88;">{icon}</div>
            <div>
              <div class="sai-eyebrow" style="color:{color};">{eyebrow}</div>
              <h1 class="sai-page-title" style="background:linear-gradient(120deg, {INK} 0%, {color} 55%, {deep} 100%);
                  -webkit-background-clip:text; background-clip:text; -webkit-text-fill-color:transparent;">{title}</h1>
            </div>
          </div>
          <div class="sai-page-sub">{subtitle}</div>
          <div class="sai-page-rule" style="background:linear-gradient(90deg, {color}99, {color}22 35%, transparent 75%);"></div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def inject_global_styles():
    st.markdown(
        f"""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@500;600;700&family=Manrope:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

        html, body, [class*="css"], [data-testid="stAppViewContainer"] {{
            font-family: 'Manrope', -apple-system, sans-serif;
        }}
        .sai-serif {{ font-family: 'Cormorant Garamond', Georgia, serif; }}
        .sai-mono {{ font-family: 'JetBrains Mono', monospace; }}

        h1, h2, h3 {{
            font-family: 'Cormorant Garamond', Georgia, serif !important;
            letter-spacing: 0.01em; font-weight: 700 !important;
        }}
        h1 {{
            background: linear-gradient(120deg, {GOLD_BRIGHT} 0%, {GOLD} 45%, {GOLD_DEEP} 100%);
            -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
            filter: drop-shadow(0 1px 12px {GOLD}22);
        }}
        p, li, label, [data-testid="stCaptionContainer"] {{ line-height: 1.6; }}

        /* ---- whole-app background: obsidian with two faint ambient-light
           pools, like gallery spotlighting on a dark showroom floor ---- */
        [data-testid="stAppViewContainer"] > .main {{
            background:
                radial-gradient(ellipse 900px 500px at 8% -5%, {GOLD}14, transparent 60%),
                radial-gradient(ellipse 800px 600px at 100% 15%, {EMERALD}0d, transparent 55%),
                radial-gradient(ellipse 700px 500px at 50% 100%, {AMETHYST}0a, transparent 55%),
                {OBSIDIAN_0};
        }}
        [data-testid="stHeader"] {{ background: transparent; }}

        /* ---- sidebar: darker obsidian, gold right hairline ---- */
        [data-testid="stSidebar"] {{
            background: linear-gradient(180deg, {OBSIDIAN_1} 0%, {OBSIDIAN_0} 100%) !important;
            border-right: 1px solid {GOLD_LINE};
        }}

        /* ---- sidebar logo slot (st.logo(), via sidebar_brand()) — the
           only part of the sidebar that renders ABOVE the page nav, so
           this is where the brand lockup lives instead of a bare nav
           list with no identity at the top. ---- */
        [data-testid="stSidebarHeader"] {{
            padding: 20px 20px 16px 20px !important;
            border-bottom: 1px solid {GOLD_LINE};
            margin-bottom: 6px;
        }}
        [data-testid="stSidebarHeader"] img {{
            filter: drop-shadow(0 0 10px {GOLD}55);
        }}
        [data-testid="stSidebarCollapseButton"] button {{
            color: {MUTED} !important;
        }}

        /* ---- sidebar nav: a small gem-colored dot per module (matching
           that module's identity color everywhere else in the app) plus
           a proper gold "you are here" treatment. Streamlit 1.41 doesn't
           mark the current page with aria-current — it only varies the
           link's own emotion-cache class — so the active rule below is
           pinned to that exact generated class name; it degrades to just
           losing the extra emphasis (never to a broken look) if a future
           Streamlit upgrade changes it. The href-suffix selectors are
           version-proof since they just key off the page's own slug. ---- */
        [data-testid="stSidebarNavLink"] {{
            border-radius: 10px !important; margin: 2px 8px !important;
            padding: 10px 14px !important;
            transition: background 0.2s ease, padding-left 0.2s ease;
        }}
        [data-testid="stSidebarNavLink"] span {{ font-weight: 500 !important; }}
        [data-testid="stSidebarNavLink"]:hover {{
            background: {GOLD}14 !important; padding-left: 18px !important;
        }}
        [data-testid="stSidebarNavLink"]::before {{
            content: ""; display: inline-block; width: 7px; height: 7px; border-radius: 50%;
            margin-right: 11px; vertical-align: middle; background: {MUTED_DIM};
        }}
        a[data-testid="stSidebarNavLink"][href$="/Home"]::before {{
            background: {GOLD}; box-shadow: 0 0 6px 1px {GOLD}99;
        }}
        a[data-testid="stSidebarNavLink"][href$="/Network_IDS"]::before {{
            background: {SAPPHIRE}; box-shadow: 0 0 6px 1px {SAPPHIRE}99;
        }}
        a[data-testid="stSidebarNavLink"][href$="/Phishing_Detector"]::before {{
            background: {TOPAZ}; box-shadow: 0 0 6px 1px {TOPAZ}99;
        }}
        a[data-testid="stSidebarNavLink"][href$="/Malware_Scanner"]::before {{
            background: {RUBY}; box-shadow: 0 0 6px 1px {RUBY}99;
        }}
        a[data-testid="stSidebarNavLink"][href$="/Vulnerability_Scanner"]::before {{
            background: {AMETHYST}; box-shadow: 0 0 6px 1px {AMETHYST}99;
        }}
        a[data-testid="stSidebarNavLink"][href$="/Secure_Vault"]::before {{
            background: {EMERALD}; box-shadow: 0 0 6px 1px {EMERALD}99;
        }}
        [data-testid="stSidebarNav"] a[aria-current="page"],
        .st-emotion-cache-zp31zu {{
            background: linear-gradient(90deg, {GOLD}22, transparent) !important;
            box-shadow: inset 3px 0 0 0 {GOLD} !important;
            font-weight: 700 !important;
        }}
        [data-testid="stSidebarNav"] a[aria-current="page"] span,
        .st-emotion-cache-zp31zu span {{ color: {GOLD_BRIGHT} !important; }}

        /* ---- page header (page_header()) ---- */
        .sai-page-header {{ margin: 2px 0 22px 0; }}
        .sai-page-header-row {{ display: flex; align-items: center; gap: 16px; }}
        .sai-page-header-badge {{
            flex: none; width: 52px; height: 52px; border-radius: 16px;
            display: flex; align-items: center; justify-content: center;
            font-size: 1.5rem;
        }}
        .sai-eyebrow {{
            font-size: 0.74rem; font-weight: 700; letter-spacing: 0.22em; text-transform: uppercase;
            margin-bottom: 2px;
        }}
        .sai-page-title {{
            font-size: 2.1rem !important; margin: 0 !important; line-height: 1.15 !important;
        }}
        .sai-page-sub {{
            color: {MUTED}; font-size: 0.95rem; margin: 10px 0 0 68px; max-width: 760px;
        }}
        .sai-page-rule {{
            height: 1px; margin: 16px 0 0 0; border-radius: 1px;
        }}

        /* ---- explainer / "what this does" box — glass card ---- */
        .sai-intro {{
            border: 1px solid {GOLD_LINE};
            border-radius: 16px;
            background: linear-gradient(135deg, {GOLD}12, {SURFACE} 65%);
            backdrop-filter: blur(12px);
            padding: 18px 22px;
            margin: 4px 0 20px 0;
        }}
        .sai-intro h4 {{
            margin: 0 0 6px 0; font-size: 1.1rem; font-weight: 700; color: {GOLD_BRIGHT};
            font-family: 'Cormorant Garamond', Georgia, serif;
        }}
        .sai-intro p {{
            margin: 0; color: {INK}; opacity: 0.92; font-size: 0.95rem; line-height: 1.6;
        }}
        .sai-intro p + p {{ margin-top: 8px; }}

        /* ---- plain-language result translation callout ---- */
        .sai-translate {{
            border-left: 3px solid {GOLD};
            background: {GOLD}14;
            padding: 11px 15px;
            border-radius: 0 10px 10px 0;
            font-size: 0.92rem;
            color: {INK};
            margin: 10px 0 16px 0;
            line-height: 1.55;
        }}

        /* ---- generic glass card ---- */
        .sai-card {{
            border: 1px solid {SURFACE_LINE};
            border-radius: 14px;
            background: linear-gradient(160deg, {OBSIDIAN_2}, {OBSIDIAN_1});
            padding: 16px 18px;
            transition: transform 0.25s ease, box-shadow 0.25s ease, border-color 0.25s ease;
        }}

        /* ---- chip ---- */
        .sai-chip {{
            display: inline-block; padding: 3px 12px; border-radius: 999px;
            font-size: 0.78rem; font-weight: 600; white-space: nowrap;
            letter-spacing: 0.01em;
        }}

        /* ---- restyle Streamlit's own native widgets so gold is
           deliberate everywhere, not the stock default accent ---- */
        [data-testid="stForm"] {{
            border: 1px solid {GOLD_LINE} !important;
            border-radius: 18px !important;
            padding: 24px 26px 12px 26px !important;
            background: linear-gradient(160deg, {OBSIDIAN_1}, {OBSIDIAN_0}) !important;
            box-shadow: 0 20px 60px -20px #00000099;
        }}
        [data-testid="stMetric"] {{
            background: linear-gradient(160deg, {OBSIDIAN_2}, {OBSIDIAN_1});
            border: 1px solid {SURFACE_LINE};
            border-radius: 14px;
            padding: 14px 16px 10px 16px;
            transition: border-color 0.25s ease;
        }}
        [data-testid="stMetric"]:hover {{ border-color: {GOLD_LINE}; }}
        [data-testid="stMetricLabel"] {{ color: {MUTED} !important; }}
        [data-testid="stMetricValue"] {{ font-family: 'Cormorant Garamond', Georgia, serif !important; }}
        div[data-testid="stExpander"] {{
            border: 1px solid {SURFACE_LINE} !important;
            border-radius: 14px !important;
            background: linear-gradient(160deg, {OBSIDIAN_2}, {OBSIDIAN_1}) !important;
            overflow: hidden;
        }}
        div[data-testid="stExpander"] summary {{
            font-weight: 600 !important;
        }}

        /* ---- buttons: gold gradient fill (primary) / gold outline glass
           (secondary) with a light-sweep shimmer on hover ----
           Streamlit renders form-submit buttons with kind values like
           "primaryFormSubmit" / "secondaryFormSubmit" rather than plain
           "primary" / "secondary", so these use substring (*=) matches
           to catch every variant (primary, primaryFormSubmit, secondary,
           secondaryFormSubmit, header, headerNoPadding, ...). */
        button[kind*="primary"] {{
            border-radius: 11px !important;
            font-weight: 700 !important;
            border: 1px solid {GOLD_DEEP} !important;
            background: linear-gradient(135deg, {GOLD_BRIGHT}, {GOLD} 55%, {GOLD_DEEP}) !important;
            color: {OBSIDIAN_0} !important;
            box-shadow: 0 6px 18px -6px {GOLD}66;
            position: relative; overflow: hidden;
            transition: transform 0.18s ease, box-shadow 0.18s ease;
        }}
        button[kind*="primary"]:hover {{
            transform: translateY(-1px);
            box-shadow: 0 10px 26px -6px {GOLD}99;
            filter: brightness(1.05);
        }}
        button[kind*="secondary"] {{
            border-radius: 11px !important;
            font-weight: 600 !important;
            border: 1px solid {GOLD_LINE} !important;
            background: {GOLD}0d !important;
            color: {GOLD_BRIGHT} !important;
            transition: background 0.2s ease, border-color 0.2s ease;
        }}
        button[kind*="secondary"]:hover {{
            background: {GOLD}1f !important;
            border-color: {GOLD} !important;
        }}

        /* ---- text inputs / selects / text areas: dark glass, gold focus ---- */
        [data-testid="stTextInput"] input, [data-testid="stTextArea"] textarea,
        [data-testid="stNumberInput"] input, div[data-baseweb="select"] > div {{
            background: {OBSIDIAN_1} !important;
            border: 1px solid {SURFACE_LINE} !important;
            border-radius: 10px !important;
            color: {INK} !important;
        }}
        [data-testid="stTextInput"] input:focus, [data-testid="stTextArea"] textarea:focus,
        [data-testid="stNumberInput"] input:focus {{
            border-color: {GOLD} !important;
            box-shadow: 0 0 0 1px {GOLD}55 !important;
        }}

        /* ---- alert boxes (st.info/warning/error/success): dark glass
           instead of Streamlit's stock flat color fills, with a thin
           left rule in the matching gem tone so the semantics still
           read at a glance ---- */
        [data-testid="stAlertContainer"] {{
            background: linear-gradient(160deg, {OBSIDIAN_2}, {OBSIDIAN_1} 75%) !important;
            border: 1px solid {SURFACE_LINE} !important;
            border-left: 3px solid {SAPPHIRE} !important;
            border-radius: 10px !important;
            color: {INK_SECONDARY} !important;
        }}
        [data-testid="stAlertContainer"]:has([data-testid="stAlertContentInfo"]) {{
            border-left-color: {SAPPHIRE} !important;
        }}
        [data-testid="stAlertContainer"]:has([data-testid="stAlertContentWarning"]) {{
            border-left-color: {TOPAZ} !important;
        }}
        [data-testid="stAlertContainer"]:has([data-testid="stAlertContentError"]) {{
            border-left-color: {RUBY} !important;
        }}
        [data-testid="stAlertContainer"]:has([data-testid="stAlertContentSuccess"]) {{
            border-left-color: {EMERALD} !important;
        }}
        [data-testid="stAlertContainer"] [data-testid="stMarkdownContainer"] p {{
            color: {INK_SECONDARY} !important;
        }}

        /* ---- tabs: gold underline instead of stock accent ---- */
        button[data-baseweb="tab"] {{ font-weight: 600 !important; }}
        [data-baseweb="tab-highlight"] {{ background-color: {GOLD} !important; }}
        button[data-baseweb="tab"][aria-selected="true"] {{ color: {GOLD_BRIGHT} !important; }}

        /* ---- slider handle/track ---- */
        div[data-testid="stSlider"] [role="slider"] {{ background-color: {GOLD} !important; }}
        div[data-testid="stSlider"] .st-ae {{ background-color: {GOLD}55 !important; }}

        /* ---- progress bar / spinner ---- */
        div[data-testid="stProgress"] > div > div {{ background-color: {GOLD} !important; }}

        /* ---- divider: gold gradient fade instead of flat gray ---- */
        [data-testid="stDivider"], hr {{
            border: none !important; height: 1px !important;
            background: linear-gradient(90deg, transparent, {GOLD_LINE} 20%, {GOLD_LINE} 80%, transparent) !important;
            margin: 1.4rem 0 !important;
        }}

        /* ---- scrollbar: thin obsidian track, gold thumb ---- */
        ::-webkit-scrollbar {{ width: 10px; height: 10px; }}
        ::-webkit-scrollbar-track {{ background: {OBSIDIAN_0}; }}
        ::-webkit-scrollbar-thumb {{
            background: linear-gradient(180deg, {GOLD_DEEP}, {GOLD}); border-radius: 10px;
            border: 2px solid {OBSIDIAN_0};
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
            border: 1px solid {GOLD_LINE};
            overflow: hidden; margin: 0 auto;
        }}
        .sai-radar .sai-radar-ring {{
            position: absolute; border: 1px solid {SURFACE_LINE}; border-radius: 50%;
            top: 50%; left: 50%; transform: translate(-50%, -50%);
        }}
        .sai-radar .sai-radar-sweep {{
            position: absolute; inset: 0;
            background: conic-gradient(from 0deg, {GOLD}4d, transparent 70deg, transparent 360deg);
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
            text-transform: uppercase; letter-spacing: 0.05em;
            padding: 6px 10px; border-bottom: 1px solid {SURFACE_LINE};
        }}
        .sai-table td {{
            padding: 7px 10px; border-bottom: 1px solid {SURFACE_LINE}55; color: {INK};
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

        /* ---- luxury splash / loading screen (used by luxury_splash()) ---- */
        .sai-splash {{
            position: fixed; inset: 0; z-index: 99999; pointer-events: none;
            display: flex; flex-direction: column; align-items: center; justify-content: center;
            background:
                radial-gradient(ellipse 60% 50% at 50% 40%, {GOLD}1a, transparent 70%),
                {OBSIDIAN_0};
            animation: sai-splash-out 0.6s ease forwards;
            animation-delay: 2.5s;
        }}
        @keyframes sai-splash-out {{
            0% {{ opacity: 1; }}
            100% {{ opacity: 0; visibility: hidden; }}
        }}
        .sai-gem-wrap {{ position: relative; width: 130px; height: 130px; }}
        .sai-gem-wrap svg {{ width: 100%; height: 100%; filter: drop-shadow(0 0 22px {GOLD}55); }}
        .sai-gem-facet {{
            opacity: 0; transform-origin: 60px 60px;
            animation: sai-facet-in 0.5s ease forwards;
        }}
        .sai-gem-facet.f1 {{ animation-delay: 0.05s; }}
        .sai-gem-facet.f2 {{ animation-delay: 0.18s; }}
        .sai-gem-facet.f3 {{ animation-delay: 0.31s; }}
        .sai-gem-facet.f4 {{ animation-delay: 0.44s; }}
        @keyframes sai-facet-in {{
            0% {{ opacity: 0; transform: scale(0.6); }}
            60% {{ opacity: 1; }}
            100% {{ opacity: 1; transform: scale(1); }}
        }}
        .sai-gem-outline {{
            opacity: 0; animation: sai-outline-in 0.6s ease 0.6s forwards;
        }}
        @keyframes sai-outline-in {{ to {{ opacity: 1; }} }}
        .sai-gem-sheen {{
            animation: sai-sheen-sweep 2.2s ease-in-out 0.9s infinite;
        }}
        @keyframes sai-sheen-sweep {{
            0%, 100% {{ opacity: 0; transform: translateX(-30px); }}
            45% {{ opacity: 0.9; transform: translateX(30px); }}
            60% {{ opacity: 0; }}
        }}
        .sai-spark {{
            position: absolute; color: {GOLD_BRIGHT}; font-size: 14px; opacity: 0;
            animation: sai-twinkle 1.6s ease-in-out infinite;
            text-shadow: 0 0 8px {GOLD};
        }}
        @keyframes sai-twinkle {{
            0%, 100% {{ opacity: 0; transform: scale(0.4) rotate(0deg); }}
            50% {{ opacity: 1; transform: scale(1) rotate(15deg); }}
        }}
        .sai-splash-title {{
            font-family: 'Cormorant Garamond', Georgia, serif;
            font-size: 2.6rem; font-weight: 700; letter-spacing: 0.06em;
            margin-top: 22px; opacity: 0;
            background: linear-gradient(120deg, {GOLD_BRIGHT}, {GOLD} 50%, {GOLD_DEEP});
            -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
            animation: sai-rise-in 0.7s ease 0.85s forwards;
        }}
        .sai-splash-subtitle {{
            color: {MUTED}; font-size: 0.82rem; letter-spacing: 0.22em; text-transform: uppercase;
            margin-top: 8px; opacity: 0;
            animation: sai-rise-in 0.7s ease 1.15s forwards;
        }}
        @keyframes sai-rise-in {{
            0% {{ opacity: 0; transform: translateY(8px); }}
            100% {{ opacity: 1; transform: translateY(0); }}
        }}
        .sai-splash-bar {{
            width: 160px; height: 2px; margin-top: 26px; border-radius: 2px;
            background: {SURFACE_LINE}; overflow: hidden; opacity: 0;
            animation: sai-rise-in 0.4s ease 1.4s forwards;
        }}
        .sai-splash-bar-fill {{
            height: 100%; width: 0%; border-radius: 2px;
            background: linear-gradient(90deg, {GOLD_DEEP}, {GOLD_BRIGHT});
            animation: sai-bar-fill 1.0s cubic-bezier(.3,.6,.3,1) 1.45s forwards;
        }}
        @keyframes sai-bar-fill {{ to {{ width: 100%; }} }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def luxury_splash():
    """A once-per-session animated gem-facet loading screen: a faceted
    diamond draws itself in facet-by-facet, catches a gold sheen sweep,
    then the SentinelAI wordmark rises in gold foil beneath it while a
    thin gold progress line fills. The whole overlay auto-fades after
    ~2.5s via pure CSS (no JS, no blocking) and `pointer-events: none`
    from frame one, so an impatient visitor can click straight through
    it to the login form underneath rather than waiting it out.

    Call once, at the very top of the entry-point page (Home.py), gated
    on `st.session_state` so a rerun (e.g. after submitting the login
    form) never replays it mid-session."""
    if st.session_state.get("_sai_splash_shown"):
        return
    st.session_state["_sai_splash_shown"] = True
    sparks = [
        (18, 14, "0.1s"), (108, 22, "0.5s"), (12, 96, "0.9s"),
        (112, 100, "0.3s"), (62, 2, "0.7s"),
    ]
    spark_html = "".join(
        f'<span class="sai-spark" style="left:{x}px;top:{y}px;animation-delay:{d};">✦</span>'
        for x, y, d in sparks
    )
    st.markdown(
        f"""
        <div class="sai-splash">
          <div class="sai-gem-wrap">
            {spark_html}
            <svg viewBox="0 0 120 120">
              <defs>
                <linearGradient id="saiF1" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stop-color="{GOLD_BRIGHT}"/><stop offset="100%" stop-color="{GOLD}"/>
                </linearGradient>
                <linearGradient id="saiF2" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stop-color="{GOLD}"/><stop offset="100%" stop-color="{GOLD_DEEP}"/>
                </linearGradient>
                <linearGradient id="saiF3" x1="1" y1="0" x2="0" y2="1">
                  <stop offset="0%" stop-color="{GOLD}"/><stop offset="100%" stop-color="{GOLD_DEEP}"/>
                </linearGradient>
                <linearGradient id="saiF4" x1="1" y1="1" x2="0" y2="0">
                  <stop offset="0%" stop-color="{GOLD_DEEP}"/><stop offset="100%" stop-color="{GOLD}"/>
                </linearGradient>
                <clipPath id="saiGemClip"><polygon points="60,10 108,50 60,112 12,50"/></clipPath>
              </defs>
              <polygon class="sai-gem-facet f1" points="60,10 12,50 60,50" fill="url(#saiF1)"/>
              <polygon class="sai-gem-facet f2" points="60,10 60,50 108,50" fill="url(#saiF2)"/>
              <polygon class="sai-gem-facet f3" points="12,50 60,50 60,112" fill="url(#saiF3)"/>
              <polygon class="sai-gem-facet f4" points="108,50 60,50 60,112" fill="url(#saiF4)"/>
              <polygon class="sai-gem-outline" points="60,10 108,50 60,112 12,50"
                       fill="none" stroke="{GOLD_BRIGHT}" stroke-width="1.5"/>
              <line class="sai-gem-outline" x1="12" y1="50" x2="108" y2="50" stroke="{GOLD_BRIGHT}" stroke-width="1"/>
              <line class="sai-gem-outline" x1="60" y1="10" x2="60" y2="112" stroke="{GOLD_BRIGHT}" stroke-width="0.6" opacity="0.5"/>
              <g clip-path="url(#saiGemClip)">
                <rect class="sai-gem-sheen" x="40" y="0" width="14" height="120" fill="{INK}" opacity="0.5" transform="skewX(-20)"/>
              </g>
            </svg>
          </div>
          <div class="sai-splash-title">SentinelAI</div>
          <div class="sai-splash-subtitle">AI-Powered Security Operations</div>
          <div class="sai-splash-bar"><div class="sai-splash-bar-fill"></div></div>
        </div>
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
        bg = f"linear-gradient(135deg, {color}26, {SURFACE} 70%)" if is_hl else f"linear-gradient(160deg, {OBSIDIAN_2}, {OBSIDIAN_1})"
        glow = f"box-shadow: 0 0 14px {color}55;" if is_hl else ""
        with col:
            st.markdown(
                f"""
                <div class="sai-card" style="border:{border}; background:{bg}; {glow}
                     text-align:center; padding:12px 8px;">
                    <div style="font-size:1.4rem;">{card.get('icon', '')}</div>
                    <div style="font-weight:700; font-size:0.85rem; color:{INK}; margin-top:2px;">{card.get('title', '')}</div>
                    <div style="font-size:0.75rem; color:{MUTED}; margin-top:2px;">{card.get('desc', '')}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
