"""
Network Intrusion Detection page.

Rebuilt per direction change: no manual feature-entry form (too technical
for a non-technical, zero-reading audience), no explanatory text walls.
The whole page is one live scene — real HTTP requests reaching this app's
own backend get classified by the trained NSL-KDD model the instant they
arrive, and the result is shown by literally sorting each one into one of
five labeled bins, live, with nothing to read first. Same model, same
backend, same honest "HTTP-layer, not packet-layer" scope as before — only
the presentation changed. The deep-dive material (SHAP explanations, the
honest "what live really means" disclosure) is kept, just folded into
collapsed, opt-in sections at the bottom for anyone who wants it.
"""
import json
from datetime import datetime

import plotly.express as px
import streamlit as st
import pandas as pd
import streamlit.components.v1 as components

from _backend_bootstrap import ensure_backend
from api_client import api_get, api_post, is_admin, require_login
from theme import SEVERITY, inject_global_styles

st.set_page_config(page_title="Network IDS — SentinelAI", page_icon="🌐", layout="wide")
ensure_backend()
require_login()
inject_global_styles()

st.title("🌐 Network Intrusion Detection")
st.caption("Watch it sort, don't read it — real traffic to this app, classified live.")

# Bin identity — deliberately its own small palette (validated as a concept
# with the user before this build): teal doubles as both "Normal" and the
# scene's own brand/interactive color, the four attack types each get a
# distinct hue. Kept local to this page rather than theme.py's ATTACK_COLORS
# because the rest of the platform hasn't moved to this token set yet.
_CATS = ["normal", "dos", "probe", "r2l", "u2r"]
_BIN_COLORS = {"normal": "#2FE0A8", "dos": "#E0344F", "probe": "#FFA940", "r2l": "#B37FEF", "u2r": "#6B6355"}
_BIN_LABELS = {"normal": "Normal", "dos": "DoS", "probe": "Probe", "r2l": "R2L", "u2r": "U2R"}
_LABEL_WORD = {"normal": "normal", "dos": "DoS", "probe": "probe", "r2l": "R2L", "u2r": "U2R"}


def _render_shap_chart(explanation: list[dict], height: int = 220) -> None:
    exp_df = pd.DataFrame(explanation)
    exp_df["direction"] = exp_df["impact"].apply(lambda x: "Pushes toward attack" if x > 0 else "Pushes toward normal")
    fig = px.bar(
        exp_df.sort_values("impact"), x="impact", y="feature", orientation="h",
        color="direction", color_discrete_map={"Pushes toward attack": SEVERITY["High"], "Pushes toward normal": SEVERITY["Low"]},
    )
    fig.update_layout(
        height=height, yaxis_title="", xaxis_title="SHAP impact", margin=dict(t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font={"color": "#F4EFE3"},
        legend_title_text="",
    )
    st.plotly_chart(fig, use_container_width=True)


_CONSOLE_TEMPLATE = r"""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@500;600;700&family=Manrope:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
  *{box-sizing:border-box}
  html,body{margin:0;background:transparent;overflow:hidden;}
  body{
    font-family:'Manrope', system-ui, sans-serif; color:#F4EFE3;
    padding:2px;
  }
  .mono{ font-family:'JetBrains Mono', monospace; font-variant-numeric: tabular-nums; }
  .display{ font-family:'Cormorant Garamond', Georgia, serif; }

  .console{
    background: linear-gradient(180deg, #0F1115 0%, #07080B 120%);
    border:1px solid #2A2418; border-radius:18px;
    padding: 22px clamp(14px, 3vw, 30px) 20px;
    display:flex; flex-direction:column; gap:18px;
    position:relative; overflow:hidden;
  }
  .console::before{
    content:""; position:absolute; inset:0;
    background: radial-gradient(600px 220px at 12% -15%, color-mix(in srgb, #2FE0A8 10%, transparent), transparent 60%);
    pointer-events:none;
  }
  .console-head{ display:flex; align-items:center; gap:8px; position:relative; }
  .status-dot{ width:8px; height:8px; border-radius:50%; background:#2FE0A8; flex-shrink:0; }
  .status-dot.live{ animation: dot-pulse 1.8s ease-in-out infinite; }
  .status-dot.paused{ background:#6B6355; }
  @keyframes dot-pulse{ 0%,100%{ box-shadow:0 0 0 0 #2FE0A866 } 50%{ box-shadow:0 0 0 6px #2FE0A800 } }
  .console-head span{ font-size:0.74rem; color:#A39A87; letter-spacing:0.01em; }

  .lane{
    position:relative; height:128px; border-radius:14px;
    background:#07080B; border:1px solid #2A2418; overflow:visible;
  }
  .source{
    position:absolute; left:16px; top:50%; translate:0 -50%;
    display:flex; flex-direction:column; align-items:center; gap:6px; width:58px;
  }
  .source .dot{
    width:32px; height:32px; border-radius:50%;
    background: radial-gradient(circle at 35% 30%, #3A3020, #161920);
    border:1px solid #2A2418; display:flex; align-items:center; justify-content:center;
    animation: breathe 2.4s ease-in-out infinite;
  }
  .source svg{ width:15px; height:15px; stroke:#2FE0A8; }
  .source span{ font-size:0.66rem; color:#A39A87; }
  @keyframes breathe{ 0%,100%{ box-shadow:0 0 0 0 #2FE0A822 } 50%{ box-shadow:0 0 0 7px #2FE0A800 } }

  .gate{
    position:absolute; left:46%; top:8%; bottom:8%; width:3px;
    background: linear-gradient(180deg, transparent, #2A2418 20%, #2A2418 80%, transparent);
    border-radius:2px; transition:opacity 0.4s ease;
  }
  .gate::after{
    content:""; position:absolute; left:50%; top:0; width:16px; height:100%;
    translate:-50% 0; background: linear-gradient(180deg, transparent, #2FE0A84D, transparent);
    animation: scan 2.6s linear infinite;
  }
  .gate.paused::after{ animation-play-state: paused; opacity:0.25; }
  @keyframes scan{ 0%{ transform:translateY(-110%) translateX(-50%) } 100%{ transform:translateY(110%) translateX(-50%) } }
  .gate.flash::after{ animation-duration:0.45s; }
  .gate .glabel{ position:absolute; bottom:-20px; left:50%; translate:-50% 0; font-size:0.64rem; color:#A39A87; white-space:nowrap; }

  .particle{
    position:absolute; top:50%; left:2%; width:9px; height:9px; border-radius:50%;
    translate:-50% -50%; background:#A39A87; box-shadow:0 0 0 0 transparent;
    transition: left 0.8s cubic-bezier(.4,.1,.3,1), top 0.8s cubic-bezier(.4,.1,.3,1),
                background-color 0.22s linear, box-shadow 0.22s linear, scale 0.55s ease;
    z-index:3;
  }
  .ripple{
    position:absolute; width:8px; height:8px; border-radius:50%;
    translate:-50% -50%; border:1.5px solid var(--c); pointer-events:none;
    animation: ripple-out 0.6s ease-out forwards; z-index:2;
  }
  @keyframes ripple-out{ 0%{ transform:translate(-50%,-50%) scale(1); opacity:0.9 } 100%{ transform:translate(-50%,-50%) scale(4.2); opacity:0 } }

  .bins{ display:grid; grid-template-columns: repeat(5, minmax(0,1fr)); gap:clamp(6px,1.4vw,10px); }
  .bin{
    background:#0F1115; border:1px solid #2A2418; border-radius:12px;
    padding:9px 6px 10px; display:flex; flex-direction:column; align-items:center; gap:6px;
    position:relative; min-width:0; transition: transform 0.25s ease;
  }
  .bin.landed{ transform: translateY(-2px); }
  .bin .well{
    width:100%; height:52px; border-radius:8px; background:#07080B;
    border:1px solid #2A2418; position:relative; overflow:hidden;
  }
  .bin .fill{
    position:absolute; left:0; right:0; bottom:0; height:4%;
    transition: height 0.5s cubic-bezier(.3,.6,.3,1);
    background: linear-gradient(180deg, color-mix(in srgb, var(--c) 85%, transparent), color-mix(in srgb, var(--c) 35%, transparent));
  }
  .bin .well::after{
    content:""; position:absolute; inset:0; border-radius:8px;
    box-shadow: inset 0 1px 0 0 #F4EFE314; pointer-events:none;
  }
  .bin.landed .well{ box-shadow: inset 0 0 0 1px var(--c), 0 0 14px -3px var(--c); }
  .bin .count{ font-size:clamp(0.95rem,2.4vw,1.2rem); font-weight:600; line-height:1; color:var(--c); }
  .bin .label{ font-size:clamp(0.62rem,1.6vw,0.72rem); color:#A39A87; font-weight:500; white-space:nowrap; }

  .caption{ color:#A39A87; font-size:0.78rem; }

  @media (prefers-reduced-motion: reduce){
    .particle{ transition-duration:0.01s !important; }
    .gate::after, .source .dot{ animation:none !important; }
  }
</style>

<div class="console">
  <div class="console-head">
    <div class="status-dot __STATUS_CLASS__"></div>
    <span>__STATUS_TEXT__</span>
  </div>
  <div class="lane" id="lane">
    <div class="source">
      <div class="dot">
        <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round"><path d="M12 20v-6M5 10a7 7 0 0 1 14 0M8 13a4 4 0 0 1 8 0"/></svg>
      </div>
      <span>traffic</span>
    </div>
    <div class="gate __GATE_CLASS__" id="gate"><span class="glabel">model</span></div>
  </div>
  <div class="bins" id="bins">
    __BINS_HTML__
  </div>
  <span class="caption">Every dot is one real request to this app's backend, sorted the instant the model reads it.</span>
</div>

<script>
(function(){
  const payload = __PAYLOAD_JSON__;
  const lane = document.getElementById('lane');
  const gate = document.getElementById('gate');
  const bins = Array.from(document.querySelectorAll('.bin'));
  const binByKey = Object.fromEntries(bins.map(b => [b.dataset.k, b]));
  const laneRect = () => lane.getBoundingClientRect();

  function binCenterX(key){
    const b = binByKey[key]; if(!b) return 50;
    const br = b.getBoundingClientRect(); const lr = laneRect();
    return ((br.left + br.width/2) - lr.left) / lr.width * 100;
  }

  function setBin(key, count){
    const bin = binByKey[key]; if(!bin) return;
    bin.querySelector('.count').textContent = count;
    const sat = 1 - Math.exp(-count/6);
    bin.querySelector('.fill').style.height = Math.max(4, sat*100) + '%';
  }

  function landFlash(key){
    const bin = binByKey[key]; if(!bin) return;
    bin.classList.add('landed');
    clearTimeout(bin._t);
    bin._t = setTimeout(()=>bin.classList.remove('landed'), 480);
    const well = bin.querySelector('.well');
    const r = document.createElement('div');
    r.className = 'ripple';
    r.style.setProperty('--c', getComputedStyle(bin).getPropertyValue('--c'));
    r.style.left = '50%'; r.style.top = '50%';
    well.appendChild(r);
    setTimeout(()=>r.remove(), 650);
  }

  // settle to the pre-existing totals with a brief count-up, purely cosmetic
  Object.keys(payload.prevCounts).forEach(key => {
    const target = payload.prevCounts[key];
    let shown = 0;
    if (target === 0) { setBin(key, 0); return; }
    const start = performance.now(), dur = 550;
    function step(t){
      const p = Math.min(1, (t - start) / dur);
      const eased = 1 - Math.pow(1 - p, 3);
      const val = Math.round(target * eased);
      if (val !== shown) { shown = val; setBin(key, val); }
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  });

  const running = { ...payload.prevCounts };

  function spawn(key, delay){
    setTimeout(() => {
      const p = document.createElement('div');
      p.className = 'particle';
      lane.appendChild(p);
      requestAnimationFrame(() => { p.style.left = '45%'; p.style.top = '50%'; });
      setTimeout(() => {
        if (!gate.classList.contains('paused')) {
          gate.classList.add('flash');
          setTimeout(()=>gate.classList.remove('flash'), 450);
        }
        const c = payload.colors[key] || '#A39A87';
        p.style.background = c;
        p.style.boxShadow = '0 0 10px 1px ' + c;
        p.style.left = binCenterX(key) + '%';
        p.style.top = '90%';
        p.style.scale = '0.6';
        setTimeout(() => {
          running[key] = (running[key] || 0) + 1;
          setBin(key, running[key]);
          landFlash(key);
          p.remove();
        }, 780);
      }, 780);
    }, delay);
  }

  (payload.newItems || []).forEach((key, i) => spawn(key, i * 190));
})();
</script>
"""


def _build_console_html(prev_counts: dict, new_items: list[str], monitor_enabled: bool) -> str:
    bins_html = "".join(
        f'<div class="bin" data-k="{k}" style="--c:{_BIN_COLORS[k]}">'
        f'<div class="well"><div class="fill"></div></div>'
        f'<div class="count mono">0</div><div class="label">{_BIN_LABELS[k]}</div></div>'
        for k in _CATS
    )
    payload = {
        "prevCounts": {k: int(prev_counts.get(k, 0)) for k in _CATS},
        "newItems": new_items,
        "colors": _BIN_COLORS,
    }
    html = _CONSOLE_TEMPLATE
    html = html.replace("__STATUS_CLASS__", "live" if monitor_enabled else "paused")
    html = html.replace("__STATUS_TEXT__", "watching live traffic" if monitor_enabled else "monitor paused")
    html = html.replace("__GATE_CLASS__", "" if monitor_enabled else "paused")
    html = html.replace("__BINS_HTML__", bins_html)
    html = html.replace("__PAYLOAD_JSON__", json.dumps(payload))
    return html


status = api_get("/network-ids/status").json()
if not status.get("model_loaded"):
    st.error("Model not loaded on the backend yet.")
    st.stop()

# ---------------------------------------------------------------------
# Pull real traffic since this browser session last looked, tally it into
# running per-category totals (persisted in session_state so a rerun never
# re-plays history), and hand only the genuinely NEW entries to the scene
# to animate. First-ever load of a session treats everything already
# logged as silent baseline, not a sudden burst of "new" activity.
# ---------------------------------------------------------------------
if "nids_bin_counts" not in st.session_state:
    st.session_state.nids_bin_counts = {k: 0 for k in _CATS}
    st.session_state.nids_last_seen_id = 0
    st.session_state.nids_seeded = False

feed_resp = api_get("/network-ids/live-feed", params={"limit": 100})
if feed_resp.status_code != 200:
    st.error(f"Could not reach the live feed: {feed_resp.text}")
    st.stop()

feed = feed_resp.json()
items = feed["items"]  # newest-first
monitor_enabled = feed["monitor_enabled"]

if not st.session_state.nids_seeded:
    # First time this browser session has looked: fold everything already
    # logged into the baseline, no animation.
    for it in items:
        if it["label"]:
            st.session_state.nids_bin_counts[it["label"]] = st.session_state.nids_bin_counts.get(it["label"], 0) + 1
    if items:
        st.session_state.nids_last_seen_id = max(it["id"] for it in items)
    st.session_state.nids_seeded = True
    new_entries_chrono = []
else:
    new_entries = [it for it in items if it["id"] > st.session_state.nids_last_seen_id]
    new_entries_chrono = list(reversed(new_entries))  # oldest-first, for animation order
    if items:
        st.session_state.nids_last_seen_id = max(st.session_state.nids_last_seen_id, max(it["id"] for it in items))

prev_counts = dict(st.session_state.nids_bin_counts)
for it in new_entries_chrono:
    if it["label"]:
        st.session_state.nids_bin_counts[it["label"]] = st.session_state.nids_bin_counts.get(it["label"], 0) + 1

new_item_labels = [it["label"] for it in new_entries_chrono if it["label"]]

components.html(
    _build_console_html(prev_counts, new_item_labels, monitor_enabled),
    height=390,
    scrolling=False,
)

_DEMO_BURST_ENDPOINTS = [
    "/network-ids/sample-requests", "/phishing/status", "/phishing/sample-requests",
    "/malware/status", "/alerts", "/alerts/stats",
    "/vuln-scanner/targets", "/vuln-scanner/security-headers",
]

ctrl1, ctrl2, ctrl3, ctrl4 = st.columns([1.3, 1, 1, 2.2])
with ctrl1:
    burst_clicked = st.button(
        "💥 Send a burst of traffic", use_container_width=True, disabled=not is_admin(),
        help="Fires a quick round of real requests at this backend's own endpoints, so there's something "
             "real to watch sort itself. Admin only." if is_admin() else "Admin only.",
    )
with ctrl2:
    refresh_clicked = st.button("🔄 Refresh", use_container_width=True)
with ctrl3:
    clear_clicked = st.button(
        "🧹 Reset", use_container_width=True, disabled=not is_admin(),
        help="Admin only." if not is_admin() else "Wipes the live feed and the running counts above.",
    )
with ctrl4:
    if is_admin():
        pause_label = "⏸️ Pause monitor" if monitor_enabled else "▶️ Resume monitor"
        if st.button(pause_label):
            api_post("/network-ids/live-feed/toggle", json_body={"enabled": not monitor_enabled})
            st.rerun()

if clear_clicked and is_admin():
    api_post("/network-ids/live-feed/clear")
    st.session_state.nids_bin_counts = {k: 0 for k in _CATS}
    st.session_state.nids_last_seen_id = 0
    st.session_state.nids_seeded = True
    st.toast("Feed and counts reset.", icon="🧹")
    st.rerun()

if burst_clicked and is_admin():
    with st.spinner("Firing traffic..."):
        for ep in _DEMO_BURST_ENDPOINTS:
            try:
                api_get(ep)
            except Exception:
                pass
    st.rerun()

if refresh_clicked:
    st.rerun()

flagged = [it for it in items if it["label"] and it["label"] != "normal"]
st.caption(
    f"🔍 {len(flagged)} flagged in the last 100 requests — expand one to see exactly which signals drove the call."
    if flagged else "🔍 Nothing flagged in the last 100 requests."
)
for item in flagged:
    with st.expander(
        f"{_LABEL_WORD.get(item['label'], item['label'])} — {item['method']} {item['path']} "
        f"({item['status_code']}) at {datetime.fromtimestamp(item['ts']).strftime('%H:%M:%S')} "
        f"— confidence {item['confidence']:.0%}"
    ):
        _render_shap_chart(item["explanation"])
        st.caption("Feature row computed for this request (pre-encoding):")
        st.json(item["feature_row"], expanded=False)

with st.expander("🔬 For the technically curious — what \"live\" really means here", expanded=False):
    st.markdown("""
- **This is HTTP-layer monitoring, not packet-layer.** A Python web app — and especially a Streamlit
  Community Cloud container — has no access to a raw network interface, so it can never capture TCP/IP
  packets the way NSL-KDD's original 1999 dataset was built (from `tcpdump` on a real network). What it
  *can* see honestly is every HTTP request that actually reaches this backend — so that's exactly what
  this watches. Nothing here is fabricated traffic.
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
  decision boundary the way a textbook NSL-KDD attack would. R2L/U2R in particular need signals (root-shell,
  compromised-host indicators) an HTTP request can never honestly provide, so they're left at zero rather
  than guessed — expect those two bins to stay quiet under live HTTP traffic. That's an honest limitation of
  reusing a packet-trained model on HTTP-layer signals, not a bug in this page.
- This only ever watches traffic to **this app's own backend** — never anything external.
""")
