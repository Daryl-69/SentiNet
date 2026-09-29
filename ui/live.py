"""SentiNet live monitor: forecasts attacks minute by minute on a simulated network, a replayed
capture, or live packets from this computer's network card."""
from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sentinet import viz  # noqa: E402
from sentinet.engine import Forecaster  # noqa: E402
from sentinet.features.windows import make_internal_fn  # noqa: E402
from sentinet.live import (console, CaptureSource, LiveEngine, LiveRunner, ReplaySource, SimSource, demo_schedule,  # noqa: E402
                           list_interfaces)
from sentinet.stages import ATTACK_TACTIC, STAGES  # noqa: E402
from ui.livechart import live_chart  # noqa: E402

ATTACKS = {"web_exploit": "Web server exploit → C2 → lateral movement → exfiltration",
           "bruteforce": "SSH brute force on the gateway → full kill chain",
           "phishing": "Phishing workstation (no network warning signs)",
           "slow_apt": "Low-and-slow APT (hours-long, stealthy)",
           "failed_attack": "Scan + probing that never gets in",
           "ddos": "SYN flood (impact, not an intrusion)"}
REPLAYS = {"Demo CSV: 12 h enterprise with an intrusion": (ROOT / "samples" / "demo_enterprise_12h.csv.gz", None),
           "Demo PCAP: 3 h web intrusion": (ROOT / "samples" / "demo_web_intrusion.pcap.gz",
                                           ROOT / "samples" / "demo_web_intrusion_labels.csv")}
INSIDE = make_internal_fn()
PLOT_CFG = {"displayModeBar": False}


@st.cache_resource(show_spinner="Loading the world model ...")
def forecaster():
    return Forecaster.load(ROOT / "weights")


def controller():
    return st.session_state.get("live")


def build(kind: str, **kw):
    old = controller()
    if old:
        old["runner"].stop()
    fc = forecaster()
    if kind == "sim":
        src = SimSource(seed=kw.get("seed", 7), n_workstations=kw.get("n_ws", 20))
    elif kind == "replay":
        src = ReplaySource(kw["path"], labels=kw.get("labels"))
    else:
        src = CaptureSource(iface=kw.get("iface") or None)
    eng = LiveEngine(fc, src, samples=32)
    runner = LiveRunner(eng, speed=kw.get("speed", 1.0))
    if kind == "sim" and kw.get("demo"):
        runner.schedule = demo_schedule(eng.t)
    st.session_state["live"] = {"engine": eng, "runner": runner, "kind": kind}
    console("info", {"sim": "live monitor started on the simulated network" + (" (auto demo script)" if kw.get("demo") else ""),
                     "replay": f"live monitor started: replaying {Path(str(kw.get('path'))).name}",
                     "capture": f"live monitor started: capturing on {kw.get('iface') or 'default interface'}"}[kind],
            eng.t)
    runner.start()


# ------------------------------------------------------------------ sidebar
with st.sidebar:
    st.title("🛡️ SentiNet")
    st.caption("Live monitor. The world model forecasts attacks every minute from the network's recent behaviour.")
    mode = st.radio("Traffic source", ["Simulated network (demo)", "Replay a capture", "Live capture (this computer)"])
    speed = st.select_slider("Speed (simulated minutes per second)", [0.5, 1.0, 2.0, 3.0], value=1.0,
                             disabled=mode.startswith("Live"),
                             help="A live capture always runs in real time: one forecast per minute.")
    kw = {"speed": speed}
    if mode.startswith("Simulated"):
        kw["demo"] = st.checkbox("Auto demo script", value=True,
                                 help="10 simulated minutes of normal traffic, then a web intrusion: recon -> exploit -> C2 -> lateral -> exfil.")
        kw["n_ws"] = st.slider("Workstations", 10, 40, 20)
        kw["seed"] = int(st.number_input("Seed", 0, 9999, 7))
        kind = "sim"
    elif mode.startswith("Replay"):
        choice = st.selectbox("Capture", list(REPLAYS) + ["Upload a file"])
        if choice == "Upload a file":
            up = st.file_uploader("PCAP / PCAPNG / flow CSV", type=["pcap", "pcapng", "cap", "csv", "gz", "binetflow"])
            if up is not None:
                tmp = Path(tempfile.gettempdir()) / f"sentinet_live_{up.name}"
                tmp.write_bytes(up.getvalue())
                kw["path"] = str(tmp)
        else:
            kw["path"], kw["labels"] = REPLAYS[choice]
        kind = "replay"
    else:
        ifaces = list_interfaces()
        kw["iface"] = st.selectbox("Network interface", ["(default)"] + ifaces) if ifaces else None
        if kw.get("iface") == "(default)":
            kw["iface"] = None
        st.caption("Needs capture rights: run as Administrator with Npcap installed (Windows) or with sudo (Linux/macOS). "
                   "The first forecast appears after 1 minute; the model needs ~10 minutes of history to warm up.")
        kind = "capture"

    ctl = controller()
    if st.button("Start", icon=":material/play_arrow:", type="primary", width="stretch"):
        if ctl and ctl["kind"] == kind and not ctl["runner"].error:
            ctl["runner"].speed = speed
            ctl["runner"].start()
        else:
            try:
                if kind == "replay" and not kw.get("path"):
                    st.warning("Choose or upload a capture first.")
                else:
                    build(kind, **kw)
            except PermissionError:
                st.error("No permission to capture packets. Run as Administrator (Npcap) / with sudo.")
            except Exception as exc:  # noqa: BLE001
                st.error(f"Could not start: {exc}")
    c2, c3 = st.columns(2)
    if c2.button("Pause", icon=":material/pause:", width="stretch") and ctl:
        ctl["runner"].pause()
    if c3.button("Reset", icon=":material/restart_alt:", width="stretch") and ctl:
        ctl["runner"].stop()
        st.session_state.pop("live", None)
    if ctl:
        ctl["runner"].speed = speed

    ctl = controller()
    if ctl and ctl["kind"] == "sim":
        st.divider()
        st.markdown("**⚔ Launch an attack**")
        tpl = st.selectbox("Attack", list(ATTACKS), format_func=lambda k: ATTACKS[k], label_visibility="collapsed")
        if st.button("Launch now", width="stretch"):
            ctl["engine"].src.launch(tpl, ctl["engine"].t)
            st.toast(f"Attack launched: {ATTACKS[tpl]}")


# ------------------------------------------------------------------ main (auto-refreshing)
st.markdown("### 📡 Live monitor: attack forecasting")
if not controller():
    st.info("Choose a traffic source on the left and press **Start**. For a demo video, use **Simulated network** "
            "with **Auto demo script**: normal traffic, then a web intrusion starts at ~08:10 (recon first, break-in ~40 min later). "
            "Watch the forecast rise *before* the break-in, then isolate the host and watch it fall.")
    st.markdown("""
**How it works:** packets → flows → a network state every minute (47 features + host graph) → world model (graph
network + temporal Transformer + latent dynamics) → **64 imagined futures, 10 minutes ahead** → risk, ATT&CK stage,
next target, explanation → signed receipt.""")
    st.stop()


def badge(text, color):
    return (f"<span style='background:{color};color:white;padding:3px 10px;border-radius:12px;font-size:0.85rem;"
            f"font-weight:600'>{text}</span>")


@st.fragment(run_every=1.0)
def dashboard():
    ctl = controller()
    if not ctl:
        return
    eng, runner = ctl["engine"], ctl["runner"]
    runner.last_seen = time.time()
    if runner.error:
        st.error(f"Stopped: {runner.error}")
    df = eng.table()
    L = eng.latest
    live_txt = {"sim": "SIMULATED NETWORK", "replay": "REPLAY", "capture": "LIVE CAPTURE"}[ctl["kind"]]
    state = badge(("● " if runner.running else "⏸ ") + live_txt, "#15803d" if runner.running else "#6b7280")
    clock = pd.to_datetime(eng.t, unit="s").strftime("%Y-%m-%d %H:%M")
    extra = ""
    if ctl["kind"] == "capture":
        extra = f" · packets captured: {getattr(eng.src, 'packets', 0):,}"
    st.markdown(f"{state} &nbsp; network clock **{clock}** · {len(df)} minutes analysed · "
                f"{eng.flow_total:,} flows · model step {eng.step_ms:.0f} ms{extra}", unsafe_allow_html=True)
    if df.empty or not L:
        st.info("Collecting the first window of traffic ...")
        return
    last = df.iloc[-1]
    p = float(last["p_infiltration"])
    warming = bool(last.get("warming_up", False))
    stage = last["stage_forecast"]
    k1, k2, k3, k4, k5, k6 = st.columns(6)
    k1.metric("Infiltration risk (next 10 min)", "warming up" if warming else f"{p:.0%}",
              None if warming or len(df) < 2 or abs(p - float(df.iloc[-2]['p_infiltration'])) < 0.01
              else f"{(p - float(df.iloc[-2]['p_infiltration'])) * 100:+.0f} pts",
              delta_color="inverse")
    k2.metric("Forecast stage", stage)
    k3.metric("ATT&CK", ATTACK_TACTIC[STAGES.index(stage)][0] if stage in STAGES else "-")
    hosts = L["hosts"]
    top_int = hosts[hosts["internal"]].head(1)
    k4.metric("Next likely target", top_int["host"].iloc[0] if len(top_int) else "-",
              f"{top_int['risk_next_K'].iloc[0]:.0%}" if len(top_int) else None, delta_color="off")
    k5.metric("Alerts", len(eng.alerts))
    k6.metric("Flows this minute", L["flows_in_window"])
    if p >= eng.threshold and not warming:
        st.error(f"🚨 ALARM: {p:.0%} chance of infiltration within 10 minutes. Forecast stage: {stage}. "
                 f"Likely target: {top_int['host'].iloc[0] if len(top_int) else 'unknown'}.")
    internal = hosts[hosts["internal"]]["host"].tolist()
    rec = next((al["host"] for al in eng.alerts if al.get("host") and al["host"] not in eng.contained), None)
    rec = rec or next((h for h in internal if h not in eng.contained), None)
    r1, r2, r3 = st.columns([1.3, 1.7, 3], vertical_alignment="center")
    if r1.button(f"Isolate {rec}" if rec else "Isolate host", icon=":material/block:", key="iso_rec",
                 type="primary" if rec and p >= eng.threshold and not warming else "secondary", width="stretch", disabled=not rec):
        eng.contain(rec)
        st.toast(f"Isolating {rec}" + ("" if ctl["kind"] != "capture" else " (recommendation only)"))
    with r2.popover("Isolate another host", icon=":material/tune:", width="stretch"):
        other = st.selectbox("Host (riskiest first)", [h for h in internal if h not in eng.contained] or ["-"],
                             key="iso_target")
        if st.button("Isolate", key="iso_other", disabled=not internal):
            eng.contain(other)
            st.toast(f"Isolating {other}")
    r3.caption(("Isolated: **" + ", ".join(sorted(eng.contained)) + "**. " if eng.contained else
                "🛡 Recommended response: the alert's target host. ")
               + ("Passive sensor: isolation is logged as a recommendation." if ctl["kind"] == "capture" else
                  "Isolation cuts the host off the network; an attack that needs it cannot continue."))

    a, b = st.columns([2, 1])
    with a:
        st.markdown("**Infiltration forecast timeline**")
        live_chart(viz.live_timeline(df.tail(180), eng.threshold, getattr(eng.src, "events", [])), "tl")
    with b:
        live_chart(viz.fan_chart(L["fan"], eng.W, height=250), "fan")
        live_chart(viz.stage_bars(L["stage_future"], eng.W, height=190), "stg")

    a, b = st.columns([1, 1])
    with a:
        live_chart(viz.host_graph(L["node_ips"], L["node_risk"], L["adj"], INSIDE), "hg")
    with b:
        st.markdown("**🔔 Alerts (with explanation and response)**")
        box = st.container(height=360)
        if not eng.alerts:
            box.caption("No alerts yet.")
        for al in eng.alerts[:8]:
            tech = " · ".join(f"`{t['technique']}` {t['name']}" for t in al["techniques"]) or "no technique-level evidence yet"
            nxt = al["expected"][0] if al["expected"] else None
            box.markdown(
                f"**{pd.Timestamp(al['time']):%H:%M} · {al['p']:.0%} · forecast {al['stage']}**"
                + (f" · target **{al['host']}**" if al["host"] else "")
                + f"  \nEvidence: {tech}"
                + (f"  \nNext: `{nxt['technique']}` {nxt['name']}. Mitigation: {nxt['mitigation']}" if nxt else "")
                + f"  \n<span style='color:#6b7280;font-size:0.85rem'>{al['narrative'][:420]}</span>",
                unsafe_allow_html=True)
            box.divider()

    a, b = st.columns([1, 1])
    with a:
        live_chart(viz.feature_heatmap(L["z"], L["times"]), "hm")
    with b:
        st.markdown("**Flagged flows this minute** (anomaly × host risk)")
        ff = L["flagged"]
        cols = [c for c in ["src_ip", "dst_ip", "dst_port", "proto", "bytes_fwd", "score", "why", "true_stage"] if c in ff]
        st.dataframe((ff[cols] if len(ff) else ff).round({"bytes_fwd": 0, "score": 2}), hide_index=True, width="stretch", height=330)

    st.markdown("**How it is working right now**")
    p1, p2, p3, p4, p5, p6 = st.columns(6)
    p1.metric("① Traffic", f"{L['flows_in_window']} flows", "last minute", delta_color="off")
    p2.metric("② Network state", "47 features", f"+ {len(L['node_ips'])}-host graph", delta_color="off")
    p3.metric("③ Context", f"{min(30, L['n_windows_ctx'])} min", "temporal Transformer", delta_color="off")
    p4.metric("④ Imagined futures", "64 × 10 min", "latent dynamics", delta_color="off")
    p5.metric("⑤ Forecast", "warming up" if warming else f"{p:.0%}", stage, delta_color="off")
    p6.metric("⑥ Signed receipts", f"{len(df)}", f"root {L['merkle_root'][:10]}…", delta_color="off")


dashboard()
