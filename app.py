"""SentiNet web interface. Start with:  python -m sentinet app   (or: streamlit run app.py)

Runs fully offline: no cloud calls, no external APIs.
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from sentinet import viz  # noqa: E402
from sentinet.engine import Forecaster, Result, whatif  # noqa: E402
from sentinet.io.loaders import load  # noqa: E402
from sentinet.ledger import make_receipts, verify_receipts  # noqa: E402
from sentinet.stages import ATTACK_TACTIC, STAGES  # noqa: E402

SAMPLES = {  # name -> (file, optional ground-truth label rules)
    "Demo: 12 h enterprise flows with an intrusion (CSV)": (ROOT / "samples" / "demo_enterprise_12h.csv.gz", None),
    "Demo: 3 h packet capture with a web intrusion (PCAP)": (ROOT / "samples" / "demo_web_intrusion.pcap.gz",
                                                            ROOT / "samples" / "demo_web_intrusion_labels.csv"),
}

st.set_page_config(page_title="SentiNet · Attack Forecasting", page_icon="🛡️", layout="wide")
st.markdown("""<style>
.block-container{padding-top:3.2rem}
div[data-testid="stMetricValue"]{font-size:1.6rem}
</style>""", unsafe_allow_html=True)


def show(fn, obj, **kw):
    """st.dataframe / st.plotly_chart at full width on old and new Streamlit versions."""
    try:
        return fn(obj, width="stretch", **kw)
    except Exception:  # Streamlit < 1.46 has no width="stretch"
        return fn(obj, use_container_width=True, **kw)


@st.cache_resource(show_spinner="Loading the world model ...")
def get_forecaster():
    return Forecaster.load(ROOT / "weights")


def _sig(*parts) -> str:
    h = hashlib.sha1()
    for p in parts:
        h.update(str(p).encode())
    return h.hexdigest()


def run_pipeline(path: str, fmt: str, labels: str | None, samples: int, assets: str | None) -> Result:
    fc = get_forecaster()
    flows = load(path, fmt, labels=labels)
    if len(flows) == 0:
        raise ValueError("no IP flows found in this file")
    return fc.run(flows, samples=samples, assets=assets)


# ------------------------------------------------------------------- sidebar
with st.sidebar:
    st.title("🛡️ SentiNet")
    st.caption("A world model that forecasts network attacks from traffic, "
               "before the attacker completes the kill chain.")
    src = st.radio("Input", list(SAMPLES) + ["Upload a PCAP / CSV"], index=0)
    fmt, labels_path, path = "auto", None, None
    if src.startswith("Upload"):
        up = st.file_uploader("PCAP, PCAPNG or flow CSV (CICFlowMeter, CTU-13, UNSW-NB15, SentiNet)",
                              type=["pcap", "pcapng", "cap", "csv", "gz", "binetflow"])
        fmt = st.selectbox("Format", ["auto", "pcap", "sentinet", "cicflowmeter", "ctu13", "unsw"])
        lab = st.file_uploader("Optional: label rules CSV (start,end,ip,stage)", type=["csv"])
        if up is not None:
            suffix = "".join(Path(up.name).suffixes) or ".bin"
            tmp = Path(tempfile.gettempdir()) / f"sentinet_{_sig(up.name, up.size)}{suffix}"
            tmp.write_bytes(up.getvalue())
            path = str(tmp)
        if lab is not None:
            lp = Path(tempfile.gettempdir()) / f"sentinet_labels_{_sig(lab.name, lab.size)}.csv"
            lp.write_bytes(lab.getvalue())
            labels_path = str(lp)
    else:
        path = str(SAMPLES[src][0])
        labels_path = str(SAMPLES[src][1]) if SAMPLES[src][1] else None
    assets_path = None
    use_demo_assets = st.checkbox("Use the example asset list (CVE / CVSS per host)", value=not src.startswith("Upload"),
                                  help="Known vulnerabilities raise a host's risk. samples/demo_assets.csv is an example "
                                       "inventory for the demo network.")
    if use_demo_assets:
        assets_path = str(ROOT / "samples" / "demo_assets.csv")
    up_assets = st.file_uploader("Optional: your asset list CSV (ip,cvss[,cves])", type=["csv"], key="assets")
    if up_assets is not None:
        ap = Path(tempfile.gettempdir()) / f"sentinet_assets_{_sig(up_assets.name, up_assets.size)}.csv"
        ap.write_bytes(up_assets.getvalue())
        assets_path = str(ap)
    samples = st.select_slider("Simulated futures per window", [16, 32, 64, 128], value=64,
                               help="Monte-Carlo rollouts of the latent dynamics. More = smoother bands, slower.")
    try:
        fc = get_forecaster()
    except FileNotFoundError as e:
        st.error(str(e))
        st.stop()
    thr = st.slider("Alarm threshold", 0.05, 0.95, float(round(fc.threshold, 2)), 0.01,
                    help="Chosen on validation data to maximise F1. Lower = earlier but noisier alarms.")
    st.divider()
    st.caption(f"Window {fc.cfg['window']:.0f} s · context {fc.L} windows · horizon K = {fc.K} windows "
               f"({fc.K * fc.cfg['window'] / 60:.0f} min) · fully offline")

if not path or not Path(path).exists():
    st.info("Choose a sample or upload a capture to start." if not path else f"Sample not found: {path}")
    st.stop()

key = _sig(path, fmt, labels_path, samples, assets_path, Path(path).stat().st_mtime)
if st.session_state.get("key") != key:
    with st.spinner("Extracting flows, building network states and simulating futures ..."):
        try:
            st.session_state["res"] = run_pipeline(path, fmt, labels_path, samples, assets_path)
        except Exception as exc:  # show the error in the UI rather than a stack trace
            st.error(f"Could not process this file: {exc}")
            st.stop()
    st.session_state["key"] = key
    st.session_state.pop("whatif", None)

res: Result = st.session_state["res"]
tb = res.table.copy()
tb["alarm"] = tb["p_infiltration"] >= thr
horizon_min = fc.K * fc.cfg["window"] / 60

# ------------------------------------------------------------------- headline
al = tb[tb["alarm"]]
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Windows / flows", f"{len(tb):,} / {int(tb['flows'].sum()):,}")
c2.metric("Peak infiltration probability", f"{tb['p_infiltration'].max():.0%}")
c3.metric("Alarm windows", f"{len(al):,}")
c4.metric("First alarm", al.iloc[0]["time"].strftime("%H:%M") if len(al) else "none")
if res.labelled and "true_stage" in tb:
    infil = tb["true_stage"].isin(["Initial Access", "Lateral Movement", "Command & Control", "Exfiltration"]).to_numpy()
    onset = int(np.argmax(infil)) if infil.any() else None
    if onset is not None:
        # warning = the alarm run (gaps of <= 2 windows allowed) that reaches the first compromise
        alarm = tb["alarm"].to_numpy()
        first, gap = onset, 0
        for u in range(onset - 1, max(-1, onset - 61), -1):
            if alarm[u]:
                first, gap = u, 0
            else:
                gap += 1
                if gap > 2:
                    break
        lead = (onset - first) * fc.cfg["window"] / 60
        st.session_state["warn_start"] = first if lead > 0 else None
        c5.metric("Warning before first compromise", f"{lead:.0f} min" if lead > 0 else "none",
                  help="Length of the alarm run that leads into the first infiltration window (ground truth).")
    else:
        st.session_state["warn_start"] = None
        c5.metric("Ground truth", "no compromise")
else:
    st.session_state["warn_start"] = None
    c5.metric("Ground truth", "not labelled")

wi = st.session_state.get("whatif")
default_t = int(al.index[0]) if len(al) else int(tb["p_infiltration"].idxmax())
if st.session_state.get("warn_start") is not None:   # labelled input: open on the warning before the compromise
    default_t = int(st.session_state["warn_start"])
if st.session_state.get("sel_key") != key:           # new input: start at the first alarm
    st.session_state["sel_slider"], st.session_state["sel_key"] = default_t, key
    st.session_state["jump"] = -1


def _jump():
    if st.session_state["jump"] >= 0:
        st.session_state["sel_slider"] = int(st.session_state["jump"])


jump = st.columns([3, 1])
with jump[1]:
    alarm_idx = [-1] + [int(i) for i in al.index[:300]]
    st.selectbox("Jump to an alarm", alarm_idx, key="jump", on_change=_jump,
                 format_func=lambda i: "-" if i < 0 else
                 f"{tb.loc[i, 'time']:%H:%M} · {tb.loc[i, 'p_infiltration']:.0%} · {tb.loc[i, 'stage_forecast']}")
with jump[0]:
    t = st.slider("Selected window", 0, len(tb) - 1, key="sel_slider",
                  help="Pick a window to see its forecast, explanation and flagged flows.")

show(st.plotly_chart, viz.timeline(tb, thr, whatif=wi.table if wi is not None else None, selected=t,
                                   horizon_min=horizon_min))

row = tb.loc[t]
stage_idx = STAGES.index(row["stage_forecast"])
st.markdown(f"#### {row['time']:%Y-%m-%d %H:%M} — P(infiltration within {horizon_min:.0f} min) = "
            f"**{row['p_infiltration']:.0%}** (band {row['p_low']:.0%}–{row['p_high']:.0%}) · "
            f"forecast stage: **{row['stage_forecast']}** · ATT&CK: {ATTACK_TACTIC[stage_idx][0]} "
            f"{ATTACK_TACTIC[stage_idx][1]}")

tabs = st.tabs(["Forecast", "Why? (explainability)", "Flagged flows & hosts", "What-if", "Receipts & export", "About"])

with tabs[0]:
    show(st.plotly_chart, viz.horizon(res.r["p_by_k"][t], res.r["stage_future"][t], fc.cfg["window"]))
    a, b = st.columns(2)
    with a:
        st.markdown("**Current state (detection)**")
        show(st.dataframe, pd.DataFrame({"stage": STAGES, "probability": res.r["stage_now"][t]})
                     .sort_values("probability", ascending=False), hide_index=True)
    with b:
        st.markdown("**Forecast network state at +1 window vs now** (decoded from the world model)")
        from sentinet.features.windows import FEATURE_HELP, FEATURE_NAMES
        now, nxt = res.wd.X[t], res.r["x_future"][t, 0]
        d = pd.DataFrame({"feature": FEATURE_NAMES, "meaning": [FEATURE_HELP[f] for f in FEATURE_NAMES],
                          "now": now, "forecast +1": nxt})
        d["change"] = (d["forecast +1"] - d["now"]) / (np.abs(fc.norm.x_std) + 1e-9)
        show(st.dataframe, d.reindex(d["change"].abs().sort_values(ascending=False).index).head(10), hide_index=True)

with tabs[1]:
    with st.spinner("Computing Shapley values ..."):
        ex = res.explain(t)
    st.info(ex["narrative"])
    a, b = st.columns(2)
    show(a.plotly_chart, viz.shap_bars(ex["groups"], "label", "Feature groups (exact Shapley, log-odds)", 8))
    show(b.plotly_chart, viz.shap_bars(ex["features"], "feature", "Individual features inside the top groups", 10))
    if ex["features"]:
        show(st.dataframe, pd.DataFrame(ex["features"])[["feature", "meaning", "value", "typical", "shap"]].head(12),
             hide_index=True)
    a, b = st.columns(2)
    with a:
        st.markdown("**MITRE ATT&CK techniques the evidence points to** (with CAPEC patterns)")
        if ex["techniques_observed"]:
            show(st.dataframe, pd.DataFrame(ex["techniques_observed"])[["technique", "name", "stage", "capec", "evidence"]],
                 hide_index=True)
        else:
            st.caption("No technique-level evidence in this window.")
    with b:
        st.markdown("**What to watch for next, and how to stop it** (from the forecast stage)")
        if ex["techniques_expected"]:
            d = pd.DataFrame(ex["techniques_expected"])
            d["p_stage"] = d["p_stage"].map(lambda v: f"{v:.0%}")
            show(st.dataframe, d[["stage", "p_stage", "technique", "name", "mitigation"]], hide_index=True)
        else:
            st.caption("The forecast stays benign.")
    a, b = st.columns([2, 1])
    show(a.plotly_chart, viz.attention(ex["attention"], fc.cfg["window"]))
    with b:
        st.markdown("**TCP flags in this window**")
        st.dataframe(pd.DataFrame(list(ex["flags"].items()), columns=["flag", "flows"]), hide_index=True)
        st.markdown("**Busiest destination ports around risky hosts**")
        st.dataframe(pd.DataFrame(ex["ports"], columns=["port", "flows"]), hide_index=True)

with tabs[2]:
    a, b = st.columns([3, 2])
    with a:
        st.markdown("**Flagged flows in this window** (anomaly score x host risk)")
        show(st.dataframe, res.flagged_flows(t, 25), hide_index=True)
    with b:
        st.markdown(f"**Hosts most likely to be involved in the next {horizon_min:.0f} min**")
        show(st.dataframe, res.hosts(t, 15), hide_index=True)

with tabs[3]:
    st.markdown("Replay the capture with a defensive action applied from a chosen time, and let the world model "
                "re-simulate. Counterfactual: it removes the recorded traffic the action would have stopped (for example "
                "everything to and from an isolated host) and forecasts again. Try isolating the riskiest internal host.")
    hosts = res.hosts(t, 10)
    ext = hosts[~hosts["internal"]]["host"].tolist()
    intern = hosts[hosts["internal"]]["host"].tolist()
    lateral = [p for p, _ in res.port_summary(t, 10) if p in (22, 135, 139, 445, 3389, 5985, 5986)]
    kind = st.selectbox("Action", ["isolate_host", "block_ip", "block_port"],
                        format_func=lambda k: {"block_port": "Block a destination port", "isolate_host": "Isolate a host",
                                               "block_ip": "Block an external IP at the perimeter"}[k])
    if kind == "block_port":
        val = st.number_input("Port", 0, 65535, int(lateral[0]) if lateral else 445)
        action = {"type": kind, "port": int(val)}
    else:
        choices = (ext if kind == "block_ip" else intern) or hosts["host"].tolist() or ["10.0.0.1"]
        val = st.selectbox("Host / IP (riskiest first)", choices)
        action = {"type": kind, "ip": val}
    start = st.slider("Apply from window", 0, len(tb) - 1, t)
    if st.button("Simulate", type="primary"):
        with st.spinner("Re-simulating ..."):
            st.session_state["whatif"] = whatif(fc, res.flows, action, float(res.wd.times[start]), samples, res.assets)
            st.session_state["whatif_action"] = (action, start)
        st.rerun()
    if wi is not None:
        act, s0 = st.session_state.get("whatif_action", ({}, 0))
        w_tb = wi.table
        after = slice(s0, len(tb))
        before_alarms = int((tb["p_infiltration"].iloc[after] >= thr).sum())
        after_alarms = int((w_tb["p_infiltration"].iloc[after] >= thr).sum())
        m1, m2, m3 = st.columns(3)
        m1.metric("Action", " ".join(str(v) for v in act.values()))
        m2.metric("Mean risk after the action", f"{w_tb['p_infiltration'].iloc[after].mean():.0%}",
                  f"{(w_tb['p_infiltration'].iloc[after].mean() - tb['p_infiltration'].iloc[after].mean()) * 100:+.0f} pts",
                  delta_color="inverse")
        m3.metric("Alarm windows after the action", after_alarms, after_alarms - before_alarms, delta_color="inverse")
        if st.button("Clear what-if"):
            st.session_state.pop("whatif", None)
            st.rerun()

with tabs[4]:
    st.download_button("Download forecast table (CSV)", tb.to_csv(index=False).encode(), "forecast.csv", "text/csv")
    recs = [{"window": int(r.window), "time": str(r.time), "p_infiltration": round(float(r.p_infiltration), 6),
             "stage_forecast": r.stage_forecast, "alarm": bool(r.alarm)} for r in tb.itertuples()]
    doc = make_receipts(recs, source=Path(path).name)
    ok, msg = verify_receipts(doc)
    st.markdown(f"**Merkle root:** `{doc['merkle_root']}`  \n**Signature ({doc['algorithm']}):** `{doc['signature'][:48]}...`")
    (st.success if ok else st.error)(msg)
    st.download_button("Download signed receipts (JSON)", json.dumps(doc, indent=1).encode(), "receipts.json",
                       "application/json")
    st.caption("Anyone can re-check the receipts later with:  python -m sentinet verify receipts.json")

with tabs[5]:
    st.markdown(f"""
**What this is.** A world model learns how the network's state changes from one {fc.cfg['window']:.0f}-second window to the next,
P(S<sub>t+1</sub> | S<sub>≤t</sub>). It then rolls that model forward {fc.K} windows, {samples} times per window, and reports the share of
simulated futures that reach an infiltration stage (Initial Access, Lateral Movement, Command & Control, Exfiltration).

**Network state S<sub>t</sub>:** 47 flow- and packet-level features (TCP flags, IAT, ports, TTL, TCP window, fragments, payload sizes,
retransmissions, beaconing, new connections, egress volume) plus a graph of the most active hosts.

**Model:** edge-weighted GraphSAGE over the host graph → causal Temporal Transformer over the last {fc.L} windows → stochastic latent
state → GRU latent dynamics → decoders for the next network state, the ATT&CK stage and the infiltration hazard; a per-host risk head.

**Explanations:** exact Shapley values over feature groups (and features within the top groups), temporal attention over past
windows, graph attention over hosts, and the flagged flows behind each forecast.

**Honest limits:** the bundled weights were trained on the included network simulator, because the public datasets could not be
downloaded in the build environment. Retrain on CIC-IDS2017/2018, CTU-13 or UNSW-NB15 with `python -m sentinet train` (see README).
""", unsafe_allow_html=True)
