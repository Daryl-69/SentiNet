"""Plotly figures shared by the Streamlit app and the HTML report."""
from __future__ import annotations

import numpy as np
import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from .stages import STAGE_COLORS, STAGES

INK = "#1f2a37"
MUTED = "#6b7280"
RISK = "#c2410c"
BASE = "#2563eb"


def _stage_color(name: str) -> str:
    return STAGE_COLORS[STAGES.index(name)] if name in STAGES else "#e5e7eb"


def timeline(table: pd.DataFrame, threshold: float, whatif: pd.DataFrame | None = None, selected: int | None = None,
             horizon_min: float | None = None) -> go.Figure:
    rows = 3 if "true_stage" in table else 2
    heights = [0.72, 0.14, 0.14] if rows == 3 else [0.82, 0.18]
    titles = ["Infiltration probability in the next " + (f"{horizon_min:.0f} min" if horizon_min else "K windows")]
    fig = make_subplots(rows=rows, cols=1, shared_xaxes=True, row_heights=heights, vertical_spacing=0.03,
                        subplot_titles=titles + [""] * (rows - 1))
    t = table["time"]
    w_ms = (t.iloc[1] - t.iloc[0]).total_seconds() * 1000 if len(t) > 1 else 60_000
    fig.add_trace(go.Scatter(x=t, y=table["p_high"], line=dict(width=0), hoverinfo="skip", showlegend=False), 1, 1)
    fig.add_trace(go.Scatter(x=t, y=table["p_low"], fill="tonexty", fillcolor="rgba(194,65,12,0.15)", line=dict(width=0),
                             name="10-90% of simulated futures", hoverinfo="skip"), 1, 1)
    fig.add_trace(go.Scatter(x=t, y=table["p_infiltration"], line=dict(color=RISK, width=2), name="World model"), 1, 1)
    if "p_logreg_baseline" in table:
        fig.add_trace(go.Scatter(x=t, y=table["p_logreg_baseline"], line=dict(color=MUTED, width=1, dash="dot"),
                                 name="Logistic-regression baseline", visible="legendonly"), 1, 1)
    if whatif is not None:
        fig.add_trace(go.Scatter(x=whatif["time"], y=whatif["p_infiltration"], line=dict(color=BASE, width=2, dash="dash"),
                                 name="What-if (action applied)"), 1, 1)
    fig.add_hline(y=threshold, line=dict(color=INK, width=1, dash="dash"), row=1, col=1,
                  annotation_text=f"alarm threshold {threshold:.2f}", annotation_position="top left")
    al = table[table["alarm"]]
    fig.add_trace(go.Scatter(x=al["time"], y=al["p_infiltration"], mode="markers", marker=dict(color=RISK, size=5),
                             name="Alarm"), 1, 1)
    for r, col in ((2, "stage_forecast"), (3, "true_stage")):
        if r > rows:
            continue
        for st in STAGES:
            m = table[col] == st
            if not m.any():
                continue
            fig.add_trace(go.Bar(x=t[m], y=np.ones(m.sum()), marker_color=_stage_color(st), name=st, width=w_ms,
                                 legendgroup=st, showlegend=(r == 2 or col == "true_stage" and st not in set(table["stage_forecast"])),
                                 hovertemplate=f"{st}<extra></extra>"), r, 1)
        fig.update_yaxes(title_text="forecast" if r == 2 else "truth", title_font=dict(size=11), showticklabels=False,
                         showgrid=False, range=[0, 1], row=r, col=1)
    if selected is not None and 0 <= selected < len(table):
        fig.add_vline(x=table["time"].iloc[selected], line=dict(color=INK, width=1))
    fig.update_yaxes(range=[0, 1.02], tickformat=".0%", row=1, col=1)
    fig.update_layout(height=470, margin=dict(l=10, r=10, t=40, b=10), barmode="stack", bargap=0,
                      legend=dict(orientation="h", y=-0.12), plot_bgcolor="white", hovermode="x unified")
    fig.update_xaxes(showgrid=False)
    fig.update_yaxes(gridcolor="#eef0f3", row=1, col=1)
    return fig


def horizon(p_by_k: np.ndarray, stage_future: np.ndarray, window_s: float) -> go.Figure:
    K = len(p_by_k)
    x = [f"+{(k + 1) * window_s / 60:.0f} min" for k in range(K)]
    fig = make_subplots(rows=1, cols=2, subplot_titles=("P(infiltration by step k)", "Forecast stage distribution per step"))
    fig.add_trace(go.Scatter(x=x, y=p_by_k, mode="lines+markers", line=dict(color=RISK, width=2), name="P(infiltration)"), 1, 1)
    for i, st in enumerate(STAGES):
        fig.add_trace(go.Bar(x=x, y=stage_future[:, i], name=st, marker_color=STAGE_COLORS[i]), 1, 2)
    fig.update_layout(barmode="stack", height=300, margin=dict(l=10, r=10, t=40, b=10), plot_bgcolor="white",
                      legend=dict(orientation="h", y=-0.25))
    fig.update_yaxes(range=[0, 1], tickformat=".0%")
    return fig


def shap_bars(items: list[dict], label_key: str, title: str, top: int = 10) -> go.Figure:
    items = sorted(items, key=lambda d: -abs(d["shap"]))[:top][::-1]
    vals = [d["shap"] for d in items]
    fig = go.Figure(go.Bar(x=vals, y=[d[label_key] for d in items], orientation="h",
                           marker_color=[RISK if v > 0 else BASE for v in vals],
                           hovertemplate="%{y}: %{x:+.3f} log-odds<extra></extra>"))
    fig.update_layout(title=title, height=40 + 28 * len(items), margin=dict(l=10, r=10, t=40, b=10),
                      plot_bgcolor="white", xaxis_title="contribution (log-odds; red raises risk, blue lowers it)")
    fig.add_vline(x=0, line=dict(color=INK, width=1))
    return fig


def attention(att: list[float], window_s: float) -> go.Figure:
    L = len(att)
    x = [f"-{(L - 1 - i) * window_s / 60:.0f}m" if i < L - 1 else "now" for i in range(L)]
    fig = go.Figure(go.Bar(x=x, y=att, marker_color="#7c3aed"))
    fig.update_layout(title="Temporal attention: which past windows the model looked at", height=240,
                      margin=dict(l=10, r=10, t=40, b=10), plot_bgcolor="white", yaxis_title="weight")
    return fig


# ------------------------------------------------------------------ live dashboard figures
def live_timeline(df: pd.DataFrame, threshold: float, events: list | None = None, height: int = 330) -> go.Figure:
    labelled = "true_stage" in df and df["true_stage"].notna().any()
    rows = 3 if labelled else 2
    fig = make_subplots(rows=rows, cols=1, shared_xaxes=True, vertical_spacing=0.03,
                        row_heights=[0.74, 0.13, 0.13][:rows] if labelled else [0.84, 0.16])
    t = df["time"]
    if len(df):
        fig.add_trace(go.Scatter(x=t, y=df["p_high"], line=dict(width=0), hoverinfo="skip", showlegend=False), 1, 1)
        fig.add_trace(go.Scatter(x=t, y=df["p_low"], fill="tonexty", fillcolor="rgba(194,65,12,0.15)", line=dict(width=0),
                                 hoverinfo="skip", showlegend=False), 1, 1)
        fig.add_trace(go.Scatter(x=t, y=df["p_infiltration"], line=dict(color=RISK, width=2.5), name="P(infiltration ≤ 10 min)",
                                 hovertemplate="%{x|%H:%M}  %{y:.0%}<extra></extra>"), 1, 1)
        al = df[df["alarm"]]
        fig.add_trace(go.Scatter(x=al["time"], y=al["p_infiltration"], mode="markers", marker=dict(color=RISK, size=6),
                                 name="alarm", hoverinfo="skip"), 1, 1)
        w_ms = 60_000
        strips = [(2, "stage_forecast")] + ([(3, "true_stage")] if labelled else [])
        for r, col in strips:
            for st in STAGES:
                m = df[col] == st
                if m.any():
                    fig.add_trace(go.Bar(x=t[m], y=np.ones(int(m.sum())), marker_color=_stage_color(st), width=w_ms,
                                         name=st, legendgroup=st, showlegend=(r == 2),
                                         hovertemplate=f"{st}<extra></extra>"), r, 1)
            fig.update_yaxes(title_text="forecast" if r == 2 else "truth", title_font=dict(size=10),
                             showticklabels=False, showgrid=False, range=[0, 1], row=r, col=1)
    fig.add_hline(y=threshold, line=dict(color=INK, width=1, dash="dash"), row=1, col=1)
    for e in events or []:
        ts = pd.to_datetime(e["ts"], unit="s")
        if len(df) and ts >= df["time"].iloc[0]:
            color = "#b91c1c" if e["kind"] == "attack" else "#1d4ed8"
            fig.add_vline(x=ts, line=dict(color=color, width=1.2, dash="dot"))
            fig.add_annotation(x=ts, y=1.05, yref="y", text="⚔ attack" if e["kind"] == "attack" else "🛡 action",
                               showarrow=False, font=dict(size=10, color=color))
    fig.update_yaxes(range=[0, 1.1], tickformat=".0%", gridcolor="#eef0f3", row=1, col=1)
    fig.update_layout(height=height, margin=dict(l=10, r=10, t=10, b=10), barmode="stack", bargap=0, plot_bgcolor="white",
                      legend=dict(orientation="h", y=-0.18, font=dict(size=10)), uirevision="live")
    return fig


def fan_chart(fan: np.ndarray, window_s: float, height: int = 330) -> go.Figure:
    """64 imagined futures: P(infiltration by step k) along each sampled latent trajectory."""
    K = fan.shape[1]
    x = [f"+{(k + 1) * window_s / 60:.0f}m" for k in range(K)]
    fig = go.Figure()
    for i in range(fan.shape[0]):
        fig.add_trace(go.Scatter(x=x, y=fan[i], mode="lines", line=dict(color="rgba(194,65,12,0.18)", width=1),
                                 hoverinfo="skip", showlegend=False))
    fig.add_trace(go.Scatter(x=x, y=fan.mean(0), mode="lines+markers", line=dict(color=RISK, width=3),
                             name="mean of 64 futures", hovertemplate="%{x}: %{y:.0%}<extra></extra>"))
    fig.update_layout(height=height, margin=dict(l=10, r=10, t=30, b=10), plot_bgcolor="white", showlegend=False,
                      title=dict(text="64 imagined futures (world-model rollouts)", font=dict(size=13)), uirevision="fan")
    fig.update_yaxes(range=[0, 1.02], tickformat=".0%", gridcolor="#eef0f3")
    return fig


def stage_bars(stage_future: np.ndarray, window_s: float, height: int = 200) -> go.Figure:
    K = stage_future.shape[0]
    x = [f"+{(k + 1) * window_s / 60:.0f}m" for k in range(K)]
    fig = go.Figure()
    for i, st in enumerate(STAGES):
        fig.add_trace(go.Bar(x=x, y=stage_future[:, i], name=st, marker_color=STAGE_COLORS[i],
                             hovertemplate=f"{st} %{{y:.0%}}<extra></extra>"))
    fig.update_layout(barmode="stack", height=height, margin=dict(l=10, r=10, t=28, b=10), plot_bgcolor="white",
                      title=dict(text="Forecast ATT&CK stage per minute", font=dict(size=13)), showlegend=False,
                      uirevision="stages")
    fig.update_yaxes(range=[0, 1], tickformat=".0%")
    return fig


def host_graph(ips: list, risk: np.ndarray, adj: np.ndarray, is_internal, height: int = 380) -> go.Figure:
    """Who talks to whom in the latest minute; colour = forecast risk that the host is involved next."""
    import zlib
    n = len(ips)
    pos = {}
    inner = sorted([ip for ip in ips if is_internal(ip)])
    outer = [ip for ip in ips if not is_internal(ip)]
    for i, ip in enumerate(inner):
        a = 2 * np.pi * i / max(len(inner), 1)
        pos[ip] = (np.cos(a), np.sin(a))
    for ip in outer:
        a = 2 * np.pi * (zlib.crc32(ip.encode()) % 3600) / 3600
        pos[ip] = (1.9 * np.cos(a), 1.9 * np.sin(a))
    ex, ey = [], []
    for i in range(n):
        for j in range(n):
            if adj[i, j] > 0 and i != j:
                (x0, y0), (x1, y1) = pos[ips[i]], pos[ips[j]]
                ex += [x0, x1, None]
                ey += [y0, y1, None]
    fig = go.Figure(go.Scatter(x=ex, y=ey, mode="lines", line=dict(color="rgba(100,116,139,0.35)", width=0.8),
                               hoverinfo="skip"))
    xs = [pos[ip][0] for ip in ips]
    ys = [pos[ip][1] for ip in ips]
    deg = adj[:n, :n].sum(0) + adj[:n, :n].sum(1)
    fig.add_trace(go.Scatter(
        x=xs, y=ys, mode="markers+text", text=[ip if i in set(np.argsort(-np.asarray(risk))[:5]) else ""
                                                for i, ip in enumerate(ips)],
        textposition="top center", textfont=dict(size=9),
        marker=dict(size=8 + 3 * np.sqrt(deg), color=risk, colorscale=[[0, "#cbd5e1"], [0.3, "#fbbf24"], [1, "#b91c1c"]],
                    cmin=0, cmax=1, line=dict(color=["#1f2a37" if is_internal(ip) else "#9ca3af" for ip in ips], width=1),
                    colorbar=dict(title="risk", thickness=10, tickformat=".0%")),
        hovertemplate="%{customdata}<extra></extra>",
        customdata=[f"{ip} ({'internal' if is_internal(ip) else 'internet'}) · risk {r:.0%}" for ip, r in zip(ips, risk)]))
    fig.update_layout(height=height, margin=dict(l=0, r=0, t=30, b=0), plot_bgcolor="white", showlegend=False,
                      title=dict(text="Host graph: inner ring = your network, outer ring = internet", font=dict(size=13)),
                      xaxis=dict(visible=False), yaxis=dict(visible=False, scaleanchor="x"), uirevision="graph")
    return fig


def feature_heatmap(z: pd.DataFrame, times: list, height: int = 330) -> go.Figure:
    from .features.windows import FEATURE_HELP
    zz = np.clip(z.to_numpy().T, -4, 4)
    fig = go.Figure(go.Heatmap(z=zz, x=[pd.Timestamp(t).strftime("%H:%M") for t in times[-zz.shape[1]:]],
                               y=[FEATURE_HELP.get(c, c) for c in z.columns], colorscale="RdBu", reversescale=True,
                               zmin=-4, zmax=4, colorbar=dict(title="z", thickness=10),
                               hovertemplate="%{y}<br>%{x}: z=%{z:.1f}<extra></extra>"))
    fig.update_layout(height=height, margin=dict(l=10, r=10, t=30, b=10),
                      title=dict(text="What the model sees: network state, last 60 minutes (vs normal)", font=dict(size=13)),
                      uirevision="heat")
    fig.update_yaxes(tickfont=dict(size=9))
    return fig
