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
