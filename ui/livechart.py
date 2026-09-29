"""Flicker-free live charts.

st.plotly_chart gives a chart a new identity whenever its data changes, so on a page that refreshes every second
every chart is torn down and redrawn (a visible blink). This small custom component stays mounted and hands each
new figure to Plotly.react, which updates the existing chart in place.

Plotly.js is served locally (Streamlit static serving), so the app stays fully offline. If this Streamlit version has
no components.v2, it falls back to st.plotly_chart.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import plotly.io as pio
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
FONT = '"Source Sans Pro", "Source Sans 3", sans-serif'

_JS = r"""
function loadPlotly() {
  if (window.Plotly) return Promise.resolve(window.Plotly);
  if (!window.__snPlotly) {
    window.__snPlotly = new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = window.location.origin + "/app/static/plotly.min.js";
      s.onload = () => resolve(window.Plotly);
      s.onerror = reject;
      document.head.appendChild(s);
    });
  }
  return window.__snPlotly;
}
export default function ({ parentElement, data }) {
  let div = parentElement.querySelector(".sn-chart");
  if (!div) {
    div = document.createElement("div");
    div.className = "sn-chart";
    div.style.width = "100%";
    parentElement.appendChild(div);
  }
  const fig = JSON.parse(data.fig);
  div.style.height = (fig.layout.height || 320) + "px";
  delete fig.layout.width;
  fig.layout.autosize = true;
  loadPlotly().then((P) => P.react(div, fig.data, fig.layout, { displayModeBar: false, responsive: true }));
}
"""


@st.cache_resource
def _component():
    import plotly
    src = Path(plotly.__file__).parent / "package_data" / "plotly.min.js"
    dst = ROOT / "static" / "plotly.min.js"
    if not dst.exists() or dst.stat().st_size != src.stat().st_size:
        dst.parent.mkdir(exist_ok=True)
        shutil.copyfile(src, dst)
    return st.components.v2.component("sentinet_live_chart", js=_JS, isolate_styles=False)


def live_chart(fig, key: str):
    """Draw `fig` and update it in place on later runs with the same key."""
    # Streamlit's own plotly theme uses colour placeholders only its chart element understands
    fig.update_layout(template=pio.templates["plotly_white"], font_family=FONT,
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
    try:
        comp = _component()
    except Exception:  # noqa: BLE001 - older Streamlit: plain chart (it re-draws on each refresh)
        st.plotly_chart(fig, width="stretch", key=key, config={"displayModeBar": False})
        return
    comp(data={"fig": fig.to_json()}, key=key)
