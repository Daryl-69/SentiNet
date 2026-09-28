"""Self-contained HTML report (works offline: plotly.js is embedded)."""
from __future__ import annotations

import html
from pathlib import Path

from . import viz

CSS = """
body{font-family:Segoe UI,Calibri,Arial,sans-serif;margin:24px auto;max-width:1200px;color:#1f2a37;padding:0 16px}
h1{font-size:26px;margin-bottom:4px} h2{font-size:19px;margin-top:32px;border-bottom:1px solid #e5e7eb;padding-bottom:4px}
.muted{color:#6b7280} .kpis{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.kpi{border:1px solid #e5e7eb;border-radius:8px;padding:10px 14px;min-width:170px}
.kpi b{display:block;font-size:22px} table{border-collapse:collapse;font-size:13px;width:100%}
td,th{border-bottom:1px solid #eef0f3;padding:4px 6px;text-align:left} .card{border:1px solid #e5e7eb;border-radius:8px;padding:12px 16px;margin:12px 0}
"""


def write_report(res, explanations: dict, path, source: str = "") -> None:
    fc, tb = res.fc, res.table
    horizon_min = fc.K * fc.cfg["window"] / 60
    parts = [f"<html><head><meta charset='utf-8'><title>SentiNet forecast report</title><style>{CSS}</style></head><body>",
             "<h1>SentiNet &mdash; attack forecast report</h1>",
             f"<div class='muted'>Input: {html.escape(source)} &middot; {len(tb)} windows of {fc.cfg['window']:.0f} s "
             f"&middot; horizon {horizon_min:.0f} min &middot; alarm threshold {fc.threshold:.2f}</div>"]
    al = tb[tb["alarm"]]
    first = al.iloc[0] if len(al) else None
    parts.append("<div class='kpis'>"
                 f"<div class='kpi'><span class='muted'>Peak infiltration probability</span><b>{tb['p_infiltration'].max():.0%}</b></div>"
                 f"<div class='kpi'><span class='muted'>Alarm windows</span><b>{len(al)}</b></div>"
                 f"<div class='kpi'><span class='muted'>First alarm</span><b>{first.time.strftime('%H:%M') if first is not None else '-'}</b></div>"
                 f"<div class='kpi'><span class='muted'>Flows analysed</span><b>{int(tb['flows'].sum()):,}</b></div></div>")
    fig = viz.timeline(tb, fc.threshold, horizon_min=horizon_min)
    parts.append(fig.to_html(full_html=False, include_plotlyjs=True))
    parts.append("<h2>Why the alarms fired: explained windows</h2>")
    for t, ex in explanations.items():
        row = tb.loc[int(t)]
        parts.append(f"<div class='card'><b>{row.time} &mdash; P(infiltration within {horizon_min:.0f} min) = "
                     f"{row.p_infiltration:.0%}, forecast stage: {html.escape(row.stage_forecast)}</b>"
                     f"<p>{html.escape(ex['narrative'])}</p>")
        parts.append(viz.shap_bars(ex["groups"], "label", "What drove this forecast (Shapley values by feature group)", 8)
                     .to_html(full_html=False, include_plotlyjs=False))
        feats = ex["features"][:8]
        if feats:
            parts.append("<table><tr><th>Feature</th><th>Meaning</th><th>Value</th><th>Typical</th><th>Contribution</th></tr>")
            for f in feats:
                parts.append(f"<tr><td>{f['feature']}</td><td>{html.escape(f['meaning'])}</td><td>{f['value']:.3g}</td>"
                             f"<td>{f['typical']:.3g}</td><td>{f['shap']:+.3f}</td></tr>")
            parts.append("</table>")
        if ex.get("techniques_observed"):
            parts.append("<p><b>ATT&amp;CK techniques the evidence points to</b></p><table><tr><th>Technique</th><th>Name</th>"
                         "<th>CAPEC</th><th>Evidence</th></tr>" + "".join(
                             f"<tr><td>{o['technique']}</td><td>{html.escape(o['name'])}</td><td>{html.escape(o['capec'])}</td>"
                             f"<td>{html.escape(o['evidence'])}</td></tr>" for o in ex["techniques_observed"]) + "</table>")
        if ex.get("techniques_expected"):
            parts.append("<p><b>Watch for next</b></p><table><tr><th>Stage</th><th>Technique</th><th>Mitigation</th></tr>" + "".join(
                f"<tr><td>{html.escape(e['stage'])} ({e['p_stage']:.0%})</td><td>{e['technique']} {html.escape(e['name'])}</td>"
                f"<td>{html.escape(e['mitigation'])}</td></tr>" for e in ex["techniques_expected"]) + "</table>")
        ff = res.flagged_flows(int(t), top=8)
        if len(ff):
            parts.append("<p><b>Flagged flows</b></p>" + ff[["time", "src_ip", "dst_ip", "dst_port", "proto", "bytes_fwd",
                                                            "bytes_bwd", "score", "why"]]
                         .to_html(index=False, float_format=lambda v: f"{v:.3g}"))
        parts.append("</div>")
    parts.append("<h2>All windows</h2>")
    cols = [c for c in ["time", "flows", "p_infiltration", "alarm", "stage_now", "stage_forecast", "true_stage"] if c in tb]
    parts.append(tb[cols].to_html(index=False, float_format=lambda v: f"{v:.3f}", max_rows=2000))
    parts.append("<p class='muted'>Forecasts are signed into receipts.json (Merkle root + Ed25519). "
                 "Verify with: python -m sentinet verify receipts.json</p></body></html>")
    Path(path).write_text("\n".join(parts), encoding="utf-8")
