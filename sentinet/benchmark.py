"""Benchmark: world model vs logistic regression on the same features.

Target (for every window t): will infiltration activity (Initial Access,
Lateral Movement, C2 or Exfiltration) appear in windows t+1..t+K?

Compared
  * World model          - full model, K-step Monte-Carlo rollout
  * World model, history shuffled - same weights, but the order of past windows
                           is scrambled; if this is as good as the full model,
                           the model has not really learned temporal dynamics
  * Logistic regression  - current window's features only (the static baseline)

Metrics: precision, recall, F1, false-positive rate at each model's own
validation-chosen threshold, ROC-AUC, PR-AUC, Brier score, and early warning:
for each infiltration onset, how many minutes before it the alarm first fired.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score, brier_score_loss, f1_score, roc_auc_score

from .dataset import make_sequence
from .engine import Forecaster
from .features.windows import WindowData
from .io.loaders import list_inputs
from .stages import INFILTRATION, N_STAGES, STAGES
from .train import load_windows


def _shuffle_windows(wd: WindowData, rng) -> tuple[WindowData, np.ndarray]:
    perm = rng.permutation(len(wd))
    sh = WindowData(t0=wd.t0, window=wd.window, times=wd.times, X=wd.X[perm], node_X=wd.node_X[perm],
                    node_mask=wd.node_mask[perm], adj=wd.adj[perm], node_ips=[wd.node_ips[i] for i in perm],
                    stage=wd.stage[perm], node_infil=wd.node_infil[perm], labelled=wd.labelled,
                    flow_window=wd.flow_window, n_flows=wd.n_flows[perm])
    return sh, perm


def _binary(y, p, thr):
    yhat = p >= thr
    tp = int((yhat & (y == 1)).sum()); fp = int((yhat & (y == 0)).sum())
    fn = int((~yhat & (y == 1)).sum()); tn = int((~yhat & (y == 0)).sum())
    prec = tp / max(tp + fp, 1); rec = tp / max(tp + fn, 1)
    return {"threshold": float(thr), "precision": prec, "recall": rec,
            "f1": 2 * prec * rec / max(prec + rec, 1e-9), "fpr": fp / max(fp + tn, 1),
            "roc_auc": float(roc_auc_score(y, p)) if 0 < y.sum() < len(y) else float("nan"),
            "pr_auc": float(average_precision_score(y, p)) if y.sum() > 0 else float("nan"),
            "brier": float(brier_score_loss(y, np.clip(p, 0, 1))), "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def _lead_times(stage, p, thr, window_min, K, lookback=60, quiet=30, warmup=10, max_gap=2):
    """For each infiltration onset (first infiltration window after >= `quiet` windows without one):
    warned = an alarm in the K windows before the onset;
    lead   = length of the alarm run that reaches the onset - alarms may flicker off for at most
             `max_gap` windows. Isolated false alarms long before the onset do not count as warning."""
    infil = np.isin(stage, INFILTRATION)
    leads, warned, onsets = [], 0, 0
    for t in range(warmup, len(stage)):
        if infil[t] and not infil[max(0, t - quiet):t].any():
            onsets += 1
            lo = max(warmup, t - K)
            if not (p[lo:t] >= thr).any():
                continue
            warned += 1
            first, gap = t, 0
            for u in range(t - 1, max(warmup, t - lookback) - 1, -1):
                if p[u] >= thr:
                    first, gap = u, 0
                else:
                    gap += 1
                    if gap > max_gap:
                        break
            leads.append((t - first) * window_min)
    return onsets, warned, leads


def _threshold_at_fpr(y, p, fpr):
    neg = np.sort(p[y == 0])
    if len(neg) == 0:
        return 0.5
    return float(neg[min(len(neg) - 1, int(np.ceil((1 - fpr) * len(neg))))])


def predict_all(fc: Forecaster, test_paths, fmt="auto", samples=32, seed=0) -> list[dict]:
    """World model, shuffled-history world model and logistic regression on every capture."""
    rng = np.random.default_rng(seed)
    paths = [p for d in (test_paths if isinstance(test_paths, (list, tuple)) else [test_paths]) for p in list_inputs(d)]
    items = load_windows(paths, fc.cfg["window"], fc.cfg["max_nodes"], fmt, verbose=False)
    out = []
    for nm, wd in items:
        r = fc.run_windows(wd, samples=samples, explain=False, seed=seed)
        seq = r["seq"]
        sh, perm = _shuffle_windows(wd, rng)
        rs = fc.run_windows(sh, samples=samples, explain=False, seed=seed)
        p_sh = np.empty(len(wd), np.float32)
        p_sh[perm] = rs["p_infil"]
        out.append({"name": nm, "stage": wd.stage, "window_s": wd.window, "y": seq.cum[:, -1], "ymask": seq.cum_mask[:, -1],
                    "p_wm": r["p_infil"], "p_sh": p_sh, "p_lr": r["lr_p"], "stage_now": r["stage_now"].argmax(1),
                    "stage_future": r["stage_future"].argmax(2)})
    return out


def run_benchmark(fc: Forecaster, test_paths, fmt="auto", samples=32, seed=0, name="test", preds=None, log=print) -> dict:
    preds = preds if preds is not None else predict_all(fc, test_paths, fmt, samples, seed)
    K = fc.K
    thr_w, thr_l = fc.threshold, fc.cfg.get("lr_threshold", 0.5)
    ys, pw, ps, pl = [], [], [], []
    for c in preds:
        v = c["ymask"].copy()
        v[:10] = False
        ys.append(c["y"][v]); pw.append(c["p_wm"][v]); ps.append(c["p_sh"][v]); pl.append(c["p_lr"][v])
    y = np.concatenate(ys).astype(int)
    pw, ps, pl = np.concatenate(pw), np.concatenate(ps), np.concatenate(pl)
    res = {"name": name, "captures": len(preds), "windows": int(len(y)), "positives": int(y.sum()), "horizon_K": K,
           "window_seconds": fc.cfg["window"], "models": {}}
    m_w = _binary(y, pw, thr_w)
    thr_l_eq = _threshold_at_fpr(y, pl, m_w["fpr"])
    res["models"]["world_model"] = m_w
    res["models"]["world_model_history_shuffled"] = _binary(y, ps, thr_w)
    res["models"]["logistic_regression"] = _binary(y, pl, thr_l)
    res["models"]["logistic_regression_equal_fpr"] = _binary(y, pl, thr_l_eq)
    for key, p_key, thr in (("world_model", "p_wm", thr_w), ("logistic_regression", "p_lr", thr_l),
                            ("logistic_regression_equal_fpr", "p_lr", thr_l_eq)):
        on, wa, L = 0, 0, []
        for c in preds:
            o, w, l_ = _lead_times(c["stage"], c[p_key], thr, c["window_s"] / 60, K)
            on += o; wa += w; L += l_
        res["models"][key]["early_warning"] = {"onsets": on, "warned_within_K": wa, "warned_share": wa / max(on, 1),
                                               "median_lead_minutes": float(np.median(L)) if L else 0.0}
    lab = [c["stage"] >= 0 for c in preds]
    st = np.concatenate([c["stage"][m] for c, m in zip(preds, lab)])
    sp = np.concatenate([c["stage_now"][m] for c, m in zip(preds, lab)])
    res["stage_detection_macro_f1"] = float(f1_score(st, sp, average="macro", labels=list(range(N_STAGES)), zero_division=0))
    res["stage_forecast_macro_f1"] = {}
    for k in (1, K):
        tru = np.concatenate([c["stage"][k:] for c in preds])
        prd = np.concatenate([c["stage_future"][:len(c["stage"]) - k, k - 1] for c in preds])
        res["stage_forecast_macro_f1"][f"t+{k}"] = float(f1_score(tru, prd, average="macro", labels=list(range(N_STAGES)),
                                                                  zero_division=0))
    res["stage_support"] = {STAGES[i]: int((st == i).sum()) for i in range(N_STAGES)}
    return res


def to_markdown(results: list[dict]) -> str:
    out = []
    for r in results:
        out.append(f"### {r['name']}\n")
        out.append(f"{r['captures']} captures, {r['windows']} forecast windows ({r['positives']} with infiltration "
                   f"in the next {r['horizon_K']} x {int(r['window_seconds'])} s windows).\n")
        out.append("| Model | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC | Brier | Onsets warned within K | Median lead (min) |")
        out.append("|---|---|---|---|---|---|---|---|---|---|")
        names = {"world_model": "**World model (ours)**", "world_model_history_shuffled": "World model, history shuffled",
                 "logistic_regression": "Logistic regression (baseline, own F1-optimal threshold)",
                 "logistic_regression_equal_fpr": "Logistic regression at the world model's FPR"}
        for k, lab in names.items():
            if k not in r["models"]:
                continue
            m = r["models"][k]
            ew = m.get("early_warning")
            ews = f"{ew['warned_within_K']}/{ew['onsets']} ({ew['warned_share']:.0%})" if ew else "-"
            lead = f"{ew['median_lead_minutes']:.0f}" if ew else "-"
            out.append(f"| {lab} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['fpr']:.3f} | "
                       f"{m['roc_auc']:.3f} | {m['pr_auc']:.3f} | {m['brier']:.3f} | {ews} | {lead} |")
        out.append(f"\nStage detection macro-F1 (current window): {r['stage_detection_macro_f1']:.3f}. "
                   f"Stage forecast macro-F1: " + ", ".join(f"{k} = {v:.3f}" for k, v in r["stage_forecast_macro_f1"].items()) + ".\n")
    return "\n".join(out)


def save_results(results: list[dict], out_dir) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "benchmark.json").write_text(json.dumps(results, indent=1, default=float))
    (out / "benchmark.md").write_text(to_markdown(results))
