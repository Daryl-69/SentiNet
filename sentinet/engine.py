"""Inference: capture -> windows -> world-model forecasts, explanations, what-if."""
from __future__ import annotations

import itertools
import json
import math
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch

from .dataset import Normaliser, make_sequence
from .features.windows import (FEATURE_GROUPS, FEATURE_HELP, FEATURE_NAMES, GROUP_NAMES, NODE_FEATURES,
                               WindowData, featurize)
from .io.loaders import is_labelled, load
from .models.world_model import WorldModel, infil_log_odds
from .stages import ATTACK_TACTIC, BENIGN, INFILTRATION, N_STAGES, STAGES

DEFAULT_WEIGHTS = Path(__file__).resolve().parent.parent / "weights"
PLAYERS = GROUP_NAMES + ["host_graph"]
GROUP_LABEL = {"volume": "Traffic volume", "tcp_flags": "TCP flags", "timing": "Timing / IAT", "ports": "Ports",
               "hosts": "Hosts & new connections", "egress": "Egress to internet", "packet": "Packet-level (TTL, window, payload)",
               "host_graph": "Host graph (who talks to whom)"}


class Forecaster:
    def __init__(self, model: WorldModel, norm: Normaliser, cfg: dict, lr_model=None, flow_scorer=None):
        self.model, self.norm, self.cfg = model.eval(), norm, cfg
        self.lr_model, self.flow_scorer = lr_model, flow_scorer
        self.L, self.K = model.context, model.horizon

    # ------------------------------------------------------------------ io
    @classmethod
    def load(cls, weights_dir=None) -> "Forecaster":
        w = Path(weights_dir or DEFAULT_WEIGHTS)
        if not (w / "world_model.pt").exists():
            raise FileNotFoundError(f"no trained weights in {w} - run `python -m sentinet train` first")
        ck = torch.load(w / "world_model.pt", map_location="cpu", weights_only=False)
        model = WorldModel(**ck["model_cfg"])
        model.load_state_dict(ck["state_dict"])
        meta = json.loads((w / "meta.json").read_text())
        extra = joblib.load(w / "baselines.joblib") if (w / "baselines.joblib").exists() else {}
        return cls(model, Normaliser.from_state(meta["normaliser"]), meta["config"], extra.get("logreg"),
                   extra.get("flow_scorer"))

    @property
    def threshold(self) -> float:
        return float(self.cfg.get("threshold", 0.5))

    # ------------------------------------------------------------ pipeline
    def featurize(self, flows: pd.DataFrame, labelled=None) -> WindowData:
        return featurize(flows, window=self.cfg["window"], max_nodes=self.cfg["max_nodes"],
                         labelled=labelled if labelled is not None else is_labelled(flows))

    @torch.no_grad()
    def _encode(self, seq):
        T = len(seq)
        m = self.model
        es, nhs, nas = [], [], []
        for a in range(0, T, 256):
            b = min(T, a + 256)
            tt = lambda v: torch.from_numpy(np.ascontiguousarray(v[a:b]))[None]  # noqa: E731
            e, nh, na = m.encode_windows(tt(seq.X), tt(seq.node_X), tt(seq.wd.adj), tt(seq.wd.node_mask))
            es.append(e[0]), nhs.append(nh[0]), nas.append(na[0])
        return torch.cat(es), torch.cat(nhs), torch.cat(nas)

    @torch.no_grad()
    def _context(self, e):
        T, L = e.shape[0], self.L
        c = torch.zeros_like(e)
        att = np.zeros((T, L), dtype=np.float32)
        CH = 256
        for s in range(0, T, CH):
            a = max(0, s - L + 1)
            b = min(T, s + CH)
            cc, w = self.model.contextualise(e[None, a:b], need_weights=True)
            c[s:b] = cc[0, s - a:]
            w = w[0].numpy()  # [len, len]
            for t in range(s, b):
                row = w[t - a]
                lo = max(0, t - L + 1)
                seg = row[lo - a:t - a + 1]
                att[t, L - len(seg):] = seg
        return c, att

    @torch.no_grad()
    def run_windows(self, wd: WindowData, samples: int | None = None, explain: bool = True, seed: int = 0) -> dict:
        torch.manual_seed(seed)
        S = samples or int(self.cfg.get("samples", 64))
        seq = make_sequence(wd, self.norm, self.K, warmup=0)
        e, nh, na = self._encode(seq)
        c, att = self._context(e)
        T, K = len(seq), self.K
        m = self.model
        mu, _ = m.posterior(c)
        h0 = m.start(c, mu)
        _, _, st_now, _ = m.decode(mu, h0)
        p_by_k = np.zeros((T, K), np.float32)
        lo = np.zeros(T, np.float32)
        hi = np.zeros(T, np.float32)
        fut_stage = np.zeros((T, K, N_STAGES), np.float32)
        fut_x = np.zeros((T, K, len(FEATURE_NAMES)), np.float32)
        for a in range(0, T, 64):
            b = min(T, a + 64)
            r = m.rollout(c[a:b], samples=S)
            pk = r["p_infil_by_k"].numpy()                 # [B, S, K]
            p_by_k[a:b] = pk.mean(1)
            lo[a:b] = np.quantile(pk[:, :, -1], 0.1, axis=1)
            hi[a:b] = np.quantile(pk[:, :, -1], 0.9, axis=1)
            fut_stage[a:b] = torch.softmax(r["stage_logits"], -1).mean(1).numpy()
            fut_x[a:b] = r["x_mean"].mean(1).numpy()
        host = torch.sigmoid(m.host_risk(nh, c)).numpy() * wd.node_mask
        out = {
            "p_infil": p_by_k[:, -1], "p_by_k": p_by_k, "p_lo": lo, "p_hi": hi,
            "stage_now": torch.softmax(st_now, -1).numpy(), "stage_future": fut_stage,
            "x_future": fut_x * self.norm.x_std + self.norm.x_mean,
            "host_risk": host, "node_att": na.numpy(), "attention": att, "seq": seq, "wd": wd,
        }
        if self.lr_model is not None:
            out["lr_p"] = self.lr_model.predict_proba(seq.X)[:, 1]
        out["_c"], out["_e"] = c, e
        return out

    def run(self, source, fmt="auto", labels=None, samples=None, assets=None) -> "Result":
        """assets: optional dict or CSV path (ip, cvss[, cves]) of known host vulnerabilities."""
        flows = source if isinstance(source, pd.DataFrame) else load(source, fmt, labels=labels)
        wd = self.featurize(flows)
        if isinstance(assets, (str, Path)):
            from .knowledge import load_assets
            assets = load_assets(assets)
        return Result(self, flows, wd, self.run_windows(wd, samples), assets=assets)

    # ---------------------------------------------------------- explanations
    @torch.no_grad()
    def _value(self, r: dict, t: int, xs: np.ndarray, graph_on: np.ndarray) -> np.ndarray:
        """P(infiltration within K) for window t with the current window's state
        replaced by rows of xs [P, F] (normalised) and the host graph switched on/off."""
        m, L = self.model, self.L
        seq = r["seq"]
        P = len(xs)
        nx = torch.from_numpy(seq.node_X[t])[None].expand(P, -1, -1).clone()
        adj = torch.from_numpy(seq.wd.adj[t])[None].expand(P, -1, -1).clone()
        mask = torch.from_numpy(seq.wd.node_mask[t])[None].expand(P, -1).clone()
        off = torch.from_numpy(~graph_on)
        nx[off] = 0.0
        adj[off] = 0.0
        e_t, _, _ = m.encode_windows(torch.from_numpy(xs)[:, None], nx[:, None], adj[:, None], mask[:, None])
        a = max(0, t - L + 1)
        ctx = r["_e"][a:t][None].expand(P, -1, -1)
        cc, _ = m.contextualise(torch.cat([ctx, e_t], 1))
        roll = m.rollout(cc[:, -1], samples=1, deterministic=True)
        # log-odds straight from the hazard logits: Shapley values add up and do not saturate near 100 %
        return infil_log_odds(roll["hazard_logit"][:, 0]).numpy()

    @staticmethod
    def _shapley(n: int, values: dict) -> np.ndarray:
        phi = np.zeros(n)
        fact = math.factorial
        for i in range(n):
            for S, v in values.items():
                if S & (1 << i):
                    continue
                s = bin(S).count("1")
                w = fact(s) * fact(n - s - 1) / fact(n)
                phi[i] += w * (values[S | (1 << i)] - v)
        return phi

    def explain(self, r: dict, t: int, top_groups: int = 3) -> dict:
        seq = r["seq"]
        x = seq.X[t]
        base = np.zeros_like(x)  # training mean in normalised space
        n = len(PLAYERS)
        coal = list(range(1 << n))
        xs = np.repeat(base[None], len(coal), 0)
        graph_on = np.zeros(len(coal), dtype=bool)
        for ci, S in enumerate(coal):
            for gi, g in enumerate(GROUP_NAMES):
                if S & (1 << gi):
                    idx = FEATURE_GROUPS[g]
                    xs[ci, idx] = x[idx]
            graph_on[ci] = bool(S & (1 << (n - 1)))
        v = self._value(r, t, xs.astype(np.float32), graph_on)
        phi_g = self._shapley(n, dict(zip(coal, v)))
        groups = sorted(({"group": PLAYERS[i], "label": GROUP_LABEL[PLAYERS[i]], "shap": float(phi_g[i])}
                         for i in range(n)), key=lambda d: -abs(d["shap"]))
        # feature-level Shapley inside the most influential groups (others kept at actual values)
        feats = []
        raw = seq.wd.X[t]
        pos = [g for g in sorted(groups, key=lambda d: -d["shap"]) if g["shap"] > 0][:top_groups]
        neg = [g for g in groups if g["shap"] < 0][:1]
        for gd in pos + neg:
            if gd["group"] == "host_graph":
                continue
            idx = FEATURE_GROUPS[gd["group"]]
            m_ = len(idx)
            cs = list(range(1 << m_))
            xs2 = np.repeat(x[None], len(cs), 0).copy()
            for ci, S in enumerate(cs):
                for j, fi in enumerate(idx):
                    if not S & (1 << j):
                        xs2[ci, fi] = base[fi]
            v2 = self._value(r, t, xs2.astype(np.float32), np.ones(len(cs), bool))
            phi = self._shapley(m_, dict(zip(cs, v2)))
            for j, fi in enumerate(idx):
                name = FEATURE_NAMES[fi]
                feats.append({"feature": name, "group": gd["group"], "shap": float(phi[j]),
                              "value": float(raw[fi]), "typical": float(self.norm.x_mean[fi]),
                              "z": float(x[fi]), "meaning": FEATURE_HELP.get(name, name)})
        feats.sort(key=lambda d: -abs(d["shap"]))
        return {"window": int(t), "p_infil": float(r["p_infil"][t]), "p_baseline": float(1 / (1 + np.exp(-v[0]))),
                "logit_full": float(v[-1]), "logit_baseline": float(v[0]),
                "groups": groups, "features": feats, "attention": r["attention"][t].tolist()}


class Result:
    """Everything the UI and the CLI need for one capture."""

    def __init__(self, fc: Forecaster, flows: pd.DataFrame, wd: WindowData, r: dict, assets: dict | None = None):
        self.fc, self.flows, self.wd, self.r = fc, flows, wd, r
        self.assets = assets or {}
        self.labelled = wd.labelled
        self.table = self._table()

    def _table(self) -> pd.DataFrame:
        r, wd, thr = self.r, self.wd, self.fc.threshold
        peak = r["stage_future"].max(1)                    # [T, S]
        nb = peak[:, 1:]
        pred = np.where((nb.max(1) >= 0.35) | (r["p_infil"] >= thr), nb.argmax(1) + 1, BENIGN)
        cur = r["stage_now"].argmax(1)
        df = pd.DataFrame({
            "window": np.arange(len(wd)), "time": pd.to_datetime(wd.times, unit="s"), "flows": wd.n_flows,
            "p_infiltration": r["p_infil"], "p_low": r["p_lo"], "p_high": r["p_hi"],
            "alarm": r["p_infil"] >= thr, "stage_now": [STAGES[i] for i in cur],
            "stage_forecast": [STAGES[i] for i in pred],
            "attack_tactic": [ATTACK_TACTIC[i][1] for i in pred],
        })
        if "lr_p" in r:
            df["p_logreg_baseline"] = r["lr_p"]
        if self.labelled:
            df["true_stage"] = [STAGES[s] if s >= 0 else "" for s in wd.stage]
            seq = r["seq"]
            df["true_infiltration_within_K"] = np.where(seq.cum_mask[:, -1], seq.cum[:, -1], np.nan)
        return df

    # ----------------------------------------------------------------- hosts
    def hosts(self, t: int, top: int = 10) -> pd.DataFrame:
        from .features.windows import make_internal_fn
        from .knowledge import exposure_adjusted
        inside = make_internal_fn()
        ips = self.wd.node_ips[t]
        risk = self.r["host_risk"][t][:len(ips)]
        att = self.r["node_att"][t][:len(ips)]
        df = pd.DataFrame({"host": ips, "internal": [inside(i) for i in ips], "risk_next_K": risk,
                           "graph_attention": att})
        if self.assets:
            df["cvss"] = [self.assets.get(i, {}).get("cvss", 0.0) for i in ips]
            df["cves"] = [self.assets.get(i, {}).get("cves", "") for i in ips]
            df["risk_with_exposure"] = exposure_adjusted(risk, ips, self.assets)
            return df.sort_values("risk_with_exposure", ascending=False).head(top).reset_index(drop=True)
        return df.sort_values("risk_next_K", ascending=False).head(top).reset_index(drop=True)

    # --------------------------------------------------------- flagged flows
    def flagged_flows(self, t: int, top: int = 15) -> pd.DataFrame:
        f = self.flows[self.wd.flow_window == t].copy()
        if f.empty:
            return f
        ips = self.wd.node_ips[t]
        risk = dict(zip(ips, self.r["host_risk"][t][:len(ips)]))
        hr = np.maximum(f["src_ip"].map(risk).fillna(0).to_numpy(), f["dst_ip"].map(risk).fillna(0).to_numpy())
        an = self.fc.flow_scorer.score(f) if self.fc.flow_scorer is not None else np.zeros(len(f))
        f["anomaly"] = an
        f["host_risk"] = hr
        f["score"] = 0.6 * an + 0.4 * hr
        f["why"] = [_why(row) for row in f.itertuples()]
        cols = ["time", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "bytes_fwd", "bytes_bwd", "pkts_fwd",
                "pkts_bwd", "syn", "ack", "rst", "ttl_mean", "win_mean", "score", "anomaly", "host_risk", "why"]
        f["time"] = pd.to_datetime(f["ts"], unit="s")
        if self.labelled:
            f["true_stage"] = [STAGES[int(s)] for s in f["stage"]]
            cols.append("true_stage")
        return f.sort_values("score", ascending=False).head(top)[cols].reset_index(drop=True)

    def port_summary(self, t: int, top: int = 5) -> list[tuple[int, int]]:
        f = self.flows[self.wd.flow_window == t]
        ips = self.wd.node_ips[t][:5]
        risky = [ip for ip, r in zip(self.wd.node_ips[t], self.r["host_risk"][t]) if r > 0.3] or ips
        g = f[f["src_ip"].isin(risky) | f["dst_ip"].isin(risky)]
        vc = g["dst_port"].astype(int).value_counts().head(top)
        return list(zip(vc.index.tolist(), vc.values.tolist()))

    def explain(self, t: int) -> dict:
        ex = self.fc.explain(self.r, t)
        ex["ports"] = self.port_summary(t)
        ex["hosts"] = self.hosts(t, 5).to_dict("records")
        f = self.flows[self.wd.flow_window == t]
        ex["flags"] = {"SYN without reply": int(((f["syn"] > 0) & (f["ack"] == 0)).sum()),
                       "RST": int((f["rst"] > 0).sum()), "FIN": int((f["fin"] > 0).sum()),
                       "PSH": int((f["psh"] > 0).sum()), "URG": int((f["urg"] > 0).sum())}
        ex["stage_forecast"] = self.table.loc[t, "stage_forecast"]
        from .features.windows import make_internal_fn
        from .knowledge import expected, observed
        raw = dict(zip(FEATURE_NAMES, self.wd.X[t].tolist()))
        zs = dict(zip(FEATURE_NAMES, self.r["seq"].X[t].tolist()))
        ex["techniques_observed"] = observed(raw, f, make_internal_fn(), zs)
        ex["techniques_expected"] = expected(self.r["stage_future"][t])
        ex["narrative"] = narrative(ex, self.table.loc[t])
        return ex

    def alarms(self) -> pd.DataFrame:
        return self.table[self.table["alarm"]]

    def alarm_onsets(self, top: int = 5) -> list[int]:
        """First window of each alarm episode (episodes separated by >= 5 quiet windows), highest risk first."""
        a = self.table["alarm"].to_numpy()
        starts, last = [], -10
        for i in np.flatnonzero(a):
            if i - last > 5:
                starts.append(int(i))
            last = i
        return starts[:top]


def _why(row) -> str:
    reasons = []
    if row.syn > 0 and row.ack == 0:
        reasons.append("SYN never answered")
    if row.rst > 0 and row.pkts_bwd <= 1:
        reasons.append("rejected (RST)")
    if int(row.dst_port) in (22, 135, 139, 445, 3389, 5985, 5986) and str(row.src_ip).startswith(("10.", "192.168.", "172.")) \
            and str(row.dst_ip).startswith(("10.", "192.168.", "172.")):
        reasons.append(f"internal remote-service port {int(row.dst_port)}")
    if row.bytes_fwd > 5e7:
        reasons.append(f"large upload {row.bytes_fwd / 1e6:.0f} MB")
    if not pd.isna(row.win_mean) and row.win_mean <= 1024 and row.proto == "tcp":
        reasons.append("scanner-sized TCP window")
    if int(row.dst_port) == 53 and row.bytes_fwd > 150:
        reasons.append("oversized DNS query")
    return ", ".join(reasons) or "unusual for this network"


def narrative(ex: dict, row) -> str:
    p = ex["p_infil"]
    out = [f"P(infiltration within the horizon) = {p:.0%}, forecast stage: {row['stage_forecast']}"]
    top = [g for g in ex["groups"] if g["shap"] > 0][:2]
    top_names = {g["group"] for g in top}
    drivers = [f["meaning"] for f in ex["features"] if f["shap"] > 0 and f["group"] in top_names][:3]
    if top:
        out.append("Main drivers in this window: " + ", ".join(g["label"] for g in top)
                   + (" (" + "; ".join(drivers) + ")" if drivers else ""))
    elif drivers:
        out.append("Main drivers in this window: " + "; ".join(drivers))
    pb = ex.get("p_baseline")
    if pb is not None and pb >= 0.5:
        out.append(f"Even with this window's traffic set to typical values the forecast would be {pb:.0%}: most of the "
                   "risk comes from the preceding windows (see temporal attention)")
    if ex.get("ports"):
        out.append("Busiest ports around risky hosts: " + ", ".join(f"{p_} ({n})" for p_, n in ex["ports"][:4]))
    inside = [h for h in ex.get("hosts", []) if h.get("internal")]
    if inside:
        h = inside[0]
        out.append(f"Internal host most likely to be involved next: {h['host']} "
                   f"({h.get('risk_with_exposure', h['risk_next_K']):.0%})")
    if ex.get("techniques_observed"):
        out.append("Evidence matches " + ", ".join(f"{o['technique']} {o['name']}" for o in ex["techniques_observed"][:3]))
    exp = [e for e in ex.get("techniques_expected", []) if e["stage"] != "Reconnaissance"][:2]
    if exp:
        out.append("Watch next for " + ", ".join(f"{e['technique']} ({e['name']})" for e in exp)
                   + f"; mitigation: {exp[0]['mitigation']}")
    return ". ".join(out) + "."


# -------------------------------------------------------------------- what-if
def apply_action(flows: pd.DataFrame, action: dict, from_time: float) -> pd.DataFrame:
    """Counterfactual: remove the traffic an action would have stopped from `from_time` on."""
    f = flows
    after = f["ts"] >= from_time
    kind = action.get("type")
    if kind == "block_port":
        hit = f["dst_port"] == int(action["port"])
    elif kind == "isolate_host":
        hit = (f["src_ip"] == action["ip"]) | (f["dst_ip"] == action["ip"])
    elif kind == "block_ip":
        hit = (f["src_ip"] == action["ip"]) | (f["dst_ip"] == action["ip"])
    else:
        raise ValueError(f"unknown action {action}")
    return f[~(after & hit)].reset_index(drop=True)


def whatif(fc: Forecaster, flows: pd.DataFrame, action: dict, from_time: float, samples=None, assets=None) -> Result:
    cf = apply_action(flows, action, from_time)
    wd = featurize(cf, window=fc.cfg["window"], max_nodes=fc.cfg["max_nodes"], labelled=is_labelled(flows),
                   t0=float(np.floor(flows["ts"].min() / fc.cfg["window"]) * fc.cfg["window"]),
                   t_end=float(flows["ts"].max()) + 1e-3)
    return Result(fc, cf, wd, fc.run_windows(wd, samples), assets=assets)
