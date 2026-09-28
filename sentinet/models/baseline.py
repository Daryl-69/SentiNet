"""Baselines and helpers that are not the world model.

* Logistic regression on the same per-window features, predicting the same
  target (infiltration within the next K windows) from the current window
  only. This is the static baseline the problem statement asks for.
* FlowScorer: an Isolation Forest over per-flow features, fitted on benign
  flows. It does not forecast anything; it ranks individual flows inside a
  risky window so the analyst sees which ones to look at first.
"""
from __future__ import annotations

import ipaddress

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression

LATERAL = {22, 23, 135, 139, 445, 3389, 5900, 5985, 5986}
WEB = {80, 443, 8080, 8443}


def fit_logreg(seqs, horizon: int) -> LogisticRegression:
    X = np.concatenate([s.X[s.valid & s.cum_mask[:, -1]] for s in seqs])
    y = np.concatenate([s.cum[s.valid & s.cum_mask[:, -1], -1] for s in seqs])
    m = LogisticRegression(max_iter=3000, class_weight="balanced", C=1.0)
    m.fit(X, y.astype(int))
    return m


def _internal(ips: pd.Series) -> np.ndarray:
    cache = {}
    out = np.zeros(len(ips), dtype=float)
    for i, ip in enumerate(ips.astype(str).tolist()):
        v = cache.get(ip)
        if v is None:
            try:
                v = float(ipaddress.ip_address(ip).is_private)
            except ValueError:
                v = 0.0
            cache[ip] = v
        out[i] = v
    return out


def flow_features(df: pd.DataFrame) -> np.ndarray:
    dp = df["dst_port"].fillna(-1).astype(int)
    return np.column_stack([
        np.log1p(df["bytes_fwd"]), np.log1p(df["bytes_bwd"]), np.log1p(df["pkts_fwd"]), np.log1p(df["pkts_bwd"]),
        np.log1p(df["duration"].clip(lower=0)),
        ((df["syn"] > 0) & (df["ack"] == 0)).astype(float), (df["rst"] > 0).astype(float),
        (df["fin"] > 0).astype(float),
        dp.isin(LATERAL).astype(float), dp.isin(WEB).astype(float), (dp == 53).astype(float),
        ((dp >= 0) & (dp < 1024)).astype(float),
        _internal(df["src_ip"]), _internal(df["dst_ip"]),
        (df["ttl_mean"].fillna(-64) / 64.0), (df["win_mean"].fillna(65535) <= 1024).astype(float),
    ]).astype(np.float32)


class FlowScorer:
    def __init__(self, n_estimators: int = 150, seed: int = 0):
        self.model = IsolationForest(n_estimators=n_estimators, random_state=seed, contamination="auto")

    def fit(self, benign_flows: pd.DataFrame) -> "FlowScorer":
        self.model.fit(flow_features(benign_flows))
        return self

    def score(self, flows: pd.DataFrame) -> np.ndarray:
        """Higher = more unusual (0..1 roughly)."""
        if len(flows) == 0:
            return np.zeros(0)
        s = -self.model.score_samples(flow_features(flows))
        return np.clip((s - 0.35) / 0.4, 0, 1)
