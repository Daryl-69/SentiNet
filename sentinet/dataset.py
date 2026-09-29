"""Window sequences -> training targets, normalisation and batches."""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import torch

from .features.windows import WindowData
from .stages import INFILTRATION


@dataclass
class Normaliser:
    x_mean: np.ndarray
    x_std: np.ndarray
    n_mean: np.ndarray
    n_std: np.ndarray

    @classmethod
    def fit(cls, wds: list[WindowData]) -> "Normaliser":
        X = np.concatenate([w.X for w in wds])
        nodes = np.concatenate([w.node_X[w.node_mask] for w in wds])
        xs = X.std(0)
        ns = nodes.std(0)
        return cls(X.mean(0), np.where(xs < 1e-6, 1.0, xs), nodes.mean(0), np.where(ns < 1e-6, 1.0, ns))

    def x(self, X):
        return ((X - self.x_mean) / self.x_std).astype(np.float32)

    def nodes(self, node_X, mask):
        out = ((node_X - self.n_mean) / self.n_std).astype(np.float32)
        out[~mask] = 0.0
        return out

    def state_dict(self):
        return {k: getattr(self, k).tolist() for k in ("x_mean", "x_std", "n_mean", "n_std")}

    @classmethod
    def from_state(cls, d):
        return cls(*(np.asarray(d[k], dtype=np.float32) for k in ("x_mean", "x_std", "n_mean", "n_std")))


@dataclass
class Sequence:
    wd: WindowData
    X: np.ndarray            # [T, F] normalised
    node_X: np.ndarray       # [T, N, Fn] normalised
    stage: np.ndarray        # [T]  -1 = unknown
    infil: np.ndarray        # [T]  bool
    cum: np.ndarray          # [T, K] infiltration within 1..k windows
    cum_mask: np.ndarray     # [T, K]
    node_future: np.ndarray  # [T, N] host involved in infiltration within K
    valid: np.ndarray        # [T] usable as a forecast origin
    name: str = ""

    def __len__(self):
        return len(self.X)


def make_sequence(wd: WindowData, norm: Normaliser, horizon: int, warmup: int = 10, name: str = "") -> Sequence:
    T = len(wd)
    K = horizon
    stage = wd.stage.copy()
    labelled = wd.labelled or (stage >= 0).all()
    infil = np.isin(stage, INFILTRATION)
    cum = np.zeros((T, K), dtype=np.float32)
    cum_mask = np.zeros((T, K), dtype=bool)
    for k in range(1, K + 1):
        ok = np.arange(T) + k < T
        fut = np.zeros(T, dtype=bool)
        if T > k:
            fut[:T - k] = infil[k:]
        prev = cum[:, k - 2] if k > 1 else np.zeros(T, dtype=np.float32)
        cum[:, k - 1] = np.maximum(prev, fut.astype(np.float32))
        cum_mask[:, k - 1] = ok & labelled
    # hosts involved in infiltration within the horizon
    inv = [set(np.asarray(wd.node_ips[t], dtype=object)[wd.node_infil[t, :len(wd.node_ips[t])]].tolist())
           if len(wd.node_ips[t]) else set() for t in range(T)]
    N = wd.node_mask.shape[1]
    node_future = np.zeros((T, N), dtype=np.float32)
    for t in range(T):
        future = set().union(*inv[t + 1:t + 1 + K]) if t + 1 < T else set()
        if future:
            for j, ip in enumerate(wd.node_ips[t]):
                if ip in future:
                    node_future[t, j] = 1.0
    valid = np.zeros(T, dtype=bool)
    valid[warmup:max(warmup, T - 1)] = labelled
    return Sequence(wd=wd, X=norm.x(wd.X), node_X=norm.nodes(wd.node_X, wd.node_mask), stage=stage, infil=infil,
                    cum=cum, cum_mask=cum_mask, node_future=node_future, valid=valid, name=name)


def batch(seqs: list[Sequence], idx: list[tuple[int, int]], context: int, horizon: int, device="cpu") -> dict:
    """Chunks of windows t-context+1 .. t+horizon around each (seq, t)."""
    L, K = context, horizon
    W = L + K
    B = len(idx)
    s0 = seqs[0]
    F, N, Fn = s0.X.shape[1], s0.node_X.shape[1], s0.node_X.shape[2]
    X = np.zeros((B, W, F), np.float32)
    NX = np.zeros((B, W, N, Fn), np.float32)
    A = np.zeros((B, W, N, N), np.float32)
    M = np.zeros((B, W, N), bool)
    pad = np.ones((B, W), bool)
    stage = np.full((B, W), -1, np.int64)
    cum = np.zeros((B, K), np.float32)
    cmask = np.zeros((B, K), bool)
    nf = np.zeros((B, N), np.float32)
    nfm = np.zeros((B, N), bool)
    for b, (si, t) in enumerate(idx):
        s = seqs[si]
        T = len(s)
        lo, hi = t - L + 1, t + K + 1
        a, z = max(lo, 0), min(hi, T)
        o = a - lo
        n = z - a
        X[b, o:o + n] = s.X[a:z]
        NX[b, o:o + n] = s.node_X[a:z]
        A[b, o:o + n] = s.wd.adj[a:z]
        M[b, o:o + n] = s.wd.node_mask[a:z]
        pad[b, o:o + n] = False
        stage[b, o:o + n] = s.stage[a:z]
        cum[b] = s.cum[t]
        cmask[b] = s.cum_mask[t]
        nf[b] = s.node_future[t]
        nfm[b] = s.wd.node_mask[t] & bool(s.cum_mask[t].any())
    tt = lambda v: torch.from_numpy(v).to(device)  # noqa: E731
    return {"X": tt(X), "node_X": tt(NX), "adj": tt(A), "node_mask": tt(M), "pad": tt(pad), "stage": tt(stage),
            "cum": tt(cum), "cum_mask": tt(cmask), "node_future": tt(nf), "node_future_mask": tt(nfm)}
