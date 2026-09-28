"""Training: world model + logistic-regression baseline + flow anomaly scorer."""
from __future__ import annotations

import json
import time
from pathlib import Path

import joblib
import numpy as np
import torch
import torch.nn.functional as F_

from .dataset import Normaliser, Sequence, batch, make_sequence
from .features.windows import FEATURE_NAMES, NODE_FEATURES, WindowData, featurize
from .io.loaders import list_inputs, load
from .models.baseline import FlowScorer, fit_logreg
from .models.world_model import WorldModel, gaussian_nll, kl_normal
from .stages import N_STAGES, STAGES

DEFAULTS = dict(window=60.0, max_nodes=48, context=30, horizon=10, d=64, dz=32, dg=32, heads=4, layers=2,
                epochs=14, steps_per_epoch=250, batch_size=48, lr=2e-3, weight_decay=1e-4, warmup=10,
                val_fraction=0.2, seed=0, samples=64, threshold=None)


def load_windows(paths, window=60.0, max_nodes=48, fmt="auto", labelled=True, verbose=True) -> list[tuple[str, WindowData]]:
    out = []
    for p in paths:
        t = time.time()
        df = load(p, fmt)
        meta_path = Path(str(p).replace(".csv.gz", ".meta.json").replace(".csv", ".meta.json"))
        t0 = t_end = None
        if meta_path.exists():
            meta = json.loads(meta_path.read_text())
            t0, t_end = meta.get("t0"), meta.get("t_end")
        wd = featurize(df, window=window, max_nodes=max_nodes, t0=t0, t_end=t_end, labelled=labelled)
        out.append((Path(p).name, wd))
        if verbose:
            print(f"  {Path(p).name:32s} {len(df):8d} flows -> {len(wd):5d} windows  ({time.time() - t:.1f}s)")
    return out


def _class_weights(seqs: list[Sequence]) -> torch.Tensor:
    st = np.concatenate([s.stage[s.stage >= 0] for s in seqs])
    cnt = np.bincount(st, minlength=N_STAGES).astype(float)
    w = 1.0 / np.sqrt(np.maximum(cnt, 1.0))
    w = w / w[cnt > 0].mean()
    w[cnt == 0] = 0.0
    return torch.tensor(w, dtype=torch.float32)


def compute_loss(model: WorldModel, b: dict, cw: torch.Tensor, pos_w: float, host_pos_w: float, L: int, K: int,
                 train: bool = True):
    e, nh, _ = model.encode_windows(b["X"], b["node_X"], b["adj"], b["node_mask"])
    c, _ = model.contextualise(e, b["pad"])
    mu_q, ls_q = model.posterior(c)
    z_q = mu_q + torch.randn_like(mu_q) * ls_q.exp() if train else mu_q
    h0 = model.start(c, z_q)
    xm, xls, st, _ = model.decode(z_q, h0)
    live = (~b["pad"]).float()
    recon = (gaussian_nll(b["X"], xm, xls).mean(-1) * live).sum() / live.sum().clamp(min=1)
    kl0 = (kl_normal(mu_q, ls_q, torch.zeros_like(mu_q), torch.zeros_like(ls_q)) * live).sum() / live.sum().clamp(min=1)
    lab = b["stage"] >= 0
    stage_now = F_.cross_entropy(st[lab], b["stage"][lab], weight=cw) if lab.any() else st.sum() * 0

    # roll the latent dynamics forward from the forecast origin (position L-1)
    t = L - 1
    z, h = z_q[:, t], h0[:, t]
    pred_nll, pred_n, cons, stage_f, stage_n = 0.0, 0.0, 0.0, 0.0, 0
    hz = []
    for k in range(1, K + 1):
        h, pm, pls = model.step(z, h)
        z = pm + torch.randn_like(pm) * pls.exp() if train else pm
        xk, xlsk, stk, hzk = model.decode(z, h)
        hz.append(hzk)
        m = (~b["pad"][:, t + k]).float()
        pred_nll = pred_nll + (gaussian_nll(b["X"][:, t + k], xk, xlsk).mean(-1) * m).sum()
        pred_n += m.sum()
        # latent consistency: the imagined prior should match what the posterior sees at t+k
        mq, lq = mu_q[:, t + k], ls_q[:, t + k]
        kl = 0.8 * kl_normal(mq.detach(), lq.detach(), pm, pls) + 0.2 * kl_normal(mq, lq, pm.detach(), pls.detach())
        cons = cons + (kl * m).sum()
        sk = b["stage"][:, t + k]
        ok = sk >= 0
        if ok.any():
            stage_f = stage_f + F_.cross_entropy(stk[ok], sk[ok], weight=cw, reduction="sum")
            stage_n += int(ok.sum())
    pred_nll = pred_nll / max(float(pred_n), 1.0)
    cons = cons / max(float(pred_n), 1.0)
    stage_f = stage_f / max(stage_n, 1)
    hazard = torch.sigmoid(torch.stack(hz, 1))
    cum = (1 - torch.cumprod(1 - hazard, 1)).clamp(1e-5, 1 - 1e-5)
    cm = b["cum_mask"].float()
    wts = torch.where(b["cum"] > 0.5, torch.full_like(cm, pos_w), torch.ones_like(cm)) * cm
    cum_loss = (F_.binary_cross_entropy(cum, b["cum"], reduction="none") * wts).sum() / cm.sum().clamp(min=1)
    hl = model.host_risk(nh[:, t], c[:, t])
    nm = b["node_future_mask"].float()
    host_loss = (F_.binary_cross_entropy_with_logits(hl, b["node_future"], reduction="none",
                                                     pos_weight=torch.tensor(host_pos_w)) * nm).sum() / nm.sum().clamp(min=1)
    total = (0.5 * recon + 1.0 * pred_nll + 0.01 * kl0 + 0.1 * cons + 1.0 * stage_now + 1.0 * stage_f
             + 2.0 * cum_loss + 0.5 * host_loss)
    f = lambda v: float(v.detach()) if torch.is_tensor(v) else float(v)  # noqa: E731
    parts = dict(recon=f(recon), pred=f(pred_nll), kl=f(kl0), cons=f(cons), stage=f(stage_now),
                 stage_f=f(stage_f), cum=f(cum_loss), host=f(host_loss))
    return total, parts, cum[:, -1].detach()


def _sample_index(seqs, rng, n, boost=3.0):
    pools = []
    for si, s in enumerate(seqs):
        ts = np.flatnonzero(s.valid)
        w = np.where((s.cum[ts, -1] > 0) | (s.stage[ts] > 0), boost, 1.0)
        pools.append((si, ts, w))
    all_si = np.concatenate([np.full(len(ts), si) for si, ts, _ in pools])
    all_t = np.concatenate([ts for _, ts, _ in pools])
    all_w = np.concatenate([w for _, _, w in pools])
    pick = rng.choice(len(all_t), size=n, p=all_w / all_w.sum())
    return list(zip(all_si[pick].tolist(), all_t[pick].tolist()))


def _auc(y, s):
    from sklearn.metrics import roc_auc_score
    return float(roc_auc_score(y, s)) if 0 < y.sum() < len(y) else float("nan")


def train(data_paths, out_dir, fmt="auto", val_paths=None, log=print, **kw):
    cfg = {**DEFAULTS, **{k: v for k, v in kw.items() if v is not None}}
    torch.manual_seed(cfg["seed"])
    rng = np.random.default_rng(cfg["seed"])
    torch.set_num_threads(max(1, torch.get_num_threads()))
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    paths = [p for d in (data_paths if isinstance(data_paths, (list, tuple)) else [data_paths]) for p in list_inputs(d)]
    log(f"[1/5] loading and featurising {len(paths)} capture(s)")
    items = load_windows(paths, cfg["window"], cfg["max_nodes"], fmt, verbose=True)
    if val_paths:
        vp = [p for d in (val_paths if isinstance(val_paths, (list, tuple)) else [val_paths]) for p in list_inputs(d)]
        val_items = load_windows(vp, cfg["window"], cfg["max_nodes"], fmt, verbose=True)
        train_items = items
    else:
        perm = rng.permutation(len(items))
        n_val = max(1, int(round(len(items) * cfg["val_fraction"]))) if len(items) > 1 else 0
        val_items = [items[i] for i in perm[:n_val]]
        train_items = [items[i] for i in perm[n_val:]] or items

    norm = Normaliser.fit([w for _, w in train_items])
    L, K = cfg["context"], cfg["horizon"]
    tr = [make_sequence(w, norm, K, cfg["warmup"], n) for n, w in train_items]
    va = [make_sequence(w, norm, K, cfg["warmup"], n) for n, w in val_items]
    n_pos = sum(float(s.cum[s.valid, -1].sum()) for s in tr)
    n_all = sum(int(s.valid.sum()) for s in tr)
    pos_w = float(np.clip((n_all - n_pos) / max(n_pos, 1), 1, 20)) ** 0.5
    hp = np.concatenate([s.node_future[s.valid][s.wd.node_mask[s.valid]] for s in tr])
    host_pos_w = float(np.clip((len(hp) - hp.sum()) / max(hp.sum(), 1), 1, 200)) ** 0.5
    cw = _class_weights(tr)
    log(f"      train windows={n_all}  infiltration-within-{K} positives={int(n_pos)}  val captures={len(va)}")
    log("      stage distribution: " + ", ".join(
        f"{STAGES[i]}={int(c)}" for i, c in enumerate(np.bincount(np.concatenate([s.stage[s.stage >= 0] for s in tr]), minlength=N_STAGES))))

    model = WorldModel(len(FEATURE_NAMES), len(NODE_FEATURES), N_STAGES, d=cfg["d"], dz=cfg["dz"], dg=cfg["dg"],
                       heads=cfg["heads"], layers=cfg["layers"], context=L, horizon=K)
    opt = torch.optim.AdamW(model.parameters(), lr=cfg["lr"], weight_decay=cfg["weight_decay"])
    total_steps = cfg["epochs"] * cfg["steps_per_epoch"]
    sched = torch.optim.lr_scheduler.OneCycleLR(opt, max_lr=cfg["lr"], total_steps=total_steps, pct_start=0.1)
    log(f"[2/5] training world model ({sum(p.numel() for p in model.parameters()):,} parameters, "
        f"{cfg['epochs']} epochs x {cfg['steps_per_epoch']} steps)")

    val_idx = [(si, int(t)) for si, s in enumerate(va) for t in np.flatnonzero(s.valid)[::3]] if va else []
    best, best_state, history = -1.0, None, []
    for ep in range(cfg["epochs"]):
        model.train()
        t0 = time.time()
        agg = {}
        for _ in range(cfg["steps_per_epoch"]):
            idx = _sample_index(tr, rng, cfg["batch_size"])
            b = batch(tr, idx, L, K)
            loss, parts, _ = compute_loss(model, b, cw, pos_w, host_pos_w, L, K, train=True)
            opt.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            for k, v in parts.items():
                agg[k] = agg.get(k, 0.0) + v / cfg["steps_per_epoch"]
        # validation: AUC of P(infiltration within K) on held-out captures
        model.eval()
        vauc, vloss = float("nan"), float("nan")
        if val_idx:
            ys, ss, ls = [], [], []
            with torch.no_grad():
                for i in range(0, len(val_idx), 128):
                    chunk = val_idx[i:i + 128]
                    b = batch(va, chunk, L, K)
                    l_, _, p = compute_loss(model, b, cw, pos_w, host_pos_w, L, K, train=False)
                    ls.append(float(l_) * len(chunk))
                    m = b["cum_mask"][:, -1]
                    ys.append(b["cum"][:, -1][m].numpy())
                    ss.append(p[m].numpy())
            vauc = _auc(np.concatenate(ys), np.concatenate(ss))
            vloss = sum(ls) / len(val_idx)
        score = vauc if not np.isnan(vauc) else -vloss
        history.append({"epoch": ep + 1, **{k: round(v, 4) for k, v in agg.items()}, "val_auc": vauc, "val_loss": vloss})
        log(f"      epoch {ep + 1:2d}  loss parts " + " ".join(f"{k}={v:.3f}" for k, v in agg.items())
            + f"  | val AUC={vauc:.3f} loss={vloss:.3f}  ({time.time() - t0:.0f}s)")
        if score > best:
            best, best_state = score, {k: v.clone() for k, v in model.state_dict().items()}
    if best_state is not None:
        model.load_state_dict(best_state)
    model.eval()

    log("[3/5] logistic-regression baseline on the same window features")
    lr_model = fit_logreg(tr, K)
    log("[4/5] flow anomaly scorer (flags individual flows for the analyst)")
    flow_frames = []
    for p in paths[: min(len(paths), 8)]:
        df = load(p, fmt)
        flow_frames.append(df[df["stage"] == 0].sample(min(20000, int((df["stage"] == 0).sum())), random_state=0))
    import pandas as pd
    scorer = FlowScorer().fit(pd.concat(flow_frames, ignore_index=True))

    # decision threshold: the one that maximises F1 on validation forecasts
    from .engine import Forecaster
    fc = Forecaster(model, norm, cfg, lr_model=lr_model, flow_scorer=scorer)
    thr = cfg["threshold"]
    if thr is None and va:
        ys, ps = [], []
        for s in va:
            r = fc.run_windows(s.wd, samples=32, explain=False)
            m = s.cum_mask[:, -1] & s.valid
            ys.append(s.cum[m, -1])
            ps.append(r["p_infil"][m])
        thr = best_f1_threshold(np.concatenate(ys), np.concatenate(ps))
    cfg["threshold"] = float(thr if thr is not None else 0.5)
    cfg["lr_threshold"] = float(best_f1_threshold(
        np.concatenate([s.cum[s.cum_mask[:, -1] & s.valid, -1] for s in va]) if va else np.array([0, 1]),
        np.concatenate([lr_model.predict_proba(s.X[s.cum_mask[:, -1] & s.valid])[:, 1] for s in va]) if va else np.array([0.2, 0.8])))

    log(f"[5/5] saving to {out}")
    save(out, model, norm, cfg, lr_model, scorer, history)
    return fc


def best_f1_threshold(y, p) -> float:
    from sklearn.metrics import precision_recall_curve
    if y.sum() == 0:
        return 0.5
    pr, rc, th = precision_recall_curve(y, p)
    f1 = 2 * pr * rc / np.maximum(pr + rc, 1e-9)
    i = int(np.nanargmax(f1[:-1])) if len(th) else 0
    return float(th[i]) if len(th) else 0.5


def save(out: Path, model, norm, cfg, lr_model, scorer, history=None):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    torch.save({"state_dict": model.state_dict(), "model_cfg": model.cfg}, out / "world_model.pt")
    meta = {"config": cfg, "normaliser": norm.state_dict(), "features": FEATURE_NAMES, "node_features": NODE_FEATURES,
            "stages": STAGES, "history": history or []}
    (out / "meta.json").write_text(json.dumps(meta, indent=1, default=float))
    joblib.dump({"logreg": lr_model, "flow_scorer": scorer}, out / "baselines.joblib")
