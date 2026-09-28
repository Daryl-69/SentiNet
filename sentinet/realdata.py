"""Prepare real datasets (CIC-IDS2017/2018, CTU-13, UNSW-NB15, PCAP) for training.

1. discover(root)      find every flow/PCAP file under a folder and detect its format
2. prepare(files, out) load each file once, convert it to the canonical format and cut it
                       into time chunks (default 2 h) -> one training sequence per chunk
3. split(chunks)       assign whole chunks to train / validation / test, stratified so every
                       split gets chunks that contain infiltration. Rows are never mixed:
                       a chunk is a contiguous stretch of time.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np
import pandas as pd

from .io.loaders import _EXT_OK, detect_format, load
from .stages import INFILTRATION, STAGES
from .synth.generator import write_flows


def discover(root, verbose=True) -> list[dict]:
    """Every supported file under root, with its detected format (or why it cannot be used)."""
    out = []
    for p in sorted(Path(root).rglob("*")):
        if not p.is_file() or not p.name.lower().endswith(_EXT_OK) or p.name.endswith(".meta.json"):
            continue
        rec = {"path": str(p), "size_mb": round(p.stat().st_size / 1e6, 1)}
        try:
            rec["format"] = detect_format(p)
        except Exception as exc:  # noqa: BLE001
            rec["format"], rec["problem"] = None, str(exc)[:200]
        if rec["format"] == "cicflowmeter":
            head = pd.read_parquet(p).head(3) if str(p).endswith(".parquet") else pd.read_csv(p, nrows=3, encoding_errors="replace")
            cols = {c.strip().lower().replace(" ", "").replace("_", "") for c in head.columns}
            if "timestamp" not in cols:
                rec["format"], rec["problem"] = None, ("CICFlowMeter file without a Timestamp column (the 'MachineLearningCVE' "
                                                       "variant) - cannot be ordered in time; use 'GeneratedLabelledFlows'")
        out.append(rec)
    if verbose:
        for r in out:
            tag = r["format"] or f"SKIP: {r.get('problem', '?')}"
            print(f"  {r['size_mb']:9.1f} MB  {tag:14.14s}  {r['path']}")
    return out


def prepare(files, out_dir, fmt="auto", chunk_hours=2.0, window=60.0, min_windows=30, verbose=True) -> list[dict]:
    """Convert files to canonical chunk files in out_dir; returns chunk records."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    chunks = []
    span = chunk_hours * 3600.0
    for f in files:
        t = time.time()
        df = load(f, fmt)
        if len(df) == 0:
            continue
        t0 = np.floor(df["ts"].min() / window) * window
        t_end = df["ts"].max()
        stem = Path(f).name.split(".")[0][:60]
        k = 0
        for a in np.arange(t0, t_end + 1e-6, span):
            part = df[(df["ts"] >= a) & (df["ts"] < a + span)]
            n_win = int(np.ceil((min(a + span, t_end + 1) - a) / window))
            if len(part) < 100 or n_win < min_windows:
                continue
            name = f"{stem}__{k:03d}"
            path = out / f"{name}.csv.gz"
            write_flows(part, path)
            st = part["stage"].value_counts().to_dict()
            rec = {"file": str(path), "source": str(f), "t0": float(a), "t_end": float(min(a + span, t_end + 1)),
                   "flows": int(len(part)), "windows": n_win,
                   "has_infiltration": bool(part["stage"].isin(INFILTRATION).any()),
                   "stages": {STAGES[int(s)]: int(c) for s, c in sorted(st.items())}}
            (out / f"{name}.meta.json").write_text(json.dumps({"t0": rec["t0"], "t_end": rec["t_end"], **rec}, indent=1))
            chunks.append(rec)
            k += 1
        if verbose:
            st = df["stage"].value_counts().to_dict()
            print(f"  {Path(f).name[:50]:50s} {len(df):9,d} flows, {(t_end - t0) / 3600:5.1f} h -> {k} chunks "
                  f"({time.time() - t:.0f}s)  stages: " + ", ".join(f"{STAGES[int(s)]}={c:,}" for s, c in sorted(st.items())))
        del df
    return chunks


def split(chunks: list[dict], test=0.2, val=0.15, seed=0) -> dict:
    """Stratified split of whole chunks. Returns {'train': [...], 'val': [...], 'test': [...]} of file paths."""
    rng = np.random.default_rng(seed)
    res = {"train": [], "val": [], "test": []}
    for flag in (True, False):
        grp = [c["file"] for c in chunks if c["has_infiltration"] == flag]
        grp = [grp[i] for i in rng.permutation(len(grp))]
        n = len(grp)
        n_test = int(round(n * test)) if n >= 3 else (1 if n == 2 and flag else 0)
        n_val = int(round(n * val)) if n >= 4 else (1 if n >= 3 and flag else 0)
        n_test = max(n_test, 1) if flag and n >= 2 else n_test
        n_val = max(n_val, 1) if flag and n >= 3 else n_val
        res["test"] += grp[:n_test]
        res["val"] += grp[n_test:n_test + n_val]
        res["train"] += grp[n_test + n_val:]
    return res
