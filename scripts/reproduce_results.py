"""Reproduce results/benchmark.md end to end (about 45 min on a 4-core CPU).

  python scripts/reproduce_results.py --data-dir data --weights weights --out results

Steps (each is skipped when its output already exists):
  1. generate 48 training, 30 test and 16 slow-APT-only test scenarios (12 h each)
  2. train the world model on the training scenarios            -> --weights
  3. train a second model on the training scenarios that contain no slow_apt campaign
     (the "unseen attack pattern" experiment)                    -> <data-dir>/weights_no_slow_apt
  4. benchmark: main model on the test set; main and hold-out models on the slow-APT test set
"""
import argparse
import json
import os
import pickle
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import torch  # noqa: E402

from sentinet.benchmark import predict_all, run_benchmark, save_results  # noqa: E402
from sentinet.engine import Forecaster  # noqa: E402
from sentinet.synth.generator import generate_dataset  # noqa: E402
from sentinet.train import train  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--weights", default="weights")
    ap.add_argument("--out", default="results")
    ap.add_argument("--samples", type=int, default=32)
    a = ap.parse_args()
    torch.set_num_threads(max(1, min(4, os.cpu_count() or 1)))
    d = Path(a.data_dir)
    sets = {"train": dict(n_scenarios=48, seed0=0), "test": dict(n_scenarios=30, seed0=5000),
            "test_slow_apt": dict(n_scenarios=16, seed0=7000, campaigns=["slow_apt"])}
    for name, kw in sets.items():
        if not (d / name).exists():
            print(f"generating {name}")
            generate_dataset(d / name, hours=12, **kw)
    if not (Path(a.weights) / "world_model.pt").exists():
        train(str(d / "train"), a.weights)
    hold = d / "train_no_slow_apt"
    if not hold.exists():
        hold.mkdir(parents=True)
        for m in sorted((d / "train").glob("*.meta.json")):
            meta = json.loads(m.read_text())
            if not any(c["template"] == "slow_apt" for c in meta["campaigns"]):
                csv = m.with_name(m.name.replace(".meta.json", ".csv.gz"))
                for src in (csv, m):
                    (hold / src.name).write_bytes(src.read_bytes())
    w_hold = d / "weights_no_slow_apt"
    if not (w_hold / "world_model.pt").exists():
        train(str(hold), str(w_hold))

    cache = d / "predictions.pkl"
    preds = pickle.loads(cache.read_bytes()) if cache.exists() else {}
    runs = [("main_test", a.weights, d / "test"), ("main_slow", a.weights, d / "test_slow_apt"),
            ("hold_slow", str(w_hold), d / "test_slow_apt")]
    fcs = {}
    for key, w, data in runs:
        fcs[key] = Forecaster.load(w)
        if key not in preds:
            print(f"predicting {key} ...")
            preds[key] = predict_all(fcs[key], data, samples=a.samples)
            cache.write_bytes(pickle.dumps(preds))
    results = [
        run_benchmark(fcs["main_test"], None, preds=preds["main_test"],
                      name="Held-out simulated scenarios: 30 x 12 h, all attack types"),
        run_benchmark(fcs["hold_slow"], None, preds=preds["hold_slow"],
                      name="Unseen attack pattern: low-and-slow APT, model trained WITHOUT any slow-APT campaign (16 x 12 h)"),
        run_benchmark(fcs["main_slow"], None, preds=preds["main_slow"],
                      name="Same slow-APT test set, model that saw slow-APT campaigns in training (reference)"),
    ]
    save_results(results, a.out)
    print((Path(a.out) / "benchmark.md").read_text())


if __name__ == "__main__":
    main()
