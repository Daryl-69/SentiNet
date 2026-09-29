"""Build the SentiNet-Sim v1 dataset (labelled, multi-stage attack flows + PCAPs), deterministic.

  python scripts/make_dataset.py                      # -> dist/SentiNet-Sim-v1/ and dist/SentiNet-Sim-v1.zip
  python scripts/make_dataset.py --hours 12 --scale 2 # bigger

Layout
  train/  val/  test/          canonical flow CSVs (one file = one continuous stretch of a network) + .meta.json
  holdout_unseen_apt/          only the low-and-slow APT template, which train/val/test never contain
  pcap/                        raw packet captures + ground-truth label rules (to test the PCAP path)
  campaigns.csv                every attack campaign: file, template, stage phases with start/end times
  preview_5000_flows.csv       plain CSV to open in Excel
  DATASET_CARD.md              what is in it and how it was made
"""
import argparse
import gzip
import json
import shutil
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402

from sentinet.stages import STAGES  # noqa: E402
from sentinet.synth.generator import generate_scenario, write_flows  # noqa: E402
from sentinet.synth.pcapgen import flows_to_pcap, label_rules_from_flows  # noqa: E402

SEEN = ["web_exploit", "phishing", "bruteforce", "failed_attack", "ddos"]


def _job(j):
    split, seed, hours, templates, campaigns, out = j
    flows, meta = generate_scenario(seed, hours=hours, templates=templates, campaigns=campaigns)
    name = f"{split}_{seed:05d}"
    write_flows(flows, out / split / f"{name}.csv.gz")
    (out / split / f"{name}.meta.json").write_text(json.dumps(meta, indent=1))
    rows = [{"split": split, "file": f"{split}/{name}.csv.gz", "template": c["template"], "attacker": c["attacker"],
             "stage": STAGES[p["stage"]], "start": p["start"], "end": p["end"],
             "start_utc": pd.to_datetime(p["start"], unit="s").strftime("%Y-%m-%d %H:%M:%S"),
             "victims": " ".join(c["hosts"])}
            for c in meta["campaigns"] for p in c["phases"]]
    return split, name, len(flows), flows["stage"].value_counts().to_dict(), rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "dist" / "SentiNet-Sim-v1"))
    ap.add_argument("--hours", type=float, default=8.0)
    ap.add_argument("--scale", type=float, default=1.0, help="multiply the number of scenarios")
    ap.add_argument("--no-zip", action="store_true")
    a = ap.parse_args()
    t = time.time()
    out = Path(a.out)
    if out.exists():
        shutil.rmtree(out)
    n = {k: max(1, round(v * a.scale)) for k, v in {"train": 30, "val": 6, "test": 8, "holdout_unseen_apt": 4}.items()}
    seed0 = {"train": 10000, "val": 20000, "test": 30000, "holdout_unseen_apt": 40000}
    jobs = []
    for split, k in n.items():
        (out / split).mkdir(parents=True)
        for i in range(k):
            if split == "holdout_unseen_apt":
                jobs.append((split, seed0[split] + i, a.hours, None, ["slow_apt"] + (["failed_attack"] if i % 2 else []), out))
            else:
                jobs.append((split, seed0[split] + i, a.hours, SEEN, None, out))
    with ProcessPoolExecutor() as ex:
        res = list(ex.map(_job, jobs))

    campaigns = pd.DataFrame([r for x in res for r in x[4]])
    campaigns.to_csv(out / "campaigns.csv", index=False)
    stats = {}
    for split, name, nf, st, _ in res:
        s = stats.setdefault(split, {"files": 0, "flows": 0, "stages": {}})
        s["files"] += 1
        s["flows"] += nf
        for k, v in st.items():
            s["stages"][STAGES[int(k)]] = s["stages"].get(STAGES[int(k)], 0) + int(v)

    # a plain CSV preview, mostly attack rows so it is interesting to look at
    first = pd.read_csv(out / "test" / f"test_{seed0['test']:05d}.csv.gz")
    prev = pd.concat([first[first.stage > 0].head(2500), first[first.stage == 0].sample(2500, random_state=0)])
    prev.sort_values("ts").to_csv(out / "preview_5000_flows.csv", index=False)

    # PCAPs: packet-level versions of two short scenarios
    (out / "pcap").mkdir()
    pcaps = {}
    for name, seed, camp in [("phishing_to_exfil", 50001, ["phishing"]), ("bruteforce_to_exfil", 50002, ["bruteforce"])]:
        flows, meta = generate_scenario(seed, hours=2, campaigns=camp, n_workstations=8, start_hour=9, background_scan=False)
        raw = out / "pcap" / f"{name}.pcap"
        pk = flows_to_pcap(flows, raw)
        with open(raw, "rb") as f, gzip.open(str(raw) + ".gz", "wb", compresslevel=6) as g:
            shutil.copyfileobj(f, g)
        raw.unlink()
        label_rules_from_flows(flows).to_csv(out / "pcap" / f"{name}_labels.csv", index=False)
        (out / "pcap" / f"{name}.meta.json").write_text(json.dumps(meta, indent=1))
        pcaps[name] = (pk, len(flows))

    card = (ROOT / "docs" / "DATASET_CARD.md").read_text()
    table = "| split | files | flows | " + " | ".join(STAGES) + " |\n|---|---|---|" + "---|" * len(STAGES) + "\n"
    for split in n:
        s = stats[split]
        table += f"| {split} | {s['files']} | {s['flows']:,} | " + " | ".join(f"{s['stages'].get(x, 0):,}" for x in STAGES) + " |\n"
    table += "\nPCAPs: " + ", ".join(f"`{k}.pcap.gz` ({p:,} packets, {f:,} flows)" for k, (p, f) in pcaps.items())
    table += f"\n\nCampaigns: {campaigns.groupby('file').template.first().shape[0]} files with attacks, " + \
             ", ".join(f"{k} x{v}" for k, v in campaigns.drop_duplicates(['file', 'template']).template.value_counts().items())
    (out / "DATASET_CARD.md").write_text(card.replace("<!-- STATS -->", table).replace("<!-- HOURS -->", f"{a.hours:g}"))
    (out / "stats.json").write_text(json.dumps(stats, indent=1))
    print(table)
    if not a.no_zip:
        z = shutil.make_archive(str(out), "zip", out.parent, out.name)
        print(f"{z}: {Path(z).stat().st_size / 1e6:.1f} MB")
    print(f"done in {time.time() - t:.0f}s")


if __name__ == "__main__":
    main()
