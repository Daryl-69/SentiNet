"""Unit and integration tests.  Run:  python -m pytest -q"""
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sentinet.features.windows import FEATURE_NAMES, NODE_FEATURES, featurize  # noqa: E402
from sentinet.io.loaders import detect_format, load  # noqa: E402
from sentinet.ledger import make_receipts, verify_receipts  # noqa: E402
from sentinet.stages import C2, IMPACT, INITIAL_ACCESS, LATERAL, RECON, BENIGN, label_to_stage  # noqa: E402
from sentinet.synth.generator import generate_scenario  # noqa: E402
from sentinet.synth.pcapgen import flows_to_pcap, label_rules_from_flows  # noqa: E402


@pytest.fixture(scope="module")
def scenario():
    return generate_scenario(4242, hours=2, campaigns=["web_exploit"], n_workstations=6, start_hour=10)


# ------------------------------------------------------------------ labels
@pytest.mark.parametrize("label,stage", [
    ("BENIGN", BENIGN), ("PortScan", RECON), ("FTP-Patator", INITIAL_ACCESS), ("SSH-Bruteforce", INITIAL_ACCESS),
    ("Infilteration", LATERAL), ("Infiltration", LATERAL), ("Bot", C2), ("DDoS attacks-LOIC-HTTP", IMPACT),
    ("DoS Hulk", IMPACT), ("flow=Background-UDP-Established", BENIGN), ("flow=From-Normal-V42-Stribrny", BENIGN),
    ("flow=From-Botnet-V42-TCP-CC6-Plain-HTTP-Encrypted-Data", C2), ("Reconnaissance", RECON), ("Exploits", INITIAL_ACCESS),
    ("Worms", LATERAL), ("Backdoor", C2), ("stage:5:x:y", 5), ("", BENIGN),
])
def test_label_mapping(label, stage):
    assert label_to_stage(label) == stage


# ------------------------------------------------------------------ simulator + features
def test_scenario_has_all_stages(scenario):
    flows, meta = scenario
    assert {1, 2, 3, 4, 5} <= set(flows["stage"].unique())
    phases = {p["stage"] for p in meta["campaigns"][0]["phases"]}
    assert phases == {1, 2, 3, 4, 5}


def test_featurize_shapes(scenario):
    flows, _ = scenario
    wd = featurize(flows, labelled=True)
    assert wd.X.shape == (len(wd), len(FEATURE_NAMES))
    assert wd.node_X.shape[2] == len(NODE_FEATURES)
    assert np.isfinite(wd.X).all() and np.isfinite(wd.node_X).all()
    assert (wd.stage >= 0).all() and (wd.stage > 0).any()
    assert wd.node_mask.any(1).all()


# ------------------------------------------------------------------ loaders
def test_sentinet_csv_roundtrip(tmp_path, scenario):
    flows, _ = scenario
    p = tmp_path / "f.csv"
    flows.to_csv(p, index=False)
    assert detect_format(p) == "sentinet"
    back = load(p)
    assert len(back) == len(flows) and (back["stage"].values == flows["stage"].values).all()


def test_cicflowmeter_loader(tmp_path, scenario):
    flows, _ = scenario
    f = flows.head(300)
    lab = np.where(f["stage"] == 1, "PortScan", np.where(f["stage"] > 1, "Infiltration", "BENIGN"))
    ts = pd.to_datetime(f["ts"], unit="s").dt.strftime("%d/%m/%Y %H:%M:%S")
    cic = pd.DataFrame({
        "Flow ID": "x", " Source IP": f["src_ip"], " Source Port": f["src_port"], " Destination IP": f["dst_ip"],
        " Destination Port": f["dst_port"], " Protocol": 6, " Timestamp": ts, " Flow Duration": f["duration"] * 1e6,
        " Total Fwd Packets": f["pkts_fwd"], " Total Backward Packets": f["pkts_bwd"],
        "Total Length of Fwd Packets": f["bytes_fwd"], " Total Length of Bwd Packets": f["bytes_bwd"],
        " Flow IAT Mean": f["iat_mean"] * 1e6, " Flow IAT Std": f["iat_std"] * 1e6, " Flow IAT Max": f["iat_max"] * 1e6,
        "FIN Flag Count": f["fin"], " SYN Flag Count": f["syn"], " RST Flag Count": f["rst"], " PSH Flag Count": f["psh"],
        " ACK Flag Count": f["ack"], " URG Flag Count": f["urg"], "Init_Win_bytes_forward": f["win_mean"],
        " Packet Length Mean": f["payload_mean"], " Label": lab})
    p = tmp_path / "Tuesday-WorkingHours.pcap_ISCX.csv"
    cic.to_csv(p, index=False)
    assert detect_format(p) == "cicflowmeter"
    df = load(p)
    assert len(df) == 300
    assert abs(df["duration"].sum() - f["duration"].sum()) < 1e-3 * max(1, f["duration"].sum())
    assert set(df["stage"].unique()) <= {BENIGN, RECON, LATERAL}


def test_ctu13_loader(tmp_path):
    p = tmp_path / "capture.binetflow"
    p.write_text(
        "StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label\n"
        "2011/08/10 09:46:53.047277,3.124,tcp,147.32.84.165,1027,   ->,60.190.222.139,80,S_RA,0,0,4,244,124,flow=From-Botnet-V42-TCP-Attempt\n"
        "2011/08/10 09:46:59.607825,0.000,udp,147.32.84.2,0x0035,  <->,147.32.84.229,1025,CON,0,0,2,276,79,flow=Background-UDP-Established\n")
    assert detect_format(p) == "ctu13"
    df = load(p)
    assert len(df) == 2
    tcp = df[df["proto"] == "tcp"].iloc[0]
    assert tcp["syn"] == 1 and tcp["rst"] == 1 and tcp["bytes_bwd"] == 120
    assert df["dst_port"].tolist() == [80, 1025] and df["src_port"].tolist() == [1027, 53]
    assert sorted(df["stage"].tolist()) == [BENIGN, C2]


def test_unsw_loader(tmp_path):
    from sentinet.io.loaders import UNSW_COLS
    row = {c: 0 for c in UNSW_COLS}
    row.update(srcip="59.166.0.0", sport=1390, dstip="149.171.126.6", dsport=53, proto="udp", state="CON", dur=0.001,
               sbytes=132, dbytes=164, sttl=31, spkts=2, dpkts=2, swin=0, stime=1421927414, attack_cat="", label=0)
    row2 = dict(row, dsport=80, proto="tcp", state="FIN", attack_cat="Exploits", label=1, stime=1421927420)
    p = tmp_path / "UNSW-NB15_1.csv"
    pd.DataFrame([row, row2])[UNSW_COLS].to_csv(p, index=False, header=False)
    assert detect_format(p) == "unsw"
    df = load(p)
    assert df["stage"].tolist() == [BENIGN, INITIAL_ACCESS]
    assert df["ttl_mean"].iloc[0] == 31


# ------------------------------------------------------------------ pcap
def test_pcap_roundtrip(tmp_path, scenario):
    flows, _ = scenario
    pcap = tmp_path / "s.pcap"
    n = flows_to_pcap(flows, pcap)
    assert n > len(flows)
    rules = tmp_path / "rules.csv"
    label_rules_from_flows(flows).to_csv(rules, index=False)
    assert detect_format(pcap) == "pcap"
    got = load(pcap, labels=str(rules))
    assert abs(len(got) - len(flows)) <= 0.02 * len(flows)
    w1 = featurize(flows, labelled=True)
    w2 = featurize(got, labelled=True, t0=w1.t0)
    T = min(len(w1), len(w2))
    assert (w1.stage[:T] == w2.stage[:T]).mean() > 0.95
    assert got["ttl_mean"].notna().all()


# ------------------------------------------------------------------ ledger
def test_receipts_detect_tampering(tmp_path):
    recs = [{"window": i, "p": 0.1 * i} for i in range(7)]
    doc = make_receipts(recs, key_dir=tmp_path)
    ok, _ = verify_receipts(doc)
    assert ok
    bad = json.loads(json.dumps(doc))
    bad["records"][3]["p"] = 0.0
    ok, msg = verify_receipts(bad)
    assert not ok and "Merkle" in msg


# ------------------------------------------------------------------ model (needs trained weights)
weights = ROOT / "weights" / "world_model.pt"


@pytest.mark.skipif(not weights.exists(), reason="no trained weights")
def test_forecast_and_explain(scenario):
    from sentinet.engine import Forecaster, apply_action
    fc = Forecaster.load()
    flows, _ = scenario
    res = fc.run(flows, samples=16)
    tb = res.table
    assert len(tb) == len(res.wd)
    assert tb["p_infiltration"].between(0, 1).all()
    assert (tb["p_low"] <= tb["p_high"] + 1e-6).all()
    # the probability of infiltration by step k never decreases with k
    assert (np.diff(res.r["p_by_k"], axis=1) >= -1e-6).all()
    t = int(tb["p_infiltration"].idxmax())
    ex = res.explain(t)
    # Shapley efficiency: contributions add up to f(all present) - f(all at baseline)
    total = sum(g["shap"] for g in ex["groups"])
    assert abs(total - (ex["logit_full"] - ex["logit_baseline"])) < 1e-3
    assert len(res.flagged_flows(t)) > 0
    cut = apply_action(flows, {"type": "block_port", "port": 445}, flows["ts"].min())
    assert (cut["dst_port"] != 445).all()


# ------------------------------------------------------------------ knowledge base
def test_knowledge_rules(scenario):
    from sentinet.features.windows import make_internal_fn
    from sentinet.knowledge import exposure_adjusted, expected, observed
    flows, _ = scenario
    wd = featurize(flows, labelled=True)
    inside = make_internal_fn()
    found = set()
    for t in range(len(wd)):
        raw = dict(zip(FEATURE_NAMES, wd.X[t].tolist()))
        f = flows[wd.flow_window == t]
        found |= {o["technique"] for o in observed(raw, f, inside, {"log_periodic_pairs": 3.0})}
    # the web_exploit campaign scans ports, moves over SMB/RDP/WinRM and exfiltrates
    assert "T1046" in found
    assert found & {"T1021.002", "T1021.001", "T1021.006"}
    sf = np.zeros((10, 7)); sf[:, 3] = 0.8; sf[:, 0] = 0.2
    exp = expected(sf)
    assert exp and exp[0]["stage"] == "Lateral Movement" and exp[0]["mitigation"].startswith("M")
    r = exposure_adjusted(np.array([0.2, 0.2]), ["a", "b"], {"a": {"cvss": 10.0}})
    assert r[0] > r[1] == pytest.approx(0.2)
