# SentiNet-Sim v1: dataset card

A labelled, time-ordered network traffic dataset for **forecasting** multi-stage attacks, made for
SIH PS **SIH26153** (AI-based network attack forecasting). Every row is one bidirectional flow, and every
flow carries the ATT&CK stage it belongs to. Each file is one continuous <!-- HOURS --> h stretch of one
enterprise network, so a model can learn how attacks unfold *over time*. Most public IDS datasets are
shuffled rows, which only teach per-flow classification.

Built by `python scripts/make_dataset.py` (deterministic: the same command gives the same bytes).

## Contents

<!-- STATS -->

| folder / file | what |
|---|---|
| `train/`, `val/`, `test/` | `*.csv.gz` flows + `*.meta.json` (network start/end time, campaigns with the start/end of every stage) |
| `holdout_unseen_apt/` | only the **low-and-slow APT** campaign, which train/val/test never contain: tests generalisation to an unseen attack |
| `pcap/` | raw packet captures (`.pcap.gz`, Ethernet, snaplen 54) + `*_labels.csv` ground-truth rules (`start,end,ip,peer,port,stage`) |
| `campaigns.csv` | index of every attack: file, template, attacker IP, stage, start/end (unix + UTC), victim hosts |
| `preview_5000_flows.csv` | uncompressed sample (half attack, half benign) to open in Excel |

## The network

- **Internal network 10.10.0.0/16.** It has 18–40 workstations, a domain controller (10.10.0.10), and file, DB and mail servers. There is also an exposed web server (10.10.1.x) and an SSH gateway.
- **Benign traffic.** Office-hours web/DNS/mail/SMB/LDAP/Kerberos activity follows a daily rhythm, alongside software updates and cloud sync.
- **Hard negatives, all labelled Benign.** These look like attacks but are not:
  - an admin who RDPs/SSHes into servers every day;
  - a nightly internal inventory scan;
  - a nightly large cloud backup upload;
  - periodic telemetry beacons.
- **Internet scanners.** They probe the web server and never follow up. They are labelled Reconnaissance: recon is *not* a guarantee of compromise.

## Attack campaigns (stage order follows MITRE ATT&CK)

| template | stages played | notes |
|---|---|---|
| `web_exploit` | Recon → Initial Access (T1190 exploit, reverse shell) → C2 → Lateral Movement → Exfiltration | classic intrusion through the exposed web server |
| `phishing` | Initial Access → C2 → Lateral → Exfil | **no visible recon**: the model must catch it from C2 beaconing |
| `bruteforce` | Recon (scan + password guessing, T1110) → Initial Access (valid login) → C2 → Lateral → Exfil | |
| `failed_attack` | Recon only (scan, or brute force that never gets in) | a negative example; must *not* raise an infiltration forecast |
| `ddos` | Impact (T1498) | external flood, reported but not an infiltration |
| `slow_apt` | slow recon over hours → Initial Access → C2 (jittered beacons) → Lateral → small exfil | **hold-out only** |

Stage ids: `0 Benign, 1 Reconnaissance, 2 Initial Access, 3 Lateral Movement, 4 Command & Control,
5 Exfiltration, 6 Impact`. **Infiltration** = stages 2–5 (the target the forecaster predicts K minutes ahead).

## Columns (canonical SentiNet schema)

`ts` flow start (unix s), `duration`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`,
`pkts_fwd`, `pkts_bwd`, `bytes_fwd`, `bytes_bwd`, TCP flag counts `syn ack fin rst psh urg`,
inter-arrival `iat_mean iat_std iat_max`, packet-level `ttl_mean ttl_std win_mean frag payload_mean
payload_std retrans`, and ground truth `label` (e.g. `stage:4:phishing`) and `stage` (0–6).

## How to use it

```bash
# train SentiNet on it (about 10 min on a laptop CPU)
python -m sentinet train --data SentiNet-Sim-v1/train --val SentiNet-Sim-v1/val --out weights_sim
# benchmark vs logistic regression, including the unseen-APT hold-out
python -m sentinet benchmark --weights weights_sim --data SentiNet-Sim-v1/test --name test
python -m sentinet benchmark --weights weights_sim --data SentiNet-Sim-v1/holdout_unseen_apt --name unseen_apt --append
# forecast a PCAP directly
python -m sentinet forecast -i SentiNet-Sim-v1/pcap/phishing_to_exfil.pcap.gz --labels SentiNet-Sim-v1/pcap/phishing_to_exfil_labels.csv
```

In pandas: `pd.read_csv("train/train_10000.csv.gz")`. Group rows into 60 s windows by `ts` to build
sequences; the `.meta.json` gives the exact window range (`t0`, `t_end`).

## Limitations (be honest in the viva)

It is **synthetic**. Traffic volumes, timings and protocol mixes are modelled, not recorded, so a model
trained only on it should be validated on real captures (CIC-IDS2017/2018, CTU-13, UNSW-NB15). SentiNet
reads all of those directly. The generator is open, so anyone can check exactly what the labels mean
and regenerate or scale it (`--scale 3 --hours 12`).
