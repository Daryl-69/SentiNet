# SentiNet: architecture

**Problem statement SIH26153:** AI-based network attack forecasting from network traffic data (NTRO).
**Idea:** do not classify single flows. Learn how the *state of the network* evolves over time, a world model
P(S<sub>t+1</sub> | S<sub>≤t</sub>). Then simulate the future to see whether the current trajectory leads to an
infiltration before the attacker finishes the kill chain.

## 1. Pipeline

```
 PCAP / PCAPNG ─┐                      ┌──────────── state S_t, every 60 s window ────────────┐
 CIC-IDS CSV ───┤  loaders  ─► flows ─►│ 47 flow- and packet-level features (vector x_t)      │
 CTU-13, UNSW ──┘  (canonical schema)  │ host graph: ≤48 most active hosts, 14 features each,  │
                                       │ weighted adjacency of who talked to whom              │
                                       └──────────────────────────┬───────────────────────────┘
                                                                  ▼
 edge-weighted GraphSAGE (2 layers, attention pooling) + MLP(x_t)  ─►  e_t
 causal Temporal Transformer over e_{t-29..t} (band mask + ALiBi)  ─►  c_t
 posterior q(z_t | c_t)  ─►  h_0 = f(c_t, z_t)
 latent dynamics:  h_{k+1} = GRU(z_k, h_k),   z_{k+1} ~ p(z | h_{k+1})          (k = 1..K, K = 10)
 decoders on (z_k, h_k):  next state N(μ, σ) over x  ·  ATT&CK stage  ·  infiltration hazard
 host head on (node embedding, c_t): P(host involved in infiltration within K)
                                                                  ▼
 64 Monte-Carlo rollouts per window ─► P(infiltration within 1..K windows), 10–90 % band,
 forecast stage per step, next-state forecast, riskiest hosts ─► explanations ─► signed receipts
```

## 2. Inputs: two levels of traffic features

The loaders turn every source into one canonical flow table. The PCAP reader is built in for classic pcap and uses
Scapy for pcapng; it decodes Ethernet, VLAN, Linux-cooked and raw-IP links, IPv4 and IPv6.

| Level | Features per window (47 total, 7 groups) |
|---|---|
| Flow (NetFlow/IPFIX-like) | flow, byte and packet counts; bidirectional byte ratio; SYN-only / RST / FIN / PSH / URG / failed-connection ratios; IAT mean, CV and max; duration; destination-port entropy; distinct ports; most ports per source; lateral-port (SMB/RDP/SSH/WinRM) and web/DNS ratios; fan-out; new edges and hosts never seen before; egress byte share; largest upload; new internet destinations; beacon periodicity over a 10-window lookback |
| Packet (PCAP) | TTL mean and variance; share of tiny TCP windows (scanner SYNs); fragment flags; payload-size mean and spread; retransmission ratio; a **sequential-port-scan signature** (ordered vs randomised port access); share of flows with packet-level detail |

Because packet-level features are included, slow scans that stay under flow-count thresholds still show up, for
example through a 1024-byte TCP window, scattered TTLs or ordered ports.

## 3. Training (supervised dynamics learning)

Ground-truth transitions come from each dataset's attack timeline. Labels are mapped to stages: Benign,
Reconnaissance, Initial Access, Lateral Movement, Command & Control, Exfiltration, Impact
(`sentinet/stages.py` holds the rules for CIC-IDS2017/2018, CTU-13 and UNSW-NB15). Every training sample is a chunk
of 30 past + 10 future windows. The loss combines:

- Gaussian NLL of the current state, and of every **imagined** future state along the K-step rollout;
- cross-entropy of the current stage and of the stage at every future step (class-weighted);
- BCE of P(infiltration by step k), where k is monotone by construction (1 − Π(1 − hazard));
- latent consistency: KL between the imagined prior at t+k and the posterior that sees window t+k (KL balancing
  0.8/0.2, as in DreamerV3);
- per-host BCE for "involved in infiltration within K".

Windows near attacks are over-sampled 3×. The alarm threshold is the F1-optimal point on held-out captures.

## 4. Outputs and explainability

For each window the model reports:

- P(infiltration within K) with a 10–90 % band across simulated futures;
- the forecast ATT&CK stage;
- a decoded next network state;
- a host ranking.

On request it also produces:

- **exact Shapley values** over the 7 feature groups plus the host graph (2⁸ = 256 coalitions, in log-odds computed
  directly from the hazard logits, so the values add up exactly and do not saturate near 100 %), then feature-level
  Shapley values inside the top groups;
- **temporal attention** over the last 30 windows, and graph attention over hosts;
- **flagged flows**, ranked by an Isolation-Forest anomaly score fitted on benign flows × host risk, with plain-language
  reasons such as "SYN never answered" or "internal remote-service port 445";
- **what-if**: remove the traffic a defensive action would have stopped (block a port, isolate a host, block an IP)
  and re-simulate.
- **ATT&CK / CAPEC knowledge base** (`sentinet/knowledge.py`): transparent rules map the evidence to techniques, for
  example T1046 with CAPEC-300 for a port scan, or T1021.002 with CAPEC-561 for SMB lateral movement, each with the
  trigger. For the forecast stage, it lists the techniques to watch for next and the ATT&CK mitigations (M10xx).
  An optional asset list (ip, CVSS from NVD) raises the risk of vulnerable hosts: 1 − (1 − risk)^(1 + CVSS/10).

Every forecast row is hashed into a Merkle tree (RFC 6962 prefixes). The root is signed with Ed25519, and
`python -m sentinet verify` re-checks it. This makes forecasts auditable after the fact.

## 5. Evaluation protocol (`python -m sentinet benchmark`)

- The same features and the same target for every model: "infiltration in the next K windows".
- Captures are split whole, never by random rows.
- The **world model** is compared against a **logistic regression** (current window only) and against the **world model
  with its history shuffled**. If shuffling does not hurt, the model has not learned dynamics.
- Metrics: precision, recall, F1 and false-positive rate at each model's validation threshold; ROC-AUC, PR-AUC and
  Brier score; the share of infiltration onsets warned within K windows, and the median lead time.
- **Unseen attack pattern:** a second model is trained without the low-and-slow APT template, then tested only on it.

**Measured** (held-out simulated scenarios, `results/benchmark.md`): F1 0.865 at a 3.1 % false-positive rate, against
0.483 for logistic regression at the same false-positive rate. 13 of 22 compromises were warned in advance, with a
median of 14 minutes, against 7 of 22 for the baseline. Shuffling history drops F1 to 0.347. On an attack type never
seen in training, F1 is 0.49 against 0.09 for the baseline at the same false-positive rate, with no advance warning.

## 6. Deployment

Everything runs on a CPU and offline: the model has about 170k parameters, and a 12-hour capture (720 windows × 64
futures) takes a few seconds. The interface is Streamlit, served on localhost. The same engine runs from the CLI for
batch reports (`report.html` with embedded plotly, CSVs, signed receipts). Passive only: it reads traffic copies
(SPAN/TAP or files) and never sends anything back.

## 7. Limits

The shipped weights are trained on the bundled simulator, not on a real network. Public datasets could not be
downloaded in the build environment. The simulator includes hard negatives (admin RDP/SSH, nightly backups to the
cloud, periodic telemetry, an inventory scan, internet scanners), failed attacks and recon-free phishing, so recon does
not automatically mean compromise. Real-network numbers need retraining on CIC-IDS2017/2018, CTU-13 or UNSW-NB15:
the loaders and the training command are included.
