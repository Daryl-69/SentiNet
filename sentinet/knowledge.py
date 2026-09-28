"""MITRE ATT&CK / CAPEC knowledge base and CVE exposure.

Turns a forecast into defender language:
  * observed techniques: which ATT&CK techniques (and related CAPEC attack
    patterns) the evidence in the current window points to;
  * expected next techniques: for the forecast stage, the techniques an
    attacker typically uses next and the ATT&CK mitigations that stop them;
  * CVE exposure: an optional asset list (ip, cvss[, cves]) raises the risk of
    hosts whose services have known vulnerabilities (NVD CVSS scores).

The rules are deliberately simple and transparent - every match says which
feature or port triggered it.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
import pandas as pd

from .stages import C2, EXFIL, IMPACT, INITIAL_ACCESS, LATERAL, RECON, STAGES

L1P = math.log1p


@dataclass
class Technique:
    id: str
    name: str
    stage: int
    capec: str
    mitigation: str


KB = {t.id: t for t in [
    Technique("T1595.001", "Active Scanning: Scanning IP Blocks", RECON, "CAPEC-292 Host Discovery",
              "M1056 Pre-compromise; M1031 Network Intrusion Prevention"),
    Technique("T1046", "Network Service Discovery", RECON, "CAPEC-300 Port Scanning",
              "M1030 Network Segmentation; M1031 Network Intrusion Prevention"),
    Technique("T1595.002", "Active Scanning: Vulnerability Scanning", RECON, "CAPEC-310 Scanning for Vulnerable Software",
              "M1016 Vulnerability Scanning (patch first); M1031 Network Intrusion Prevention"),
    Technique("T1595.003", "Active Scanning: Wordlist Scanning (web content enumeration)", RECON,
              "CAPEC-87 Forceful Browsing", "M1056 Pre-compromise; rate-limit and WAF rules on the exposed web server"),
    Technique("T1110", "Brute Force", INITIAL_ACCESS, "CAPEC-49 Password Brute Forcing",
              "M1032 Multi-factor Authentication; M1036 Account Use Policies (lockout); M1027 Password Policies"),
    Technique("T1190", "Exploit Public-Facing Application", INITIAL_ACCESS, "CAPEC-66 SQL Injection / CAPEC-88 OS Command Injection",
              "M1051 Update Software; M1050 Exploit Protection (WAF); M1048 Application Isolation"),
    Technique("T1133", "External Remote Services", INITIAL_ACCESS, "CAPEC-555 Remote Services with Stolen Credentials",
              "M1032 Multi-factor Authentication; M1035 Limit Access to Resource Over Network"),
    Technique("T1105", "Ingress Tool Transfer", C2, "-", "M1031 Network Intrusion Prevention; M1037 Filter Network Traffic"),
    Technique("T1021.002", "Remote Services: SMB/Windows Admin Shares", LATERAL,
              "CAPEC-561 Windows Admin Shares with Stolen Credentials",
              "M1030 Network Segmentation (block 445 between workstations); M1026 Privileged Account Management"),
    Technique("T1021.001", "Remote Services: Remote Desktop Protocol", LATERAL, "CAPEC-555 Remote Services with Stolen Credentials",
              "M1035 Limit Access to Resource Over Network; M1032 Multi-factor Authentication"),
    Technique("T1021.004", "Remote Services: SSH", LATERAL, "CAPEC-555 Remote Services with Stolen Credentials",
              "M1042 Disable or Remove Feature; M1032 Multi-factor Authentication"),
    Technique("T1021.006", "Remote Services: Windows Remote Management", LATERAL, "CAPEC-555 Remote Services with Stolen Credentials",
              "M1042 Disable WinRM where unused; M1030 Network Segmentation"),
    Technique("T1071.001", "Application Layer Protocol: Web Protocols (beaconing)", C2, "-",
              "M1031 Network Intrusion Prevention; M1037 Filter Network Traffic (egress allow-list)"),
    Technique("T1573", "Encrypted Channel", C2, "-", "M1020 SSL/TLS Inspection; M1031 Network Intrusion Prevention"),
    Technique("T1571", "Non-Standard Port", C2, "-", "M1030 Network Segmentation; M1037 Filter Network Traffic"),
    Technique("T1071.004", "Application Layer Protocol: DNS (tunnelling)", C2, "-",
              "M1037 Filter Network Traffic (force internal resolvers); M1031 Network Intrusion Prevention"),
    Technique("T1041", "Exfiltration Over C2 Channel", EXFIL, "-", "M1057 Data Loss Prevention; M1031 Network Intrusion Prevention"),
    Technique("T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol (DNS)", EXFIL, "-",
              "M1037 Filter Network Traffic; M1057 Data Loss Prevention"),
    Technique("T1567.002", "Exfiltration to Cloud Storage", EXFIL, "-", "M1021 Restrict Web-Based Content; M1057 Data Loss Prevention"),
    Technique("T1498", "Network Denial of Service", IMPACT, "CAPEC-125 Flooding / CAPEC-482 TCP Flood",
              "M1037 Filter Network Traffic (upstream scrubbing, SYN cookies)"),
]}

# techniques to watch for when the model forecasts a stage
EXPECTED = {
    RECON: ["T1046", "T1595.001", "T1595.003"],
    INITIAL_ACCESS: ["T1190", "T1110", "T1133"],
    LATERAL: ["T1021.002", "T1021.001", "T1021.006", "T1021.004"],
    C2: ["T1071.001", "T1573", "T1571", "T1105"],
    EXFIL: ["T1041", "T1567.002", "T1048.003"],
    IMPACT: ["T1498"],
}

_WEB = {80, 443, 8080, 8443}
_NONSTD = {4444, 8443, 1337, 31337, 6667, 9001}


def observed(feat: dict, flows: pd.DataFrame, internal, z: dict | None = None) -> list[dict]:
    """Techniques the current window's evidence points to.
    feat: raw feature values by name; z: the same features as z-scores against the
    training baseline (used where "high" only makes sense relative to normal)."""
    z = z or {}
    out = []

    def add(tid, why):
        t = KB[tid]
        out.append({"technique": tid, "name": t.name, "stage": STAGES[t.stage], "capec": t.capec,
                    "mitigation": t.mitigation, "evidence": why})

    f = flows
    if len(f) == 0:
        return out
    s_int = f["src_ip"].map(internal)
    d_int = f["dst_ip"].map(internal)
    dp = f["dst_port"].fillna(-1).astype(int)
    syn_only = (f["syn"] > 0) & (f["ack"] == 0)
    if feat.get("log_max_ports_per_src", 0) > L1P(25) or feat.get("seq_port_score", 0) > 0.3:
        seq = " in sequential order" if feat.get("seq_port_score", 0) > 0.3 else ""
        add("T1046", f"one source probed {int(round(math.expm1(feat['log_max_ports_per_src'])))} ports{seq}")
    if feat.get("log_max_fanout", 0) > L1P(15) and feat.get("failed_conn_ratio", 0) > 0.05:
        add("T1595.001", f"one source touched {int(round(math.expm1(feat['log_max_fanout'])))} hosts, "
                         f"{feat['failed_conn_ratio']:.0%} of connections failed")
    if feat.get("low_win_ratio", 0) > 0.05 and syn_only.sum() >= 5:
        add("T1595.002", f"{int(syn_only.sum())} SYNs with scanner-sized TCP windows")
    web_in = ~s_int & d_int & dp.isin(_WEB) & (f["bytes_fwd"] < 1500)
    if web_in.any():
        top_src = f.loc[web_in, "src_ip"].value_counts()
        if top_src.iloc[0] >= 15:
            add("T1595.003", f"{int(top_src.iloc[0])} short web requests from {top_src.index[0]} in one window")
    for port, tid in ((22, "T1110"), (3389, "T1110"), (21, "T1110")):
        m = (dp == port) & ~s_int & d_int
        if m.sum() >= 10:
            add(tid, f"{int(m.sum())} short sessions from the internet to port {port}")
            break
    inb = ~s_int & d_int & dp.isin(_WEB)
    big_in = inb & (f["bytes_fwd"] > 2000) & (f["bytes_fwd"] > 2 * f["bytes_bwd"])
    if big_in.sum() >= 3:
        add("T1190", f"{int(big_in.sum())} inbound web requests with unusually large bodies")
    lat = s_int & d_int
    for port, tid in ((445, "T1021.002"), (139, "T1021.002"), (3389, "T1021.001"), (5985, "T1021.006"),
                      (5986, "T1021.006"), (22, "T1021.004")):
        n = int((lat & (dp == port)).sum())
        srcs = f.loc[lat & (dp == port), "src_ip"].nunique()
        if n >= 3 and (feat.get("new_edge_ratio", 0) > 0.15 or srcs == 1 and n >= 8):
            add(tid, f"{n} internal connections to port {port}, {feat.get('new_edge_ratio', 0):.0%} of edges never seen before")
    if feat.get("beacon_score", 0) > 0.8 and z.get("log_periodic_pairs", 0) > 2.0:
        add("T1071.001", f"{int(round(math.expm1(feat['log_periodic_pairs'])))} periodic host pairs, "
                         f"{z['log_periodic_pairs']:.1f} sd above normal (beacon score {feat['beacon_score']:.2f})")
    ns = s_int & ~d_int & dp.isin(_NONSTD)
    if ns.any():
        add("T1571", f"outbound connection to port {int(dp[ns].iloc[0])}")
    dns_big = (dp == 53) & (f["bytes_fwd"] > 150 + 28)
    if dns_big.sum() >= 10:
        add("T1071.004", f"{int(dns_big.sum())} oversized DNS queries")
        add("T1048.003", "high-volume DNS queries carrying data")
    up = s_int & ~d_int & (f["bytes_fwd"] > 2e7)
    if up.any():
        add("T1041", f"{int(up.sum())} upload(s) of {f.loc[up, 'bytes_fwd'].sum() / 1e6:.0f} MB to the internet")
    dl = s_int & ~d_int & (f["bytes_bwd"] > 3e5) & (dp == 80)
    if dl.any() and feat.get("new_ext_dst_ratio", 0) > 0:
        add("T1105", "download over plain HTTP from a never-seen internet host")
    if feat.get("syn_only_ratio", 0) > 0.3 and feat.get("log_flows", 0) > L1P(500):
        add("T1498", f"{feat['syn_only_ratio']:.0%} unanswered SYNs across {int(math.expm1(feat['log_flows']))} flows")
    seen, uniq = set(), []
    for o in out:
        if o["technique"] not in seen:
            seen.add(o["technique"])
            uniq.append(o)
    return uniq


def expected(stage_probs_future: np.ndarray, top: int = 2) -> list[dict]:
    """Techniques to watch for, from the forecast stage distribution [K, n_stages]."""
    peak = stage_probs_future.max(0)
    order = [s for s in np.argsort(-peak[1:]) + 1 if peak[s] >= 0.1][:top]
    out = []
    for s in order:
        for tid in EXPECTED.get(int(s), []):
            t = KB[tid]
            out.append({"stage": STAGES[int(s)], "p_stage": float(peak[s]), "technique": tid, "name": t.name,
                        "capec": t.capec, "mitigation": t.mitigation})
    return out


# ------------------------------------------------------------------ CVE exposure
def load_assets(path) -> dict:
    """Asset list CSV: ip, cvss (0-10, highest CVSS of the host's exposed services), optional cves."""
    df = pd.read_csv(path)
    df.columns = [c.strip().lower() for c in df.columns]
    return {str(r["ip"]).strip(): {"cvss": float(r.get("cvss", 0) or 0), "cves": str(r.get("cves", "") or "")}
            for _, r in df.iterrows()}


def exposure_adjusted(risk: np.ndarray, ips: list, assets: dict | None) -> np.ndarray:
    """Raise a host's risk by its known-vulnerability exposure:
    adjusted = 1 - (1 - risk) ** (1 + cvss / 10). A host with CVSS 10 has its
    'safe' probability squared; a host without known CVEs is unchanged."""
    if not assets:
        return risk
    c = np.array([assets.get(ip, {}).get("cvss", 0.0) for ip in ips], dtype=float)
    return 1 - (1 - np.asarray(risk, float)) ** (1 + np.clip(c, 0, 10) / 10)
