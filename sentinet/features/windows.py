"""Flows -> network state S_t per time window.

Every window of W seconds becomes
  * a state vector x_t (flow-level + packet-level features, named and grouped
    so explanations can point at "TCP flags" or "ports" or a single feature),
  * a host graph: up to N most active hosts as nodes with per-host features,
    and a weighted adjacency of who talked to whom in that window,
  * labels when the input is labelled: the window's attack stage and, per
    host, whether it was involved in infiltration activity.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from ..stages import INFILTRATION, N_STAGES

LATERAL_PORTS = np.array([22, 23, 135, 139, 445, 3389, 5900, 5985, 5986])
WEB_PORTS = np.array([80, 443, 8080, 8443])

NET_FEATURES = [
    ("volume", "log_flows"), ("volume", "log_bytes_fwd"), ("volume", "log_bytes_bwd"),
    ("volume", "log_pkts"), ("volume", "bidir_byte_ratio"), ("volume", "top_talker_share"),
    ("tcp_flags", "syn_only_ratio"), ("tcp_flags", "rst_ratio"), ("tcp_flags", "fin_ratio"),
    ("tcp_flags", "psh_ratio"), ("tcp_flags", "urg_ratio"), ("tcp_flags", "failed_conn_ratio"),
    ("timing", "log_iat_mean_ms"), ("timing", "iat_cv"), ("timing", "log_iat_max_ms"),
    ("timing", "log_dur_mean"), ("timing", "short_flow_ratio"), ("timing", "beacon_score"),
    ("timing", "log_periodic_pairs"),
    ("ports", "dst_port_entropy"), ("ports", "log_distinct_dst_ports"), ("ports", "log_max_ports_per_src"),
    ("ports", "seq_port_score"), ("ports", "lateral_port_ratio"), ("ports", "web_port_ratio"),
    ("ports", "dns_ratio"), ("ports", "high_port_ratio"),
    ("hosts", "log_n_src"), ("hosts", "log_n_dst"), ("hosts", "log_max_fanout"),
    ("hosts", "internal_internal_ratio"), ("hosts", "new_edge_ratio"), ("hosts", "new_host_ratio"),
    ("hosts", "dst_ip_entropy"), ("hosts", "inbound_ext_ratio"),
    ("egress", "out_ext_byte_ratio"), ("egress", "log_max_out_bytes"), ("egress", "log_n_ext_dst"),
    ("egress", "new_ext_dst_ratio"),
    ("packet", "ttl_mean"), ("packet", "ttl_std"), ("packet", "low_win_ratio"), ("packet", "frag_ratio"),
    ("packet", "log_payload_mean"), ("packet", "payload_cv"), ("packet", "retrans_ratio"),
    ("packet", "pkt_level_avail"),
]
FEATURE_NAMES = [n for _, n in NET_FEATURES]
FEATURE_GROUPS = {}
for _g, _n in NET_FEATURES:
    FEATURE_GROUPS.setdefault(_g, []).append(FEATURE_NAMES.index(_n))
GROUP_NAMES = list(FEATURE_GROUPS)

FEATURE_HELP = {
    "log_flows": "number of flows", "log_bytes_fwd": "bytes sent by initiators", "log_bytes_bwd": "bytes returned",
    "log_pkts": "packets", "bidir_byte_ratio": "share of bytes flowing back (bidirectional ratio)",
    "top_talker_share": "share of bytes from the busiest host",
    "syn_only_ratio": "flows that sent SYN and never got an ACK", "rst_ratio": "flows with RST",
    "fin_ratio": "flows closed with FIN", "psh_ratio": "flows with PSH", "urg_ratio": "flows with URG",
    "failed_conn_ratio": "failed / rejected connections",
    "log_iat_mean_ms": "mean packet inter-arrival time", "iat_cv": "IAT variability",
    "log_iat_max_ms": "max packet inter-arrival time", "log_dur_mean": "mean flow duration",
    "short_flow_ratio": "flows shorter than 100 ms", "beacon_score": "strongest periodic host pair (beaconing)",
    "log_periodic_pairs": "number of periodic host pairs",
    "dst_port_entropy": "destination-port entropy", "log_distinct_dst_ports": "distinct destination ports",
    "log_max_ports_per_src": "most ports touched by one source", "seq_port_score": "sequential port-scan signature",
    "lateral_port_ratio": "internal flows on SMB/RDP/SSH/WinRM ports", "web_port_ratio": "web-port flows",
    "dns_ratio": "DNS flows", "high_port_ratio": "flows to ports >= 1024",
    "log_n_src": "distinct sources", "log_n_dst": "distinct destinations",
    "log_max_fanout": "most hosts contacted by one source", "internal_internal_ratio": "internal-to-internal flows",
    "new_edge_ratio": "never-seen-before host/port connections", "new_host_ratio": "never-seen-before hosts",
    "dst_ip_entropy": "destination-IP entropy", "inbound_ext_ratio": "flows arriving from the internet",
    "out_ext_byte_ratio": "share of bytes leaving to the internet", "log_max_out_bytes": "largest single upload",
    "log_n_ext_dst": "distinct internet destinations", "new_ext_dst_ratio": "uploads to never-seen internet hosts",
    "ttl_mean": "mean TTL", "ttl_std": "TTL variance across flows", "low_win_ratio": "tiny TCP windows (scanner SYNs)",
    "frag_ratio": "fragmented packets", "log_payload_mean": "mean payload size", "payload_cv": "payload-size spread",
    "retrans_ratio": "TCP retransmissions", "pkt_level_avail": "packet-level detail available",
}

NODE_FEATURES = ["log_out_flows", "log_in_flows", "log_out_bytes", "log_in_bytes", "log_out_ports",
                 "log_out_peers", "log_in_peers", "syn_only_out", "failed_out", "lateral_out",
                 "log_ext_out_bytes", "is_internal", "new_peer_out", "ext_in_ratio"]

_PRIVATE = [ipaddress.ip_network(n) for n in
            ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10")]


def make_internal_fn(prefixes=None):
    nets = [ipaddress.ip_network(p) for p in prefixes] if prefixes else _PRIVATE

    def is_internal(ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a.version == n.version and a in n for n in nets)
    return is_internal


@dataclass
class WindowData:
    t0: float
    window: float
    times: np.ndarray                 # [T] window start (unix s)
    X: np.ndarray                     # [T, F] state vectors
    node_X: np.ndarray                # [T, N, Fn]
    node_mask: np.ndarray             # [T, N] bool
    adj: np.ndarray                   # [T, N, N]
    node_ips: list                    # T lists of ips (len <= N)
    stage: np.ndarray                 # [T] int, -1 when unlabelled
    node_infil: np.ndarray            # [T, N] host involved in infiltration activity in this window
    labelled: bool
    flow_window: np.ndarray           # [n_flows] window index of each flow
    n_flows: np.ndarray               # [T]
    meta: dict = field(default_factory=dict)

    def __len__(self):
        return len(self.times)


def _entropy(codes: np.ndarray) -> float:
    if len(codes) == 0:
        return 0.0
    _, c = np.unique(codes, return_counts=True)
    p = c / c.sum()
    return float(-(p * np.log2(p)).sum())


def _group_nunique(keys: np.ndarray, vals: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """For each distinct key, number of distinct vals."""
    if len(keys) == 0:
        return np.array([], dtype=keys.dtype), np.array([], dtype=int)
    pairs = np.unique(np.stack([keys, vals], 1), axis=0)
    k, c = np.unique(pairs[:, 0], return_counts=True)
    return k, c


def featurize(flows: pd.DataFrame, window: float = 60.0, max_nodes: int = 48, internal_prefixes=None,
              beacon_lookback: int = 10, t0: float | None = None, t_end: float | None = None,
              labelled: bool | None = None) -> WindowData:
    """Turn a canonical flow table into per-window network states."""
    df = flows.sort_values("ts", kind="mergesort").reset_index(drop=True)
    n_total = len(df)
    if n_total == 0:
        raise ValueError("no flows to featurize")
    t0 = float(np.floor(df["ts"].iloc[0] / window) * window) if t0 is None else float(t0)
    t_last = float(df["ts"].iloc[-1]) if t_end is None else float(t_end) - 1e-6
    T = int(np.floor((t_last - t0) / window)) + 1

    ts = df["ts"].to_numpy(float)
    win_idx = np.clip(((ts - t0) // window).astype(int), 0, T - 1)
    bounds = np.searchsorted(win_idx, np.arange(T + 1))

    ip_codes, ip_uni = pd.factorize(pd.concat([df["src_ip"], df["dst_ip"]], ignore_index=True))
    src = ip_codes[:n_total].astype(np.int64)
    dst = ip_codes[n_total:].astype(np.int64)
    is_int_fn = make_internal_fn(internal_prefixes)
    ip_internal = np.array([is_int_fn(str(ip)) for ip in ip_uni], dtype=bool)
    src_int, dst_int = ip_internal[src], ip_internal[dst]

    g = lambda c: df[c].to_numpy(float)  # noqa: E731
    dport = np.nan_to_num(g("dst_port"), nan=-1).astype(np.int64)
    pf, pb = g("pkts_fwd"), g("pkts_bwd")
    bf, bb = g("bytes_fwd"), g("bytes_bwd")
    syn, ack, fin, rst, psh, urg = (g(c) for c in ("syn", "ack", "fin", "rst", "psh", "urg"))
    dur = g("duration")
    iat_mean, iat_std, iat_max = g("iat_mean"), g("iat_std"), g("iat_max")
    ttl, ttl_s, winsz, frag = g("ttl_mean"), g("ttl_std"), g("win_mean"), g("frag")
    pay_m, pay_s, retr = g("payload_mean"), g("payload_std"), g("retrans")
    is_tcp = (df["proto"].to_numpy(str) == "tcp")
    stage = df["stage"].to_numpy(int)
    if labelled is None:
        labelled = bool((df["label"].astype(str).str.lower() != "benign").any() or (stage > 0).any())

    syn_only = (syn > 0) & (ack == 0)
    failed = is_tcp & (syn_only | ((rst > 0) & (pb <= 1)))
    lateral = np.isin(dport, LATERAL_PORTS) & src_int & dst_int
    web = np.isin(dport, WEB_PORTS)
    out_ext = src_int & ~dst_int
    in_ext = ~src_int & dst_int
    infil_flow = np.isin(stage, INFILTRATION)

    F = len(FEATURE_NAMES)
    X = np.zeros((T, F), dtype=np.float32)
    N = max_nodes
    node_X = np.zeros((T, N, len(NODE_FEATURES)), dtype=np.float32)
    node_mask = np.zeros((T, N), dtype=bool)
    adj = np.zeros((T, N, N), dtype=np.float32)
    node_infil = np.zeros((T, N), dtype=bool)
    node_ips: list[list[str]] = []
    wstage = np.full(T, -1 if not labelled else 0, dtype=int)
    n_flows = np.diff(bounds)

    seen_edges: set = set()
    seen_hosts: set = set()
    seen_ext: set = set()
    seen_peer: set = set()
    M = len(ip_uni) + 1
    fi = {n: i for i, n in enumerate(FEATURE_NAMES)}
    slot_arr = np.full(M, -1, dtype=np.int64)

    for w in range(T):
        a, b = bounds[w], bounds[w + 1]
        n = b - a
        if n == 0:
            node_ips.append([])
            continue
        s = slice(a, b)
        x = X[w]
        S, D = src[s], dst[s]
        x[fi["log_flows"]] = np.log1p(n)
        sbf, sbb = bf[s].sum(), bb[s].sum()
        x[fi["log_bytes_fwd"]] = np.log1p(sbf)
        x[fi["log_bytes_bwd"]] = np.log1p(sbb)
        x[fi["log_pkts"]] = np.log1p(pf[s].sum() + pb[s].sum())
        x[fi["bidir_byte_ratio"]] = sbb / (sbf + sbb + 1.0)
        tot_b = bf[s] + bb[s]
        us, inv = np.unique(S, return_inverse=True)
        per_src_bytes = np.bincount(inv, weights=tot_b)
        x[fi["top_talker_share"]] = per_src_bytes.max() / (tot_b.sum() + 1.0)

        x[fi["syn_only_ratio"]] = syn_only[s].mean()
        x[fi["rst_ratio"]] = (rst[s] > 0).mean()
        x[fi["fin_ratio"]] = (fin[s] > 0).mean()
        x[fi["psh_ratio"]] = (psh[s] > 0).mean()
        x[fi["urg_ratio"]] = (urg[s] > 0).mean()
        x[fi["failed_conn_ratio"]] = failed[s].mean()

        multi = (pf[s] + pb[s]) > 1
        imv, isv, ixv = iat_mean[s][multi], iat_std[s][multi], iat_max[s][multi]
        okv = ~np.isnan(imv)
        if okv.any():
            x[fi["log_iat_mean_ms"]] = np.log1p(1000 * imv[okv].mean())
            x[fi["iat_cv"]] = float(np.clip(np.nan_to_num(isv[okv]) / (imv[okv] + 1e-3), 0, 5).mean())
            x[fi["log_iat_max_ms"]] = np.log1p(1000 * np.nan_to_num(ixv[okv]).mean())
        x[fi["log_dur_mean"]] = np.log1p(dur[s].mean())
        x[fi["short_flow_ratio"]] = (dur[s] < 0.1).mean()

        # beaconing over a lookback of several windows
        lb = bounds[max(0, w - beacon_lookback + 1)]
        key = src[lb:b] * M + dst[lb:b]
        tt = ts[lb:b]
        order = np.lexsort((tt, key))
        k_s, t_s = key[order], tt[order]
        same = k_s[1:] == k_s[:-1]
        if same.any():
            d = np.diff(t_s)[same]
            grp = k_s[1:][same]
            ug, gi = np.unique(grp, return_inverse=True)
            cnt = np.bincount(gi)
            mean = np.bincount(gi, weights=d) / cnt
            var = np.bincount(gi, weights=d * d) / cnt - mean ** 2
            cv = np.sqrt(np.maximum(var, 0)) / (mean + 1e-6)
            ok = (cnt >= 3) & (mean > 2.0)
            if ok.any():
                score = (1 - np.minimum(cv[ok], 1)) * np.minimum((cnt[ok] + 1) / 8, 1)
                x[fi["beacon_score"]] = score.max()
                x[fi["log_periodic_pairs"]] = np.log1p(((cv[ok] < 0.35)).sum())

        P = dport[s]
        x[fi["dst_port_entropy"]] = _entropy(P)
        x[fi["log_distinct_dst_ports"]] = np.log1p(len(np.unique(P)))
        k, c = _group_nunique(S, P)
        x[fi["log_max_ports_per_src"]] = np.log1p(c.max()) if len(c) else 0
        # sequential port-scan signature
        seq = 0.0
        for src_code in k[c >= 8]:
            m = S == src_code
            pp = P[m]
            if len(np.unique(pp)) < 8:
                continue
            dd = np.abs(np.diff(pp))
            seq = max(seq, float((dd == 1).mean()))
        x[fi["seq_port_score"]] = seq
        x[fi["lateral_port_ratio"]] = lateral[s].mean()
        x[fi["web_port_ratio"]] = web[s].mean()
        x[fi["dns_ratio"]] = (P == 53).mean()
        x[fi["high_port_ratio"]] = (P >= 1024).mean()

        x[fi["log_n_src"]] = np.log1p(len(us))
        ud = np.unique(D)
        x[fi["log_n_dst"]] = np.log1p(len(ud))
        k2, c2 = _group_nunique(S, D)
        x[fi["log_max_fanout"]] = np.log1p(c2.max()) if len(c2) else 0
        x[fi["internal_internal_ratio"]] = (src_int[s] & dst_int[s]).mean()
        edges = (S * M + D) * 70000 + np.clip(P, 0, 69999)
        new_e = np.array([e not in seen_edges for e in edges.tolist()])
        x[fi["new_edge_ratio"]] = new_e.mean()
        seen_edges.update(edges.tolist())
        hosts = np.unique(np.concatenate([S, D]))
        new_h = [h not in seen_hosts for h in hosts.tolist()]
        x[fi["new_host_ratio"]] = float(np.mean(new_h))
        seen_hosts.update(hosts.tolist())
        x[fi["dst_ip_entropy"]] = _entropy(D)
        x[fi["inbound_ext_ratio"]] = in_ext[s].mean()

        oe = out_ext[s]
        x[fi["out_ext_byte_ratio"]] = bf[s][oe].sum() / (tot_b.sum() + 1.0)
        x[fi["log_max_out_bytes"]] = np.log1p(bf[s][oe].max()) if oe.any() else 0.0
        ext_d = D[oe]
        x[fi["log_n_ext_dst"]] = np.log1p(len(np.unique(ext_d)))
        if oe.any():
            x[fi["new_ext_dst_ratio"]] = float(np.mean([d_ not in seen_ext for d_ in ext_d.tolist()]))
            seen_ext.update(ext_d.tolist())

        tv = ttl[s]
        have = ~np.isnan(tv)
        x[fi["pkt_level_avail"]] = have.mean()
        if have.any():
            x[fi["ttl_mean"]] = tv[have].mean() / 64.0
            ts_within = np.nan_to_num(ttl_s[s][have]).mean()
            x[fi["ttl_std"]] = np.log1p(tv[have].std() + ts_within)
            wv = winsz[s][have & is_tcp[s]]
            wv = wv[~np.isnan(wv)]
            x[fi["low_win_ratio"]] = (wv <= 1024).mean() if len(wv) else 0.0
            x[fi["frag_ratio"]] = (np.nan_to_num(frag[s][have]) > 0).mean()
            pm = np.nan_to_num(pay_m[s][have])
            x[fi["log_payload_mean"]] = np.log1p(pm.mean())
            x[fi["payload_cv"]] = float(np.clip((np.nan_to_num(pay_s[s][have]) / (pm + 1.0)).mean(), 0, 5))
            x[fi["retrans_ratio"]] = np.nan_to_num(retr[s][have]).sum() / (pf[s][have].sum() + pb[s][have].sum() + 1.0)

        # ---- host graph
        act = np.bincount(np.concatenate([S, D]), minlength=M)
        cand = np.nonzero(act)[0]
        cand = cand[np.argsort(-act[cand], kind="stable")][:N]
        nn = len(cand)
        slot_arr[cand] = np.arange(nn)
        node_ips.append([str(ip_uni[h]) for h in cand])
        node_mask[w, :nn] = True
        nx = node_X[w]
        si, di = slot_arr[S], slot_arr[D]
        o, i_ = si >= 0, di >= 0
        bs, bd = bf[s], bb[s]
        cnt_out = np.bincount(si[o], minlength=N).astype(float)
        cnt_in = np.bincount(di[i_], minlength=N).astype(float)
        nx[:, 0] = np.log1p(cnt_out)
        nx[:, 1] = np.log1p(cnt_in)
        nx[:, 2] = np.log1p(np.bincount(si[o], weights=bs[o], minlength=N) + np.bincount(di[i_], weights=bd[i_], minlength=N))
        nx[:, 3] = np.log1p(np.bincount(si[o], weights=bd[o], minlength=N) + np.bincount(di[i_], weights=bs[i_], minlength=N))
        kk, cc = _group_nunique(si[o], P[o])
        nx[kk, 4] = np.log1p(cc)
        kk, cc = _group_nunique(si[o], D[o])
        nx[kk, 5] = np.log1p(cc)
        kk, cc = _group_nunique(di[i_], S[i_])
        nx[kk, 6] = np.log1p(cc)
        so_ = np.maximum(cnt_out, 1)
        nx[:, 7] = np.bincount(si[o], weights=syn_only[s][o], minlength=N) / so_
        nx[:, 8] = np.bincount(si[o], weights=failed[s][o], minlength=N) / so_
        nx[:, 9] = np.bincount(si[o], weights=lateral[s][o], minlength=N) / so_
        nx[:, 10] = np.log1p(np.bincount(si[o], weights=np.where(oe, bs, 0.0)[o], minlength=N))
        nx[:nn, 11] = ip_internal[cand]
        pk = (S * M + D).tolist()
        newp = np.array([p_ not in seen_peer for p_ in pk], dtype=float)
        seen_peer.update(pk)
        nx[:, 12] = np.bincount(si[o], weights=newp[o], minlength=N) / so_
        nx[:, 13] = np.bincount(di[i_], weights=in_ext[s][i_], minlength=N) / np.maximum(cnt_in, 1)
        if (o & i_).any():
            np.add.at(adj[w], (si[o & i_], di[o & i_]), 1.0)
            adj[w] = np.log1p(adj[w])
        slot = {h: j for j, h in enumerate(cand.tolist())}
        slot_arr[cand] = -1

        if labelled:
            st = stage[s]
            mal = st[st > 0]
            if len(mal):
                cnt = np.bincount(mal, minlength=N_STAGES)
                wstage[w] = int(np.flatnonzero(cnt == cnt.max()).max())
            inf = infil_flow[s]
            if inf.any():
                inv_hosts = set(S[inf].tolist()) | set(D[inf].tolist())
                for h in inv_hosts:
                    if h in slot:
                        node_infil[w, slot[h]] = True

    return WindowData(t0=t0, window=window, times=t0 + window * np.arange(T), X=X, node_X=node_X,
                      node_mask=node_mask, adj=adj, node_ips=node_ips, stage=wstage, node_infil=node_infil,
                      labelled=labelled, flow_window=win_idx, n_flows=n_flows)
