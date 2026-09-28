"""The canonical flow table every loader produces.

One row per bidirectional flow. `src` is the side that opened the flow.
Packet-level columns are NaN when the source (e.g. a NetFlow-only dataset)
does not carry them; the featuriser records how much packet-level detail
each window actually had.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

FLOW_COLUMNS = [
    "ts",            # flow start, unix seconds (float)
    "duration",      # seconds
    "src_ip", "dst_ip",
    "src_port", "dst_port",
    "proto",         # "tcp" | "udp" | "icmp" | other
    "pkts_fwd", "pkts_bwd",
    "bytes_fwd", "bytes_bwd",
    # TCP flag counts over the whole flow (both directions)
    "syn", "ack", "fin", "rst", "psh", "urg",
    # inter-arrival time statistics over all packets of the flow, seconds
    "iat_mean", "iat_std", "iat_max",
    # packet-level (PCAP-derived) attributes
    "ttl_mean", "ttl_std",       # IP TTL / hop limit of the initiator's packets
    "win_mean",                  # TCP window size (initiator)
    "frag",                      # packets with MF set or a fragment offset
    "payload_mean", "payload_std",
    "retrans",                   # retransmitted TCP segments
    # ground truth (optional)
    "label", "stage",
]

NUMERIC = [c for c in FLOW_COLUMNS if c not in ("src_ip", "dst_ip", "proto", "label")]
PACKET_LEVEL = ["ttl_mean", "ttl_std", "win_mean", "frag", "payload_mean", "payload_std", "retrans"]

PROTO_NUM = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp"}


def normalise_proto(v) -> str:
    if isinstance(v, (int, np.integer, float, np.floating)) and not pd.isna(v):
        return PROTO_NUM.get(int(v), str(int(v)))
    s = str(v).strip().lower()
    if s.isdigit():
        return PROTO_NUM.get(int(s), s)
    if s in ("ipv6-icmp", "icmpv6"):
        return "icmp"
    return s


def empty_flows() -> pd.DataFrame:
    return pd.DataFrame({c: pd.Series(dtype="float64") for c in FLOW_COLUMNS})


def finalise(df: pd.DataFrame) -> pd.DataFrame:
    """Coerce any loader output to the canonical schema, sorted by time."""
    out = pd.DataFrame(index=df.index)
    for c in FLOW_COLUMNS:
        if c in df.columns:
            out[c] = df[c]
        else:
            out[c] = np.nan
    out["src_ip"] = out["src_ip"].astype(str).fillna("unknown")
    out["dst_ip"] = out["dst_ip"].astype(str).fillna("unknown")
    out["proto"] = out["proto"].map(normalise_proto)
    out["label"] = out["label"].where(out["label"].notna(), "benign").astype(str)
    for c in NUMERIC:
        out[c] = pd.to_numeric(out[c], errors="coerce")
    for c in ("pkts_fwd", "pkts_bwd", "bytes_fwd", "bytes_bwd", "duration",
              "syn", "ack", "fin", "rst", "psh", "urg"):
        out[c] = out[c].fillna(0.0).clip(lower=0)
    out["src_port"] = out["src_port"].fillna(-1)
    out["dst_port"] = out["dst_port"].fillna(-1)
    out = out[out["ts"].notna()]
    if out["stage"].isna().all():
        from .stages import label_to_stage
        out["stage"] = out["label"].map(label_to_stage)
    out["stage"] = out["stage"].fillna(0).astype(int)
    return out.sort_values("ts", kind="mergesort").reset_index(drop=True)
