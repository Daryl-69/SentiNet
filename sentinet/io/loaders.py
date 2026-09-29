"""Loaders: public datasets and our own formats -> canonical flow table.

Supported (format name -> what it reads):
  sentinet     canonical CSV written by this tool (and by the simulator)
  cicflowmeter CIC-IDS2017 "GeneratedLabelledFlows", CSE-CIC-IDS2018 CSVs and any
               CICFlowMeter output (column names are matched loosely)
  ctu13        CTU-13 / Stratosphere *.binetflow (Argus bidirectional flows)
  unsw         UNSW-NB15 raw CSVs (UNSW-NB15_1..4.csv, 49 columns, no header)
  pcap         raw .pcap / .pcapng (see sentinet.io.pcap)

`load(path)` auto-detects the format. A directory loads every supported file in
it, one sequence per file.
"""
from __future__ import annotations

import re
from pathlib import Path

import numpy as np
import pandas as pd

from ..schema import finalise
from ..stages import label_to_stage

FORMATS = ["auto", "sentinet", "cicflowmeter", "ctu13", "unsw", "pcap"]
_EXT_OK = (".csv", ".csv.gz", ".binetflow", ".binetflow.gz", ".pcap", ".pcapng", ".cap", ".gz", ".parquet")


def _norm(c: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(c).lower())


def _epoch(t: pd.Series) -> pd.Series:
    """datetime -> unix seconds, independent of pandas' datetime resolution (ns / us / s)."""
    return (t - pd.Timestamp("1970-01-01")).dt.total_seconds()


def stages_of(labels: pd.Series) -> pd.Series:
    """label -> stage, evaluating each distinct label once (datasets have millions of rows, few labels)."""
    lab = labels.astype(str)
    m = {u: label_to_stage(u) for u in lab.unique()}
    return lab.map(m).astype(int)


def _read_csv(path, **kw) -> pd.DataFrame:
    if str(path).lower().endswith(".parquet"):
        df = pd.read_parquet(path)
        n = kw.get("nrows")
        if kw.get("header", "infer") is None:   # emulate header=None: first row = column names
            df = pd.concat([pd.DataFrame([list(df.columns)], columns=df.columns), df], ignore_index=True)
            df.columns = range(df.shape[1])
        return df.head(n) if n else df
    return pd.read_csv(path, low_memory=False, encoding_errors="replace", **kw)


def detect_format(path) -> str:
    p = str(path).lower()
    p = p[:-3] if p.endswith(".gz") else p
    if p.endswith((".pcap", ".pcapng", ".cap")):
        return "pcap"
    if ".binetflow" in p:
        return "ctu13"
    head = _read_csv(path, nrows=5, header=None)
    first = [str(v) for v in head.iloc[0].tolist()]
    cols = {_norm(v) for v in first}
    if {"ts", "srcip", "dstip"} <= cols and "bytesfwd" in cols:
        return "sentinet"
    if "starttime" in cols and ("srcaddr" in cols or "totbytes" in cols):
        return "ctu13"
    if "flowduration" in cols or "totfwdpkts" in cols or "totalfwdpackets" in cols:
        return "cicflowmeter"
    if head.shape[1] in (48, 49) and re.match(r"^\d+\.\d+\.\d+\.\d+$", first[0] or ""):
        return "unsw"
    if "attackcat" in cols and "stime" in cols:
        return "unsw"
    raise ValueError(f"could not detect the format of {path}; pass --format explicitly")


# ------------------------------------------------------------------ canonical
def load_sentinet(path) -> pd.DataFrame:
    return finalise(_read_csv(path))


# ------------------------------------------------------------ CICFlowMeter
_CIC_MAP = {
    "src_ip": ["sourceip", "srcip"], "dst_ip": ["destinationip", "dstip"],
    "src_port": ["sourceport", "srcport"], "dst_port": ["destinationport", "dstport"],
    "proto": ["protocol"], "ts": ["timestamp"], "duration": ["flowduration"],
    "pkts_fwd": ["totalfwdpackets", "totfwdpkts", "totalfwdpacket"],
    "pkts_bwd": ["totalbackwardpackets", "totbwdpkts", "totalbwdpackets", "totalbwdpacket"],
    "bytes_fwd": ["totallengthoffwdpackets", "totlenfwdpkts", "totallengthoffwdpacket"],
    "bytes_bwd": ["totallengthofbwdpackets", "totlenbwdpkts", "totallengthofbwdpacket"],
    "iat_mean": ["flowiatmean"], "iat_std": ["flowiatstd"], "iat_max": ["flowiatmax"],
    "fin": ["finflagcount", "finflagcnt"], "syn": ["synflagcount", "synflagcnt"], "rst": ["rstflagcount", "rstflagcnt"],
    "psh": ["pshflagcount", "pshflagcnt"], "ack": ["ackflagcount", "ackflagcnt"], "urg": ["urgflagcount", "urgflagcnt"],
    "win_mean": ["initwinbytesforward", "initfwdwinbyts", "fwdinitwinbytes"],
    "payload_mean": ["packetlengthmean", "pktlenmean"], "payload_std": ["packetlengthstd", "pktlenstd"],
    "label": ["label"],
}


def _pick(df: pd.DataFrame, names: list[str]):
    cols = {_norm(c): c for c in df.columns}
    for n in names:
        if n in cols:
            return df[cols[n]]
    return None


def _parse_cic_time(s: pd.Series) -> pd.Series:
    raw = s.astype(str).str.strip()
    has_ampm = raw.str.contains(r"[AP]M", case=False, regex=True).any()
    t = None
    for fmt in ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %I:%M %p",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        cand = pd.to_datetime(raw, format=fmt, errors="coerce")
        if cand.notna().mean() > 0.99:
            t = cand
            break
    if t is None:  # slow path: per-row parsing
        t = pd.to_datetime(raw, dayfirst=True, errors="coerce", format="mixed")
    if not has_ampm and t.notna().any():
        # CIC-IDS2017 writes afternoon times on a 12-hour clock with no AM/PM
        # ("3:30" = 15:30). Capture hours were ~08:00-18:00, so hours < 8 are PM.
        h = t.dt.hour
        if h.max() <= 12 and (h < 8).any() and (h >= 8).any():
            t = t + pd.to_timedelta(np.where(h < 8, 12, 0), unit="h")
    return _epoch(t)


def load_cicflowmeter(path) -> pd.DataFrame:
    df = _read_csv(path)
    out = {}
    for k, names in _CIC_MAP.items():
        v = _pick(df, names)
        if v is not None:
            out[k] = v
    if "ts" not in out:
        raise ValueError(f"{path}: no Timestamp column; this CSV cannot be ordered in time "
                         "(the CIC 'MachineLearningCSV' files drop it -- use 'GeneratedLabelledFlows' / TrafficLabelling)")
    o = pd.DataFrame(out)
    o["ts"] = _parse_cic_time(o["ts"])
    for c in ("duration", "iat_mean", "iat_std", "iat_max"):
        if c in o:
            o[c] = pd.to_numeric(o[c], errors="coerce").clip(lower=0) / 1e6  # microseconds -> s
    for c in ("src_ip", "dst_ip"):
        if c not in o:
            o[c] = "unknown"
    o = o.replace([np.inf, -np.inf], np.nan)
    o["label"] = o.get("label", pd.Series("benign", index=o.index)).astype(str).str.strip()
    o["stage"] = stages_of(o["label"])
    return finalise(o)


# --------------------------------------------------------------------- CTU-13
def _port(v):
    s = str(v).strip()
    if s in ("", "nan"):
        return np.nan
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(float(s))
    except ValueError:
        return np.nan


def load_ctu13(path) -> pd.DataFrame:
    df = _read_csv(path)
    df.columns = [_norm(c) for c in df.columns]
    if "starttime" not in df.columns:
        raise ValueError(f"{path}: no StartTime column (stripped CTU-13 copy?) - columns are {list(df.columns)[:25]}")
    o = pd.DataFrame()
    st = df["starttime"].astype(str).str.strip()
    ts = pd.to_datetime(st, format="%Y/%m/%d %H:%M:%S.%f", errors="coerce")
    if ts.notna().mean() < 0.99:
        ts = pd.to_datetime(st, errors="coerce", format="mixed")
    o["ts"] = _epoch(ts)
    o["duration"] = pd.to_numeric(df["dur"], errors="coerce")
    o["proto"] = df["proto"].astype(str).str.lower()
    o["src_ip"], o["dst_ip"] = df["srcaddr"].astype(str), df["dstaddr"].astype(str)
    o["src_port"] = df["sport"].map(_port)
    o["dst_port"] = df["dport"].map(_port)
    tot_b = pd.to_numeric(df["totbytes"], errors="coerce").fillna(0)
    src_b = pd.to_numeric(df.get("srcbytes", tot_b / 2), errors="coerce").fillna(0)
    tot_p = pd.to_numeric(df["totpkts"], errors="coerce").fillna(0)
    share = (src_b / tot_b.replace(0, np.nan)).fillna(0.5)
    o["bytes_fwd"], o["bytes_bwd"] = src_b, (tot_b - src_b).clip(lower=0)
    o["pkts_fwd"] = np.maximum(1, np.round(tot_p * share))
    o["pkts_bwd"] = (tot_p - o["pkts_fwd"]).clip(lower=0)
    state = df.get("state", pd.Series("", index=df.index)).astype(str)
    is_tcp = o["proto"] == "tcp"
    for flag, letter in (("syn", "S"), ("ack", "A"), ("fin", "F"), ("rst", "R"), ("psh", "P"), ("urg", "U")):
        lut = {u: sum(letter in p_ for p_ in str(u).split("_")) for u in state.unique()}
        o[flag] = np.where(is_tcp, state.map(lut), 0)
    o["label"] = df["label"].astype(str)
    o["stage"] = stages_of(o["label"])
    return finalise(o)


# ------------------------------------------------------------------- UNSW-NB15
UNSW_COLS = ["srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes", "sttl", "dttl",
             "sloss", "dloss", "service", "sload", "dload", "spkts", "dpkts", "swin", "dwin", "stcpb", "dtcpb",
             "smeansz", "dmeansz", "trans_depth", "res_bdy_len", "sjit", "djit", "stime", "ltime", "sintpkt",
             "dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd",
             "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm",
             "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "label"]


def load_unsw(path) -> pd.DataFrame:
    head = _read_csv(path, nrows=1, header=None)
    has_header = "srcip" in {_norm(v) for v in head.iloc[0].tolist()}
    df = _read_csv(path, header=0 if has_header else None)
    if not has_header:
        df.columns = UNSW_COLS[: df.shape[1]]
    df.columns = [c.strip().lower() for c in df.columns]
    num = lambda c: pd.to_numeric(df[c], errors="coerce")  # noqa: E731
    o = pd.DataFrame()
    o["ts"] = num("stime")
    o["duration"] = num("dur")
    o["src_ip"], o["dst_ip"] = df["srcip"].astype(str), df["dstip"].astype(str)
    o["src_port"], o["dst_port"] = df["sport"].map(_port), df["dsport"].map(_port)
    o["proto"] = df["proto"].astype(str).str.lower()
    o["bytes_fwd"], o["bytes_bwd"] = num("sbytes"), num("dbytes")
    o["pkts_fwd"], o["pkts_bwd"] = num("spkts"), num("dpkts")
    o["ttl_mean"], o["ttl_std"] = num("sttl"), 0.0
    o["win_mean"] = num("swin")
    o["retrans"] = num("sloss").fillna(0) + num("dloss").fillna(0)
    o["payload_mean"] = num("smeansz")
    o["iat_mean"] = num("sintpkt") / 1000.0
    o["iat_std"] = num("sjit") / 1000.0
    st = df["state"].astype(str).str.upper()
    tcp = o["proto"] == "tcp"
    o["syn"] = np.where(tcp, 1 + st.isin(["FIN", "CON", "ACC", "CLO"]), 0)
    o["ack"] = np.where(tcp & ~st.isin(["REQ", "INT"]), o["pkts_fwd"].fillna(0) + o["pkts_bwd"].fillna(0) - 1, 0)
    o["fin"] = np.where(tcp & st.isin(["FIN", "CLO"]), 2, 0)
    o["rst"] = np.where(tcp & (st == "RST"), 1, 0)
    lab = pd.to_numeric(df.get("label", 0), errors="coerce").fillna(0)
    cat = df.get("attack_cat", pd.Series("", index=df.index)).astype(str).str.strip()
    o["label"] = np.where(lab > 0, cat.where(cat.str.len() > 0, "attack"), "benign")
    o["stage"] = stages_of(pd.Series(o["label"])).values
    return finalise(o)


# ---------------------------------------------------------------------- label rules
def apply_label_rules(flows: pd.DataFrame, rules_path) -> pd.DataFrame:
    """Label flows from a rules CSV with columns start,end,ip,stage and optional
    peer, port, label. A flow gets the stage when it starts inside [start, end],
    one end is `ip` ('*' = any), the other end is `peer` (if given) and its
    destination port is `port` (if given). Times are unix seconds or ISO strings."""
    rules = pd.read_csv(rules_path, dtype=str).fillna("*")

    def _t(v):
        try:
            return float(v)
        except (TypeError, ValueError):
            return pd.Timestamp(v).timestamp()
    flows = flows.copy()
    src, dst = flows["src_ip"].astype(str), flows["dst_ip"].astype(str)
    dport = flows["dst_port"].fillna(-1).astype(int)
    for _, r in rules.iterrows():
        m = (flows["ts"] >= _t(r["start"])) & (flows["ts"] <= _t(r["end"]))
        ip, peer = str(r.get("ip", "*")), str(r.get("peer", "*"))
        if ip != "*" and peer != "*":
            m &= ((src == ip) & (dst == peer)) | ((src == peer) & (dst == ip))
        elif ip != "*":
            m &= (src == ip) | (dst == ip)
        port = str(r.get("port", "*"))
        if port not in ("*", ""):
            m &= dport == int(float(port))
        st = str(r.get("stage", "*"))
        stage = int(float(st)) if st not in ("*", "") else label_to_stage(r.get("label"))
        flows.loc[m, "stage"] = stage
        flows.loc[m, "label"] = str(r.get("label")) if str(r.get("label", "*")) != "*" else f"stage:{stage}"
    return flows


# ------------------------------------------------------------------------ entry
def load(path, fmt: str = "auto", labels=None) -> pd.DataFrame:
    """Load one file into the canonical flow table."""
    fmt = detect_format(path) if fmt in (None, "auto") else fmt
    if fmt == "pcap":
        from .pcap import read_pcap
        df = read_pcap(path)
    elif fmt == "sentinet":
        df = load_sentinet(path)
    elif fmt == "cicflowmeter":
        df = load_cicflowmeter(path)
    elif fmt == "ctu13":
        df = load_ctu13(path)
    elif fmt == "unsw":
        df = load_unsw(path)
    else:
        raise ValueError(f"unknown format {fmt!r}; choose from {FORMATS}")
    if labels:
        df = apply_label_rules(df, labels)
    df.attrs["format"] = fmt
    return df


def list_inputs(path) -> list[Path]:
    p = Path(path)
    if p.is_dir():
        files = sorted(f for f in p.iterdir() if f.is_file() and f.name.lower().endswith(_EXT_OK)
                       and not f.name.endswith(".meta.json"))
        return files
    return [p]


def is_labelled(df: pd.DataFrame) -> bool:
    """True when the table carries ground-truth attack labels."""
    return bool((df["label"].astype(str).str.lower() != "benign").any() or (df["stage"] > 0).any())
