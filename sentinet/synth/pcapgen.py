"""Write a simulated scenario as a real PCAP file (Ethernet/IPv4/TCP|UDP).

Packets are stored header-only (snaplen 54: Ethernet + IP + TCP) with the true on-wire length in
the record, the way a sensor with a short snaplen would capture them; IP
total-length fields carry the real sizes, so any PCAP tool (Wireshark, Scapy,
tcpdump, and our extractor) sees the right byte counts. Large transfers are
written as large (TSO/GRO-style) segments to keep the file small.
"""
from __future__ import annotations

import socket
import struct

import numpy as np
import pandas as pd

SNAP = 54
MAX_SEG = 65000
MAX_DATA_PKTS = 3000


def _csum(b: bytes) -> int:
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _mac(ip: str) -> bytes:
    h = abs(hash(ip)) & 0xFFFFFFFFFF
    return b"\x02" + h.to_bytes(5, "big")


class PcapWriter:
    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, SNAP, 1))
        self.n = 0

    def packet(self, ts, src, dst, sport, dport, proto, payload_len, flags=0, ttl=64, win=64240, seq=0, ack=0, mf=False):
        if proto == "tcp":
            l4 = struct.pack("!HHIIBBHHH", int(sport) & 0xFFFF, int(dport) & 0xFFFF, seq & 0xFFFFFFFF,
                             ack & 0xFFFFFFFF, 5 << 4, flags, int(win) & 0xFFFF, 0, 0)
            pnum = 6
        else:
            l4 = struct.pack("!HHHH", int(sport) & 0xFFFF, int(dport) & 0xFFFF, (8 + payload_len) & 0xFFFF, 0)
            pnum = 17
        total = min(20 + len(l4) + int(payload_len), 65535)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, self.n & 0xFFFF, 0x2000 if mf else 0x4000,
                         int(ttl) & 0xFF, pnum, 0, socket.inet_aton(src), socket.inet_aton(dst))
        ip = ip[:10] + struct.pack("!H", _csum(ip)) + ip[12:]
        eth = _mac(dst) + _mac(src) + b"\x08\x00"
        frame = eth + ip + l4
        wire = 14 + total
        cap = frame[:SNAP]
        sec = int(ts)
        self.f.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(cap), wire))
        self.f.write(cap)
        self.n += 1

    def close(self):
        self.f.close()


SYN, ACK, FIN, RST, PSH = 0x02, 0x10, 0x01, 0x04, 0x08


def flows_to_pcap(flows: pd.DataFrame, path, seed: int = 0) -> int:
    """Materialise canonical flows as packets. Returns the packet count."""
    rng = np.random.default_rng(seed)
    pkts = []  # (ts, args) collected then sorted
    for r in flows.itertuples(index=False):
        src, dst, sp, dp = r.src_ip, r.dst_ip, int(r.src_port), int(r.dst_port)
        t0, dur = float(r.ts), max(float(r.duration), 0.0)
        ttl = int(r.ttl_mean) if not pd.isna(r.ttl_mean) else 64
        win = int(r.win_mean) if not pd.isna(r.win_mean) else 64240
        mf = (r.frag or 0) > 0
        if r.proto == "udp":
            nf = max(1, int(r.pkts_fwd)); nb = int(r.pkts_bwd)
            pf = max(0, (r.bytes_fwd - 28 * nf) / nf); pb = max(0, (r.bytes_bwd - 28 * max(nb, 1)) / max(nb, 1))
            times = np.sort(t0 + rng.uniform(0, max(dur, 1e-4), nf + nb))
            for i, ts in enumerate(times):
                if i % 2 == 0 and nf > 0:
                    pkts.append((ts, (src, dst, sp, dp, "udp", int(pf), 0, ttl, win, 0, 0, mf))); nf -= 1
                elif nb > 0:
                    pkts.append((ts, (dst, src, dp, sp, "udp", int(pb), 0, 64, win, 0, 0, False))); nb -= 1
                else:
                    pkts.append((ts, (src, dst, sp, dp, "udp", int(pf), 0, ttl, win, 0, 0, mf))); nf -= 1
            continue
        isn, isn2 = int(rng.integers(0, 2**31)), int(rng.integers(0, 2**31))
        if r.ack == 0 and r.syn > 0:  # unanswered SYN(s)
            for i in range(int(r.syn)):
                pkts.append((t0 + i * min(1.0, dur or 1.0), (src, dst, sp, dp, "tcp", 0, SYN, ttl, win, isn, 0, mf)))
            continue
        if r.rst > 0 and r.pkts_bwd <= 1 and r.bytes_fwd <= 80:  # rejected
            pkts.append((t0, (src, dst, sp, dp, "tcp", 0, SYN, ttl, win, isn, 0, mf)))
            pkts.append((t0 + max(dur, 1e-4), (dst, src, dp, sp, "tcp", 0, RST | ACK, 64, 0, 0, isn + 1, False)))
            continue
        # full (or reset) TCP connection
        rtt = min(0.05, max(dur / 20, 1e-4))
        pf = max(0.0, r.bytes_fwd - 40 * r.pkts_fwd)
        pb = max(0.0, r.bytes_bwd - 40 * r.pkts_bwd)
        seg_f = max(1448.0, pf / MAX_DATA_PKTS)
        seg_b = max(1448.0, pb / MAX_DATA_PKTS)
        nf = int(np.ceil(pf / min(seg_f, MAX_SEG))) if pf > 0 else 0
        nb = int(np.ceil(pb / min(seg_b, MAX_SEG))) if pb > 0 else 0
        pkts.append((t0, (src, dst, sp, dp, "tcp", 0, SYN, ttl, win, isn, 0, mf)))
        pkts.append((t0 + rtt, (dst, src, dp, sp, "tcp", 0, SYN | ACK, 64, 65160, isn2, isn + 1, False)))
        pkts.append((t0 + 2 * rtt, (src, dst, sp, dp, "tcp", 0, ACK, ttl, win, isn + 1, isn2 + 1, False)))
        span = max(dur - 4 * rtt, 1e-3)
        ack_f, ack_b = int(np.ceil(nb / 2)), int(np.ceil(nf / 2))   # delayed ACKs, as the simulator counts them
        kinds = np.r_[np.zeros(nf, int), np.ones(nb, int), np.full(ack_f, 2), np.full(ack_b, 3)]
        times = np.sort(t0 + 2 * rtt + rng.uniform(0, span, len(kinds)))
        order = rng.permutation(kinds)
        n_re = int(r.retrans or 0)
        sf, sb = isn + 1, isn2 + 1
        left_f, left_b = pf, pb
        last = None
        for ts, d in zip(times, order):
            if d == 0:
                ln = int(min(seg_f, left_f, MAX_SEG)); left_f -= ln
                last = (src, dst, sp, dp, "tcp", ln, PSH | ACK, ttl, win, sf, sb, False)
                pkts.append((ts, last))
                sf += ln
            elif d == 1:
                ln = int(min(seg_b, left_b, MAX_SEG)); left_b -= ln
                pkts.append((ts, (dst, src, dp, sp, "tcp", ln, PSH | ACK, 64, 65160, sb, sf, False))); sb += ln
            elif d == 2:
                pkts.append((ts, (src, dst, sp, dp, "tcp", 0, ACK, ttl, win, sf, sb, False)))
            else:
                pkts.append((ts, (dst, src, dp, sp, "tcp", 0, ACK, 64, 65160, sb, sf, False)))
            if n_re and last is not None and rng.random() < 0.05:
                pkts.append((ts + rtt, last)); n_re -= 1
        te = t0 + max(dur, 3 * rtt)
        if r.rst > 0:
            pkts.append((te, (src, dst, sp, dp, "tcp", 0, RST | ACK, ttl, win, sf, sb, False)))
        else:
            pkts.append((te, (src, dst, sp, dp, "tcp", 0, FIN | ACK, ttl, win, sf, sb, False)))
            pkts.append((te + rtt, (dst, src, dp, sp, "tcp", 0, FIN | ACK, 64, 65160, sb, sf + 1, False)))
            pkts.append((te + 2 * rtt, (src, dst, sp, dp, "tcp", 0, ACK, ttl, win, sf + 1, sb + 1, False)))
    pkts.sort(key=lambda p: p[0])
    w = PcapWriter(path)
    for ts, (s, d, a, b, proto, ln, fl, ttl, win, seq, ack, mf) in pkts:
        w.packet(ts, s, d, a, b, proto, ln, fl, ttl, win, seq, ack, mf)
    w.close()
    return w.n


def label_rules_from_flows(flows: pd.DataFrame) -> pd.DataFrame:
    """Ground-truth rules CSV (start,end,ip,peer,port,stage,label) from labelled flows,
    so a PCAP written from them can be re-labelled after extraction."""
    mal = flows[flows["stage"] > 0]
    rows = []
    for (s_, d_, st), g in mal.groupby(["src_ip", "dst_ip", "stage"]):
        ports = g["dst_port"].astype(int).unique()
        lab = str(g["label"].iloc[0]).split(":")[2] if str(g["label"].iloc[0]).startswith("stage:") else ""
        base = {"start": float(g["ts"].min()) - 0.5, "end": float(g["ts"].max()) + 0.5, "ip": s_, "peer": d_,
                "stage": int(st), "label": f"stage:{int(st)}:{lab}"}
        if len(ports) > 20:
            rows.append({**base, "port": "*"})
        else:
            for p_ in ports:
                gp = g[g["dst_port"].astype(int) == p_]
                rows.append({**base, "start": float(gp["ts"].min()) - 0.5, "end": float(gp["ts"].max()) + 0.5,
                             "port": int(p_)})
    return pd.DataFrame(rows, columns=["start", "end", "ip", "peer", "port", "stage", "label"])
