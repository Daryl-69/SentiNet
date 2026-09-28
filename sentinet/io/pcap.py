"""PCAP / PCAPNG -> canonical flow table with packet-level features.

Classic pcap files are parsed with a small built-in reader (fast); pcapng is
read through Scapy's RawPcapNgReader. Headers are decoded by hand, which is
10-50x faster than building a Scapy packet object per frame and works on
captures truncated with a small snaplen (lengths come from the IP header).

Per bidirectional flow it records, besides the NetFlow-style counters:
TTL mean/variance of the initiator's packets, the initiator's TCP window,
fragment flags, payload-size mean/std, packet IAT mean/std/max, TCP flag
counts and retransmitted segments.
"""
from __future__ import annotations

import gzip
import math
import socket
import struct
from pathlib import Path

import pandas as pd

from ..schema import finalise

IDLE_TIMEOUT = 120.0
ACTIVE_TIMEOUT = 3600.0
_MAX_SEQS = 4096


class _Run:
    """Running mean / variance / max (Welford)."""
    __slots__ = ("n", "mean", "m2", "max")

    def __init__(self):
        self.n, self.mean, self.m2, self.max = 0, 0.0, 0.0, 0.0

    def add(self, x: float):
        self.n += 1
        d = x - self.mean
        self.mean += d / self.n
        self.m2 += d * (x - self.mean)
        if x > self.max:
            self.max = x

    @property
    def std(self):
        return math.sqrt(self.m2 / self.n) if self.n > 1 else 0.0


class _Flow:
    __slots__ = ("key", "src", "dst", "sport", "dport", "proto", "start", "last", "pf", "pb", "bf", "bb",
                 "flags", "iat", "ttl", "win", "frag", "pay", "retrans", "seqs", "closed")

    def __init__(self, key, src, dst, sport, dport, proto, ts):
        self.key, self.src, self.dst, self.sport, self.dport, self.proto = key, src, dst, sport, dport, proto
        self.start = self.last = ts
        self.pf = self.pb = self.bf = self.bb = 0
        self.flags = [0, 0, 0, 0, 0, 0]  # syn ack fin rst psh urg
        self.iat, self.ttl, self.win, self.pay = _Run(), _Run(), _Run(), _Run()
        self.frag = self.retrans = 0
        self.seqs: set = set()
        self.closed = False

    def row(self):
        return (self.start, self.last - self.start, self.src, self.dst, self.sport, self.dport, self.proto,
                self.pf, self.pb, self.bf, self.bb, *self.flags, self.iat.mean if self.iat.n else float("nan"),
                self.iat.std if self.iat.n else float("nan"), self.iat.max if self.iat.n else float("nan"),
                self.ttl.mean if self.ttl.n else float("nan"), self.ttl.std if self.ttl.n else float("nan"),
                self.win.mean if self.win.n else float("nan"), self.frag, self.pay.mean, self.pay.std, self.retrans)


_ROW_COLS = ["ts", "duration", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "pkts_fwd", "pkts_bwd",
             "bytes_fwd", "bytes_bwd", "syn", "ack", "fin", "rst", "psh", "urg", "iat_mean", "iat_std", "iat_max",
             "ttl_mean", "ttl_std", "win_mean", "frag", "payload_mean", "payload_std", "retrans"]


def _open(path):
    p = str(path)
    return gzip.open(p, "rb") if p.endswith(".gz") else open(p, "rb")


def _iter_classic(f, header: bytes):
    magic = header[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    else:
        endian = ">"
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(endian + "I", header[20:24])[0] & 0x0FFFFFFF
    rec = struct.Struct(endian + "IIII")
    div = 1e9 if nano else 1e6
    while True:
        h = f.read(16)
        if len(h) < 16:
            return
        sec, frac, incl, orig = rec.unpack(h)
        data = f.read(incl)
        if len(data) < incl:
            return
        yield sec + frac / div, linktype, data, orig


def _iter_packets(path):
    with _open(path) as f:
        header = f.read(24)
        if header[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            yield from _iter_classic(f, header)
            return
    if header[:4] == b"\x0a\x0d\x0d\x0a":
        from scapy.utils import RawPcapNgReader
        src = str(path)
        if src.endswith(".gz"):
            import tempfile
            with _open(path) as g, tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as tmp:
                tmp.write(g.read())
                src = tmp.name
        for data, meta in RawPcapNgReader(src):
            ts = ((meta.tshigh << 32) | meta.tslow) / float(meta.tsresol or 1e6)
            yield ts, meta.linktype, data, meta.wirelen
        return
    raise ValueError(f"{path} is not a pcap or pcapng file")


def _l3(linktype: int, data: bytes):
    """Return (ethertype, offset of the network header) or None."""
    if linktype == 1:  # Ethernet
        if len(data) < 14:
            return None
        et = (data[12] << 8) | data[13]
        off = 14
        while et in (0x8100, 0x88A8) and len(data) >= off + 4:
            et = (data[off + 2] << 8) | data[off + 3]
            off += 4
        return et, off
    if linktype in (101, 12, 14, 228, 229):  # raw IP
        if not data:
            return None
        v = data[0] >> 4
        return (0x0800 if v == 4 else 0x86DD), 0
    if linktype == 113:  # Linux cooked
        return ((data[14] << 8) | data[15]), 16
    if linktype == 276:  # Linux cooked v2
        return ((data[0] << 8) | data[1]), 20
    if linktype == 0:  # BSD loopback
        fam = struct.unpack("<I", data[:4])[0]
        return (0x0800 if fam == 2 else 0x86DD), 4
    return None


def read_pcap(path, idle_timeout: float = IDLE_TIMEOUT, max_packets: int | None = None) -> pd.DataFrame:
    flows: dict = {}
    pair_last: dict = {}
    done: list = []
    ip4 = socket.inet_ntoa
    ip6 = lambda b: socket.inet_ntop(socket.AF_INET6, b)  # noqa: E731
    n = 0
    for ts, linktype, data, wirelen in _iter_packets(path):
        n += 1
        if max_packets and n > max_packets:
            break
        l3 = _l3(linktype, data)
        if l3 is None:
            continue
        et, o = l3
        frag = False
        if et == 0x0800 and len(data) >= o + 20:
            ihl = (data[o] & 0x0F) * 4
            tot_len = (data[o + 2] << 8) | data[o + 3]
            ff = (data[o + 6] << 8) | data[o + 7]
            frag = bool(ff & 0x2000) or (ff & 0x1FFF) > 0
            ttl, proto = data[o + 8], data[o + 9]
            src, dst = ip4(data[o + 12:o + 16]), ip4(data[o + 16:o + 20])
            l4 = o + ihl
            ip_len = tot_len or (wirelen - o)
            l4_len = ip_len - ihl
            if (ff & 0x1FFF) > 0:  # non-first fragment: no L4 header
                proto_name = {6: "tcp", 17: "udp", 1: "icmp"}.get(proto, str(proto))
                fl = pair_last.get((proto_name, src, dst))
                if fl is not None:
                    fl.frag += 1
                    if src == fl.src:
                        fl.pf += 1
                        fl.bf += ip_len
                    else:
                        fl.pb += 1
                        fl.bb += ip_len
                continue
        elif et == 0x86DD and len(data) >= o + 40:
            pl = (data[o + 4] << 8) | data[o + 5]
            proto, ttl = data[o + 6], data[o + 7]
            src, dst = ip6(data[o + 8:o + 24]), ip6(data[o + 24:o + 40])
            l4 = o + 40
            if proto == 44 and len(data) >= l4 + 8:  # fragment header
                frag = True
                proto = data[l4]
                l4 += 8
                pl -= 8
            ip_len, l4_len = pl + 40, pl
        else:
            continue

        sport = dport = -1
        flags = 0
        win = None
        seq = None
        if proto == 6 and len(data) >= l4 + 14:
            sport = (data[l4] << 8) | data[l4 + 1]
            dport = (data[l4 + 2] << 8) | data[l4 + 3]
            seq = struct.unpack(">I", data[l4 + 4:l4 + 8])[0]
            doff = (data[l4 + 12] >> 4) * 4
            flags = data[l4 + 13]
            win = (data[l4 + 14] << 8) | data[l4 + 15] if len(data) >= l4 + 16 else None
            payload = max(0, l4_len - doff)
            pname = "tcp"
        elif proto == 17 and len(data) >= l4 + 8:
            sport = (data[l4] << 8) | data[l4 + 1]
            dport = (data[l4 + 2] << 8) | data[l4 + 3]
            payload = max(0, l4_len - 8)
            pname = "udp"
        elif proto in (1, 58):
            pname = "icmp"
            dport = data[l4] if len(data) > l4 else -1
            payload = max(0, l4_len - 8)
        else:
            pname = str(proto)
            payload = max(0, l4_len)

        a, b = (src, sport), (dst, dport)
        key = (pname, a, b) if a <= b else (pname, b, a)
        fl = flows.get(key)
        syn_only = pname == "tcp" and (flags & 0x02) and not (flags & 0x10)
        if fl is not None and (ts - fl.last > idle_timeout or ts - fl.start > ACTIVE_TIMEOUT or (fl.closed and syn_only)):
            done.append(fl.row())
            fl = None
        if fl is None:
            fl = _Flow(key, src, dst, sport, dport, pname, ts)
            flows[key] = fl
        else:
            fl.iat.add(ts - fl.last)
            fl.last = ts
        pair_last[(pname, src, dst)] = fl
        fwd = src == fl.src and sport == fl.sport
        if fwd:
            fl.pf += 1
            fl.bf += ip_len
            fl.ttl.add(float(ttl))
            if win is not None:
                fl.win.add(float(win))
        else:
            fl.pb += 1
            fl.bb += ip_len
        fl.pay.add(float(payload))
        if frag:
            fl.frag += 1
        if pname == "tcp":
            fl.flags[0] += bool(flags & 0x02)
            fl.flags[1] += bool(flags & 0x10)
            fl.flags[2] += bool(flags & 0x01)
            fl.flags[3] += bool(flags & 0x04)
            fl.flags[4] += bool(flags & 0x08)
            fl.flags[5] += bool(flags & 0x20)
            if flags & 0x04 or fl.flags[2] >= 2:
                fl.closed = True
            if payload > 0 and seq is not None:
                k = (fwd, seq)
                if k in fl.seqs:
                    fl.retrans += 1
                elif len(fl.seqs) < _MAX_SEQS:
                    fl.seqs.add(k)
    done.extend(fl.row() for fl in flows.values())
    df = pd.DataFrame(done, columns=_ROW_COLS)
    df["label"] = "benign"
    df["stage"] = 0
    out = finalise(df)
    out.attrs["packets"] = n
    return out


def pcap_to_csv(pcap_path, csv_path):
    df = read_pcap(pcap_path)
    Path(csv_path).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(csv_path, index=False)
    return df
