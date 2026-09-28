"""Multi-stage attack scenario simulator.

Generates a labelled flow table (canonical schema) for a small enterprise
network: workstations, a domain controller, file/DB/mail servers, an exposed
web server and SSH gateway, and external services. On top of benign traffic
it plays attack campaigns that move through ATT&CK stages over time.

Why a simulator: the public datasets named in the problem statement
(CIC-IDS2017/2018, CTU-13, UNSW-NB15, ...) are supported by `sentinet.io`,
but none of them could be downloaded inside the build environment. The
simulator lets the whole pipeline train, run and be benchmarked offline, and
it is deliberately hard to game:

  * benign "hard negatives" that look like attack stages: an admin who RDPs
    and SSHes into servers every day, a nightly internal inventory scan, a
    nightly cloud backup upload, periodic telemetry beacons, and internet
    scanners that probe the web server and never follow up;
  * failed campaigns (recon + brute force that never gets in), so recon is
    not a guaranteed predictor of compromise;
  * phishing campaigns with no visible recon at all;
  * a low-and-slow APT template that can be held out entirely to test
    generalisation to an attack pattern the model never saw.
"""
from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from ..schema import FLOW_COLUMNS, finalise
from ..stages import BENIGN, RECON, INITIAL_ACCESS, LATERAL, C2, EXFIL, IMPACT

TEMPLATES = ["web_exploit", "phishing", "bruteforce", "slow_apt", "failed_attack", "ddos"]
DEFAULT_TEMPLATE_WEIGHTS = {"web_exploit": 0.27, "phishing": 0.2, "bruteforce": 0.2,
                            "slow_apt": 0.13, "failed_attack": 0.14, "ddos": 0.06}

LATERAL_PORTS = [22, 135, 139, 445, 3389, 5985]
MAX_DATA_PKTS = 3000


# --------------------------------------------------------------------------- #
# vectorised flow construction
# --------------------------------------------------------------------------- #
class FlowBuffer:
    def __init__(self, rng: np.random.Generator):
        self.rng = rng
        self.chunks: list[pd.DataFrame] = []

    def add(self, ts, src, dst, dport, *, proto="tcp", kind="full", bytes_fwd=0.0,
            bytes_bwd=0.0, dur=0.1, ttl=64.0, ttl_std=0.0, win=64240.0, sport=None,
            iat_cv=1.0, frag=0.0, label="benign", stage=BENIGN):
        """Append n flows. Scalars broadcast; `kind` is one of
        full | syn (no answer) | rej (RST answer) | rst (reset mid-way) | udp."""
        ts = np.atleast_1d(np.asarray(ts, dtype=float))
        n = len(ts)
        if n == 0:
            return
        rng = self.rng
        b = lambda v: np.broadcast_to(np.asarray(v), (n,)).copy()  # noqa: E731
        pf = b(bytes_fwd).astype(float)
        pb = b(bytes_bwd).astype(float)
        dur = b(dur).astype(float)
        if sport is None:
            sport = rng.integers(49152, 65535, n)
        kinds = b(kind).astype(str)
        proto = b(proto).astype(str)

        pkts_f = np.zeros(n); pkts_b = np.zeros(n)
        syn = np.zeros(n); ack = np.zeros(n); fin = np.zeros(n); rst = np.zeros(n)
        psh = np.zeros(n); urg = np.zeros(n)

        full = kinds == "full"
        rstk = kinds == "rst"
        synk = kinds == "syn"
        rej = kinds == "rej"
        udp = kinds == "udp"

        # segment size: MSS, but large transfers use big (GRO/TSO-style) segments, max ~3000 per direction,
        # exactly as sentinet.synth.pcapgen writes them, so CSV and PCAP views of a scenario agree
        seg_f = np.maximum(1448.0, pf / MAX_DATA_PKTS)
        seg_b = np.maximum(1448.0, pb / MAX_DATA_PKTS)
        dp_f = np.ceil(pf / seg_f); dp_b = np.ceil(pb / seg_b)
        tcpdata = full | rstk
        pkts_f[tcpdata] = dp_f[tcpdata] + 3 + np.ceil(dp_b[tcpdata] / 2) + full[tcpdata]
        pkts_b[tcpdata] = dp_b[tcpdata] + 1 + np.ceil(dp_f[tcpdata] / 2) + full[tcpdata]
        syn[tcpdata] = 2
        fin[full] = 2
        rst[rstk] = 1
        ack[tcpdata] = pkts_f[tcpdata] + pkts_b[tcpdata] - 1
        psh[tcpdata] = np.minimum(dp_f[tcpdata] + dp_b[tcpdata], 1 + (dp_f[tcpdata] + dp_b[tcpdata]) // 3)

        retry = rng.random(n) < 0.3
        pkts_f[synk] = 1 + retry[synk]
        syn[synk] = pkts_f[synk]
        dur[synk] = np.where(retry[synk], rng.uniform(1.0, 3.0, synk.sum()), 0.0)
        pf[synk] = 0; pb[synk] = 0

        pkts_f[rej] = 1; pkts_b[rej] = 1; syn[rej] = 1; rst[rej] = 1; ack[rej] = 1
        pf[rej] = 0; pb[rej] = 0
        dur[rej] = rng.uniform(0.0005, 0.08, rej.sum())

        pkts_f[udp] = np.maximum(1, np.ceil(pf[udp] / 1400.0))
        pkts_b[udp] = np.where(pb[udp] > 0, np.maximum(1, np.ceil(pb[udp] / 1400.0)), 0)

        tot = pkts_f + pkts_b
        hdr = np.where(udp, 28.0, 40.0)
        bytes_f = pf + hdr * pkts_f
        bytes_b = pb + hdr * pkts_b
        # packets arrive roughly uniformly within a flow: exponential gaps (CV ~ 1),
        # the largest gap ~ mean * H(n-1)
        iat_mean = np.where(tot > 1, dur / np.maximum(tot - 1, 1), 0.0)
        cv = b(iat_cv).astype(float) * rng.uniform(0.85, 1.15, n)
        iat_std = iat_mean * cv
        iat_max = np.minimum(dur, iat_mean * (0.577 + np.log(np.maximum(tot - 1, 1)) + 0.5))
        pay_mean = np.where(tot > 0, (pf + pb) / np.maximum(tot, 1), 0.0)
        # payload sizes: data segments of ~equal size mixed with zero-payload control packets
        q = np.clip((dp_f + dp_b) / np.maximum(tot, 1), 1e-3, 1.0)
        pay_std = np.where((pf + pb) > 0, pay_mean * np.sqrt((1 - q) / q) * rng.uniform(0.9, 1.1, n), 0.0)
        retrans = np.where(dp_f + dp_b > 0, rng.poisson(0.01 * (dp_f + dp_b)), 0)
        ttl = b(ttl).astype(float)
        ttl_std = b(ttl_std).astype(float)
        win = b(win).astype(float)
        win = np.where(udp, np.nan, win)
        frag = b(frag).astype(float)

        self.chunks.append(pd.DataFrame({
            "ts": ts, "duration": dur, "src_ip": b(src).astype(str), "dst_ip": b(dst).astype(str),
            "src_port": b(sport).astype(float), "dst_port": b(dport).astype(float),
            "proto": np.where(udp, "udp", proto),
            "pkts_fwd": pkts_f, "pkts_bwd": pkts_b, "bytes_fwd": bytes_f, "bytes_bwd": bytes_b,
            "syn": syn, "ack": ack, "fin": fin, "rst": rst, "psh": psh, "urg": urg,
            "iat_mean": iat_mean, "iat_std": iat_std, "iat_max": iat_max,
            "ttl_mean": ttl, "ttl_std": ttl_std, "win_mean": win, "frag": frag,
            "payload_mean": pay_mean, "payload_std": pay_std, "retrans": retrans.astype(float),
            "label": b(label).astype(str), "stage": b(stage).astype(int),
        }))

    def frame(self) -> pd.DataFrame:
        if not self.chunks:
            return pd.DataFrame(columns=FLOW_COLUMNS)
        return pd.concat(self.chunks, ignore_index=True)


# --------------------------------------------------------------------------- #
# network model
# --------------------------------------------------------------------------- #
def _rand_public(rng, n, firsts):
    out = []
    while len(out) < n:
        a = int(rng.choice(firsts))
        ip = f"{a}.{rng.integers(0, 256)}.{rng.integers(0, 256)}.{rng.integers(1, 255)}"
        if not ipaddress.ip_address(ip).is_private:
            out.append(ip)
    return out


@dataclass
class Network:
    rng: np.random.Generator
    n_ws: int = 28
    ws: list = field(default_factory=list)
    admin: str = "10.10.1.5"
    dc: str = "10.10.0.5"
    fs: str = "10.10.0.10"
    db: str = "10.10.0.30"
    mail: str = "10.10.0.40"
    jump: str = "10.10.0.50"
    backup: str = "10.10.0.60"
    web: str = "10.10.2.20"
    gw: str = "10.10.2.21"        # internet-facing SSH/VPN gateway
    saas: list = field(default_factory=list)
    visitors: list = field(default_factory=list)
    cloud_backup: str = ""
    telemetry: str = ""

    def __post_init__(self):
        r = self.rng
        self.ws = [f"10.10.1.{i}" for i in range(10, 10 + self.n_ws)]
        self.saas = _rand_public(r, 180, [13, 20, 23, 34, 35, 52, 104, 142, 151, 172, 199, 216])
        self.visitors = _rand_public(r, 400, [27, 49, 59, 103, 106, 117, 122, 157, 182, 223])
        self.cloud_backup = _rand_public(r, 1, [52])[0]
        self.telemetry = _rand_public(r, 1, [40])[0]

    @property
    def servers(self):
        return [self.dc, self.fs, self.db, self.mail, self.jump, self.backup, self.web, self.gw]

    @property
    def internal(self):
        return self.ws + [self.admin] + self.servers


def _diurnal(hours: np.ndarray) -> np.ndarray:
    h = hours % 24
    w = np.full_like(h, 0.08, dtype=float)
    w[(h >= 7) & (h < 9)] = 0.45
    w[(h >= 9) & (h < 18)] = 1.0
    w[(h >= 18) & (h < 22)] = 0.3
    return w


def _events(rng, t0, minutes, rate, diurnal_on, start_hour, n_hosts=1):
    """Poisson event times for n_hosts, `rate` events/min at peak."""
    hours = start_hour + np.arange(minutes) / 60.0
    lam = rate * (_diurnal(hours) if diurnal_on else np.ones(minutes))
    counts = rng.poisson(np.tile(lam, (n_hosts, 1)))
    host_idx, minute_idx = np.nonzero(counts)
    reps = counts[host_idx, minute_idx]
    host_idx = np.repeat(host_idx, reps)
    minute_idx = np.repeat(minute_idx, reps)
    ts = t0 + minute_idx * 60.0 + rng.uniform(0, 60, len(minute_idx))
    return ts, host_idx


def _benign(buf: FlowBuffer, net: Network, t0: float, minutes: int, start_hour: float):
    r = net.rng
    ws = np.array(net.ws + [net.admin])
    nw = len(ws)
    lognorm = lambda m, s, n: np.exp(r.normal(np.log(m), s, n))  # noqa: E731

    # web browsing (downloads dominate)
    ts, h = _events(r, t0, minutes, 1.3, True, start_hour, nw)
    n = len(ts)
    buf.add(ts, ws[h], r.choice(net.saas, n), r.choice([443, 443, 443, 80], n),
            bytes_fwd=lognorm(900, 0.8, n), bytes_bwd=lognorm(40000, 1.4, n),
            dur=lognorm(3, 1.2, n), ttl=128, win=64240, iat_cv=1.4)
    # DNS to the domain controller
    ts, h = _events(r, t0, minutes, 1.6, True, start_hour, nw)
    n = len(ts)
    buf.add(ts, ws[h], net.dc, 53, kind="udp", bytes_fwd=r.integers(30, 70, n),
            bytes_bwd=r.integers(60, 300, n), dur=r.uniform(0.001, 0.05, n), ttl=128, iat_cv=0.1)
    # Kerberos / LDAP
    ts, h = _events(r, t0, minutes, 0.25, True, start_hour, nw)
    n = len(ts)
    buf.add(ts, ws[h], net.dc, r.choice([88, 389, 389, 445], n), bytes_fwd=lognorm(1500, 0.5, n),
            bytes_bwd=lognorm(3000, 0.6, n), dur=lognorm(0.3, 0.8, n), ttl=128, win=64240)
    # file shares (SMB is legitimate here)
    ts, h = _events(r, t0, minutes, 0.3, True, start_hour, nw)
    n = len(ts)
    buf.add(ts, ws[h], net.fs, 445, bytes_fwd=lognorm(4000, 1.2, n), bytes_bwd=lognorm(60000, 1.6, n),
            dur=lognorm(4, 1.0, n), ttl=128, win=64240)
    # mail
    ts, h = _events(r, t0, minutes, 0.12, True, start_hour, nw)
    n = len(ts)
    buf.add(ts, ws[h], net.mail, r.choice([993, 587, 443], n), bytes_fwd=lognorm(2000, 1.0, n),
            bytes_bwd=lognorm(20000, 1.3, n), dur=lognorm(2, 1.0, n), ttl=128, win=64240)
    # software updates (large downloads)
    ts, h = _events(r, t0, minutes, 0.01, False, start_hour, nw)
    n = len(ts)
    buf.add(ts, ws[h], r.choice(net.saas[:20], n), 443, bytes_fwd=lognorm(3000, 0.4, n),
            bytes_bwd=lognorm(8e7, 0.8, n), dur=lognorm(60, 0.7, n), ttl=128, win=64240)
    # periodic telemetry: every workstation checks in every ~300 s (hard negative for C2)
    period = 300.0
    for i, host in enumerate(ws):
        k = np.arange(int(minutes * 60 / period))
        ts = t0 + r.uniform(0, period) + k * period + r.normal(0, 4, len(k))
        buf.add(ts, host, net.telemetry, 443, bytes_fwd=r.integers(300, 700, len(k)),
                bytes_bwd=r.integers(200, 900, len(k)), dur=r.uniform(0.05, 0.4, len(k)), ttl=128,
                win=64240, iat_cv=0.3)
    # two SaaS clients polling every 60 s
    for host in r.choice(ws, 2, replace=False):
        k = np.arange(minutes)
        ts = t0 + r.uniform(0, 60) + k * 60 + r.normal(0, 2, len(k))
        buf.add(ts, host, net.saas[5], 443, bytes_fwd=r.integers(400, 900, len(k)),
                bytes_bwd=r.integers(500, 3000, len(k)), dur=r.uniform(0.1, 0.6, len(k)), ttl=128, win=64240)
    # web server: visitors, and its database
    ts, _ = _events(r, t0, minutes, 6.0, True, start_hour, 1)
    n = len(ts)
    vis = r.choice(net.visitors, n)
    buf.add(ts, vis, net.web, r.choice([443, 443, 80], n), bytes_fwd=lognorm(800, 0.7, n),
            bytes_bwd=lognorm(25000, 1.2, n), dur=lognorm(1.5, 1.0, n),
            ttl=r.choice([46, 52, 109, 113, 117], n), win=r.choice([64240, 65535, 29200], n), iat_cv=1.2)
    ts, _ = _events(r, t0, minutes, 5.0, True, start_hour, 1)
    n = len(ts)
    buf.add(ts, net.web, net.db, 3306, bytes_fwd=lognorm(600, 0.6, n), bytes_bwd=lognorm(4000, 1.0, n),
            dur=lognorm(0.05, 0.8, n), ttl=64, win=29200)
    # NTP
    ts, h = _events(r, t0, minutes, 0.02, False, start_hour, nw)
    buf.add(ts, ws[h], net.dc, 123, kind="udp", bytes_fwd=48, bytes_bwd=48, dur=0.01, ttl=128)
    # admin RDP / SSH / WinRM into servers during the day (hard negative for lateral movement)
    ts, _ = _events(r, t0, minutes, 0.08, True, start_hour, 1)
    n = len(ts)
    buf.add(ts, net.admin, r.choice(net.servers, n), r.choice([3389, 22, 5985, 445], n),
            bytes_fwd=lognorm(20000, 1.2, n), bytes_bwd=lognorm(200000, 1.4, n),
            dur=lognorm(300, 1.0, n), ttl=128, win=64240)
    # internet background noise: single probes at the exposed hosts, 24/7
    ts, _ = _events(r, t0, minutes, 0.5, False, start_hour, 1)
    n = len(ts)
    src = _rand_public(r, n, [45, 80, 89, 92, 141, 162, 167, 185, 193, 194]) if n else []
    buf.add(ts, src, r.choice([net.web, net.gw], n), r.choice([22, 23, 80, 443, 445, 3389, 8080, 5900], n),
            kind=r.choice(["syn", "rej"], n), ttl=r.integers(38, 60, n), win=1024)

    # nightly jobs (hard negatives): backup to the cloud and an inventory scan
    for hh in range(int(minutes / 60) + 1):
        hour_of_day = (start_hour + hh) % 24
        tt = t0 + hh * 3600.0
        if int(hour_of_day) == 2 and r.random() < 0.7:
            m = int(r.integers(8, 20))
            ts = tt + np.sort(r.uniform(0, 1800, m))
            buf.add(ts, r.choice([net.fs, net.db, net.dc], m), net.backup, 445,
                    bytes_fwd=lognorm(3e8, 0.6, m), bytes_bwd=lognorm(20000, 0.5, m),
                    dur=lognorm(400, 0.4, m), ttl=64, win=64240)
            m = int(r.integers(10, 30))
            ts = tt + 1800 + np.sort(r.uniform(0, 3000, m))
            buf.add(ts, net.backup, net.cloud_backup, 443, bytes_fwd=lognorm(2e8, 0.5, m),
                    bytes_bwd=lognorm(40000, 0.5, m), dur=lognorm(300, 0.4, m), ttl=64, win=64240)
        if int(hour_of_day) == 3 and r.random() < 0.35:
            targets = net.internal
            m = len(targets) * len(LATERAL_PORTS)
            ts = tt + np.sort(r.uniform(0, 900, m))
            dst = np.repeat(targets, len(LATERAL_PORTS))
            port = np.tile(LATERAL_PORTS, len(targets))
            kind = np.where(r.random(m) < 0.3, "full", "rej")
            buf.add(ts, net.admin, dst, port, kind=kind, bytes_fwd=200, bytes_bwd=400, dur=0.05,
                    ttl=128, win=64240)


# --------------------------------------------------------------------------- #
# attack campaigns
# --------------------------------------------------------------------------- #
class Campaign:
    def __init__(self, buf: FlowBuffer, net: Network, template: str, t0: float):
        self.buf, self.net, self.template, self.t = buf, net, template, t0
        self.rng = net.rng
        self.phases: list[dict] = []
        self.attacker = _rand_public(self.rng, 1, [5, 31, 45, 77, 91, 185, 193, 194])[0]
        self.c2 = _rand_public(self.rng, 1, [37, 46, 95, 176, 188, 212])[0]
        self.hosts: set[str] = set()

    def lab(self, stage, what):
        return f"stage:{stage}:{self.template}:{what}"

    def phase(self, stage, start, end):
        self.phases.append({"stage": int(stage), "start": float(start), "end": float(end)})

    # ---- building blocks
    def port_scan(self, src, dst_hosts, ports, t, dur, stage, sequential=True, open_ports=(), ttl=None,
                  win=1024, frag_p=0.0, what="port_scan"):
        r = self.rng
        dst_hosts = list(np.atleast_1d(dst_hosts))
        ports = list(ports)
        if not sequential:
            ports = list(r.permutation(ports))
        pairs = [(h, p) for h in dst_hosts for p in ports]
        m = len(pairs)
        ts = t + np.sort(r.uniform(0, dur, m)) if not sequential else t + np.linspace(0, dur, m) + r.uniform(0, dur / max(m, 1) * 0.3, m)
        dst = [h for h, _ in pairs]
        dp = [p for _, p in pairs]
        kind = np.array(["full" if p in open_ports else ("rej" if r.random() < 0.6 else "syn") for p in dp])
        ttlv = ttl if ttl is not None else r.integers(37, 63, m)
        frag = np.where(r.random(m) < frag_p, 2, 0)
        self.buf.add(ts, src, dst, dp, kind=kind, bytes_fwd=np.where(kind == "full", 60, 0),
                     bytes_bwd=np.where(kind == "full", 300, 0), dur=0.02, ttl=ttlv, win=win, frag=frag,
                     label=self.lab(stage, what), stage=stage, iat_cv=0.1)
        self.hosts.update(dst_hosts)
        return t + dur

    def http_enum(self, src, dst, t, dur, rate):
        r = self.rng
        m = max(1, int(dur / 60 * rate))
        ts = t + np.sort(r.uniform(0, dur, m))
        self.buf.add(ts, src, dst, r.choice([80, 443], m), bytes_fwd=r.integers(150, 400, m),
                     bytes_bwd=r.integers(200, 700, m), dur=r.uniform(0.01, 0.2, m), ttl=r.integers(45, 55),
                     win=29200, label=self.lab(RECON, "http_enum"), stage=RECON, iat_cv=0.2)
        return t + dur

    def beacons(self, src, t, t_end, period, jitter, port=443, stage=C2):
        r = self.rng
        if t_end <= t:
            return
        k = int((t_end - t) / period) + 1
        ts = t + np.arange(k) * period + r.normal(0, jitter * period, k)
        ts = ts[(ts >= t) & (ts < t_end)]
        m = len(ts)
        big = r.random(m) < 0.1
        self.buf.add(ts, src, self.c2, port, bytes_fwd=np.where(big, r.integers(5000, 60000, m), r.integers(200, 700, m)),
                     bytes_bwd=np.where(big, r.integers(2000, 20000, m), r.integers(100, 1500, m)),
                     dur=r.uniform(0.05, 0.8, m), ttl=128 if src.startswith("10.10.1.") else 64,
                     win=64240, label=self.lab(stage, "beacon"), stage=stage, iat_cv=0.2)

    def sessions(self, src, dsts, ports, t, dur, count, stage, what, bytes_fwd=5000, bytes_bwd=20000, sess_dur=30):
        r = self.rng
        ts = t + np.sort(r.uniform(0, dur, count))
        dst = r.choice(dsts, count)
        self.buf.add(ts, src, dst, r.choice(ports, count), bytes_fwd=bytes_fwd * np.exp(r.normal(0, 0.8, count)),
                     bytes_bwd=bytes_bwd * np.exp(r.normal(0, 0.8, count)),
                     dur=sess_dur * np.exp(r.normal(0, 0.7, count)),
                     ttl=128 if src.startswith("10.10.1.") else 64, win=64240,
                     label=self.lab(stage, what), stage=stage)
        self.hosts.update(dsts)
        return t + dur

    def exfil(self, src, dst, t, dur, total_bytes, chunks, port=443):
        r = self.rng
        ts = t + np.sort(r.uniform(0, dur, chunks))
        per = total_bytes / chunks * np.exp(r.normal(0, 0.3, chunks))
        self.buf.add(ts, src, dst, port, bytes_fwd=per, bytes_bwd=per * 0.01, dur=per / 2e6 + r.uniform(1, 5, chunks),
                     ttl=64, win=64240, label=self.lab(EXFIL, "upload"), stage=EXFIL)
        return t + dur

    def dns_tunnel(self, src, t, dur, rate):
        r = self.rng
        m = max(1, int(dur / 60 * rate))
        ts = t + np.sort(r.uniform(0, dur, m))
        self.buf.add(ts, src, self.c2, 53, kind="udp", bytes_fwd=r.integers(180, 255, m),
                     bytes_bwd=r.integers(80, 200, m), dur=r.uniform(0.01, 0.1, m), ttl=64,
                     label=self.lab(EXFIL, "dns_tunnel"), stage=EXFIL)
        return t + dur

    # ---- templates
    def run(self) -> dict:
        getattr(self, "_" + self.template)()
        return {"template": self.template, "attacker": self.attacker, "c2": self.c2,
                "phases": self.phases, "hosts": sorted(self.hosts)}

    def _web_exploit(self):
        r, n, t = self.rng, self.net, self.t
        # reconnaissance
        s = t
        ports = list(range(1, int(r.integers(200, 1200))))
        t = self.port_scan(self.attacker, n.web, ports, t, r.uniform(120, 900), RECON,
                           sequential=r.random() < 0.5, open_ports=(80, 443), frag_p=0.1 * (r.random() < 0.3))
        t += r.uniform(60, 600)
        t = self.http_enum(self.attacker, n.web, t, r.uniform(300, 1200), r.uniform(20, 80))
        self.phase(RECON, s, t)
        t += r.uniform(120, 1200)
        # initial access: exploit + reverse shell + tool download
        s = t
        m = int(r.integers(5, 30))
        ts = t + np.sort(r.uniform(0, 300, m))
        self.buf.add(ts, self.attacker, n.web, 443, bytes_fwd=r.integers(2000, 50000, m), bytes_bwd=r.integers(300, 3000, m),
                     dur=r.uniform(0.1, 2, m), ttl=r.integers(45, 55), win=29200,
                     label=self.lab(INITIAL_ACCESS, "exploit"), stage=INITIAL_ACCESS)
        t += 300
        self.buf.add([t], n.web, self.attacker, int(r.choice([4444, 443, 8443])), bytes_fwd=40000, bytes_bwd=15000,
                     dur=r.uniform(300, 900), ttl=64, win=29200, label=self.lab(INITIAL_ACCESS, "reverse_shell"),
                     stage=INITIAL_ACCESS)
        self.buf.add([t + 60], n.web, self.attacker, 80, bytes_fwd=800, bytes_bwd=r.uniform(5e5, 5e6), dur=8, ttl=64,
                     win=29200, label=self.lab(INITIAL_ACCESS, "tool_download"), stage=INITIAL_ACCESS)
        t += r.uniform(120, 600)
        self.phase(INITIAL_ACCESS, s, t)
        self.hosts.add(n.web)
        self._post_compromise(n.web, t, lm_targets=[n.db, n.fs, n.dc], exfil_src=n.db)

    def _post_compromise(self, foothold, t, lm_targets, exfil_src, slow=False):
        r, n = self.rng, self.net
        period = r.uniform(20, 120) if not slow else r.uniform(300, 900)
        c2_start = t
        t += r.uniform(300, 1800) if not slow else r.uniform(1800, 3600)
        # lateral movement: internal discovery then sessions to high-value hosts
        s = t
        if not slow:
            targets = r.choice(n.internal, int(r.integers(12, len(n.internal))), replace=False)
            t = self.port_scan(foothold, targets, LATERAL_PORTS, t, r.uniform(120, 600), LATERAL,
                               sequential=r.random() < 0.5, open_ports=(445, 3389, 22, 5985), ttl=64 if not foothold.startswith("10.10.1.") else 128,
                               win=64240, what="internal_discovery")
            t = self.sessions(foothold, lm_targets, [445, 5985, 3389, 135], t, r.uniform(600, 2400),
                              int(r.integers(15, 60)), LATERAL, "remote_services")
            pivot = lm_targets[0]
            t = self.sessions(pivot, [n.dc, n.fs], [445, 135, 389], t, r.uniform(300, 1200),
                              int(r.integers(10, 40)), LATERAL, "pivot")
        else:
            targets = list(r.choice(lm_targets, len(lm_targets), replace=False))
            dur = r.uniform(3600, 7200)
            t = self.sessions(foothold, targets, [445, 5985, 3389], t, dur, int(r.integers(8, 20)), LATERAL,
                              "slow_remote_services")
        self.phase(LATERAL, s, t)
        t += r.uniform(300, 1500)
        # exfiltration
        s = t
        if r.random() < 0.3 and not slow:
            t = self.dns_tunnel(exfil_src, t, r.uniform(600, 1800), r.uniform(40, 200))
        elif slow:
            t = self.exfil(exfil_src, self.c2, t, r.uniform(2400, 5400), r.uniform(5e7, 3e8), int(r.integers(15, 40)))
        else:
            # stage to the foothold, then out
            self.buf.add([t], exfil_src, foothold, 445, bytes_fwd=r.uniform(1e8, 6e8), bytes_bwd=30000, dur=300, ttl=64,
                          win=64240, label=self.lab(EXFIL, "staging"), stage=EXFIL)
            t = self.exfil(foothold, self.c2, t + 320, r.uniform(600, 2400), r.uniform(2e8, 1.5e9), int(r.integers(5, 25)))
        self.phase(EXFIL, s, t)
        # beacons persist through the whole post-compromise period
        self.beacons(foothold, c2_start, t + r.uniform(0, 1800), period, r.uniform(0.02, 0.35) if not slow else 0.4)
        self.phase(C2, c2_start, t)

    def _phishing(self):
        r, n, t = self.rng, self.net, self.t
        victim = str(r.choice(n.ws))
        s = t
        self.buf.add([t], victim, self.attacker, 443, bytes_fwd=900, bytes_bwd=r.uniform(2e5, 5e6), dur=r.uniform(1, 10),
                     ttl=128, win=64240, label=self.lab(INITIAL_ACCESS, "payload_download"), stage=INITIAL_ACCESS)
        self.buf.add([t + r.uniform(20, 120)], victim, self.c2, 443, bytes_fwd=3000, bytes_bwd=90000, dur=5, ttl=128,
                     win=64240, label=self.lab(INITIAL_ACCESS, "first_callback"), stage=INITIAL_ACCESS)
        t += 150
        self.phase(INITIAL_ACCESS, s, t)
        self.hosts.add(victim)
        self._post_compromise(victim, t, lm_targets=[n.fs, n.dc, str(r.choice(n.ws))], exfil_src=n.fs)

    def _bruteforce(self, succeed=True):
        r, n, t = self.rng, self.net, self.t
        target = n.gw
        s = t
        t = self.port_scan(self.attacker, [n.gw, n.web], [21, 22, 23, 25, 80, 443, 445, 3389, 5900, 8080], t,
                           r.uniform(60, 600), RECON, sequential=False, open_ports=(22, 80, 443))
        t += r.uniform(60, 900)
        # brute force: many short authenticated-looking sessions that fail
        dur = r.uniform(600, 2400)
        m = int(dur / 60 * r.uniform(8, 50))
        ts = t + np.sort(r.uniform(0, dur, m))
        kind = np.where(r.random(m) < 0.8, "full", "rst")
        self.buf.add(ts, self.attacker, target, 22, kind=kind, bytes_fwd=r.integers(1200, 2600, m),
                     bytes_bwd=r.integers(1800, 3200, m), dur=r.uniform(0.5, 4, m), ttl=r.integers(44, 52),
                     win=29200, label=self.lab(RECON, "ssh_bruteforce"), stage=RECON, iat_cv=0.3)
        t += dur
        self.phase(RECON, s, t)
        if not succeed:
            return
        s = t
        self.buf.add([t + 5], self.attacker, target, 22, bytes_fwd=60000, bytes_bwd=900000, dur=r.uniform(600, 1800),
                     ttl=48, win=29200, label=self.lab(INITIAL_ACCESS, "valid_login"), stage=INITIAL_ACCESS)
        self.buf.add([t + 90], target, self.attacker, 80, bytes_fwd=700, bytes_bwd=r.uniform(1e6, 8e6), dur=10, ttl=64,
                     win=29200, label=self.lab(INITIAL_ACCESS, "tool_download"), stage=INITIAL_ACCESS)
        t += 200
        self.phase(INITIAL_ACCESS, s, t)
        self.hosts.add(target)
        self._post_compromise(target, t, lm_targets=[n.jump, n.db, n.fs], exfil_src=n.db)

    def _failed_attack(self):
        if self.rng.random() < 0.5:
            self._bruteforce(succeed=False)
        else:
            r, n, t = self.rng, self.net, self.t
            s = t
            t = self.port_scan(self.attacker, n.web, list(range(1, int(r.integers(200, 1500)))), t, r.uniform(120, 900),
                               RECON, sequential=r.random() < 0.5, open_ports=(80, 443))
            t = self.http_enum(self.attacker, n.web, t + r.uniform(60, 600), r.uniform(300, 1500), r.uniform(20, 80))
            self.phase(RECON, s, t)

    def _slow_apt(self):
        r, n, t = self.rng, self.net, self.t
        s = t
        # low-and-slow distributed recon: one probe every 30-120 s from several IPs
        dur = r.uniform(3600, 7200)
        m = int(dur / r.uniform(30, 120))
        ts = t + np.sort(r.uniform(0, dur, m))
        srcs = _rand_public(r, 5, [5, 31, 45, 77, 91, 185])
        self.buf.add(ts, r.choice(srcs, m), r.choice([n.web, n.gw], m), r.integers(1, 10000, m),
                     kind=r.choice(["syn", "rej"], m), ttl=r.integers(37, 63, m), ttl_std=r.uniform(0, 3, m), win=1024,
                     frag=np.where(r.random(m) < 0.3, 2, 0), label=self.lab(RECON, "slow_scan"), stage=RECON)
        t += dur
        self.phase(RECON, s, t)
        t += r.uniform(600, 3600)
        s = t
        self.buf.add([t], self.attacker, n.web, 443, bytes_fwd=r.uniform(3000, 30000), bytes_bwd=2000, dur=1, ttl=50,
                     win=29200, label=self.lab(INITIAL_ACCESS, "exploit"), stage=INITIAL_ACCESS)
        t += 60
        self.phase(INITIAL_ACCESS, s, t)
        self.hosts.add(n.web)
        self._post_compromise(n.web, t, lm_targets=[n.db, n.fs], exfil_src=n.web, slow=True)

    def _ddos(self):
        r, n, t = self.rng, self.net, self.t
        s = t
        dur = r.uniform(300, 1200)
        m = int(dur * r.uniform(20, 60))
        ts = t + np.sort(r.uniform(0, dur, m))
        bots = _rand_public(r, 300, [1, 14, 27, 36, 39, 58, 61, 101, 110, 112, 175, 177, 186, 187, 189, 190, 200, 201])
        self.buf.add(ts, r.choice(bots, m), n.web, r.choice([80, 443], m), kind=r.choice(["syn", "syn", "full"], m),
                     bytes_fwd=r.integers(0, 200, m), bytes_bwd=r.integers(0, 400, m), dur=r.uniform(0, 0.5, m),
                     ttl=r.integers(40, 120, m), win=r.choice([512, 1024, 8192, 65535], m),
                     label=self.lab(IMPACT, "syn_flood"), stage=IMPACT, iat_cv=0.1)
        self.phase(IMPACT, s, t + dur)


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #
def generate_scenario(seed: int, hours: float = 12.0, templates=None, n_campaigns=None,
                      start_epoch: float = 1772409600.0, campaigns=None,
                      background_scan: bool | None = None, n_workstations: int | None = None,
                      start_hour: float | None = None) -> tuple[pd.DataFrame, dict]:
    """Return (flows, metadata) for one scenario.

    templates: list of allowed campaign templates (default: all).
    n_campaigns: fixed number of campaigns, or None for a random 0-2.
    campaigns: explicit list of templates to play, in order (overrides the above).
    """
    rng = np.random.default_rng(seed)
    templates = list(templates or TEMPLATES)
    net = Network(rng, n_ws=int(rng.integers(18, 40)) if n_workstations is None else int(n_workstations))
    start_hour = float(rng.integers(0, 24)) if start_hour is None else float(start_hour)
    t0 = start_epoch + (seed % 300) * 86400.0 + start_hour * 3600.0
    minutes = int(hours * 60)
    buf = FlowBuffer(rng)
    _benign(buf, net, t0, minutes, start_hour)

    # a burst scan from the internet that is never followed up (labelled recon)
    if (rng.random() < 0.45) if background_scan is None else background_scan:
        c = Campaign(buf, net, "background_scanner", t0 + rng.uniform(0, minutes * 60 - 1800))
        c.port_scan(c.attacker, net.web, range(1, int(rng.integers(300, 2000))), c.t, rng.uniform(60, 300), RECON,
                    sequential=rng.random() < 0.5, open_ports=(80, 443), what="internet_scanner")

    if n_campaigns is None:
        n_campaigns = int(rng.choice([0, 1, 1, 1, 2, 2]))
    weights = np.array([DEFAULT_TEMPLATE_WEIGHTS.get(t, 0.1) for t in templates], dtype=float)
    weights /= weights.sum()
    chosen = list(campaigns) if campaigns else [str(rng.choice(templates, p=weights)) for _ in range(n_campaigns)]
    n_campaigns = len(chosen)
    campaigns = []
    span = minutes * 60.0
    for k, tpl in enumerate(chosen):
        lo = span * (0.08 + 0.45 * k / max(n_campaigns, 1))
        hi = span * (0.25 + 0.45 * k / max(n_campaigns, 1))
        start = t0 + rng.uniform(lo, hi)
        campaigns.append(Campaign(buf, net, tpl, start).run())

    flows = buf.frame()
    t_end = t0 + span
    flows = flows[(flows["ts"] >= t0) & (flows["ts"] < t_end)]
    flows = finalise(flows)
    meta = {"seed": seed, "hours": hours, "t0": t0, "t_end": t_end, "campaigns": campaigns,
            "internal_prefixes": ["10.10.0.0/16"], "n_workstations": net.n_ws}
    return flows, meta


def generate_dataset(out_dir, n_scenarios=40, hours=12.0, seed0=0, templates=None, n_campaigns=None,
                     compress=True, verbose=True, campaigns=None, workers: int | None = None) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    jobs = [(out, seed0 + i, hours, templates, n_campaigns, campaigns, compress) for i in range(n_scenarios)]
    workers = max(1, min(workers or os.cpu_count() or 1, n_scenarios))
    if workers > 1:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(workers) as ex:
            results = list(ex.map(_one_scenario, jobs))
    else:
        results = [_one_scenario(j) for j in jobs]
    for p, seed, n, tpls in results:
        if verbose:
            print(f"  scenario {seed:4d}: {n:7d} flows  [{tpls}]")
    return [r[0] for r in results]


def _one_scenario(job):
    out, seed, hours, templates, n_campaigns, campaigns, compress = job
    flows, meta = generate_scenario(seed, hours=hours, templates=templates, n_campaigns=n_campaigns, campaigns=campaigns)
    p = out / (f"scenario_{seed:04d}.csv" + (".gz" if compress else ""))
    write_flows(flows, p)
    (out / f"scenario_{seed:04d}.meta.json").write_text(json.dumps(meta, indent=1))
    return p, seed, len(flows), ",".join(c["template"] for c in meta["campaigns"]) or "benign-only"


def write_flows(flows: pd.DataFrame, path) -> None:
    """CSV with sensible precision (keeps files small)."""
    f = flows.copy()
    f["ts"] = f["ts"].round(4)
    for c in ("duration", "iat_mean", "iat_std", "iat_max"):
        f[c] = f[c].round(5)
    for c in ("bytes_fwd", "bytes_bwd", "payload_mean", "payload_std", "ttl_mean", "win_mean"):
        f[c] = f[c].round(1)
    f["ttl_std"] = f["ttl_std"].round(3)
    f.to_csv(path, index=False)
