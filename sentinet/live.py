"""Live monitoring: stream traffic window by window and forecast as it arrives.

Sources
  SimSource      a simulated enterprise network generated on the fly. Attacks can be launched on
                 demand (or on a schedule for demos) and hosts can be isolated - the simulator then
                 really stops that host's traffic, so a defensive action changes the future.
  ReplaySource   any PCAP / CSV replayed as if it were live (accelerated).
  CaptureSource  real packets from a network interface (Scapy; needs admin rights / Npcap on
                 Windows, root on Linux). Flows are exported once per window.

LiveEngine keeps the last few hours of windows, re-runs the world model each step, stores the
forecast for every new window, raises alerts (with explanation, ATT&CK technique and mitigation)
when an alarm starts, and keeps a Merkle root over every forecast it has issued.
"""
from __future__ import annotations

import math
import os
import threading
import time
from collections import deque

import numpy as np
import pandas as pd
import torch

from .engine import Forecaster, Result
from .features.windows import FEATURE_NAMES, featurize, make_internal_fn
from .io.loaders import is_labelled, load
from .ledger import leaf_hash, merkle_root
from .schema import finalise
from .stages import INFILTRATION, STAGES
from .synth.generator import Campaign, FlowBuffer, Network, _benign


def console(kind: str, text: str, ts: float | None = None):
    """Mirror live events to the terminal that started the app (`python -m sentinet app` shows them)."""
    if os.environ.get("SENTINET_CONSOLE"):
        clock = pd.to_datetime(ts, unit="s").strftime("%H:%M") if ts is not None else ""
        print(f"SENTINET|{kind}|{clock}|{text}", flush=True)

SIM_EPOCH = 1772438400.0  # 2026-03-02 08:00 UTC


# ------------------------------------------------------------------ sources
class SimSource:
    kind = "sim"
    labelled = True

    def __init__(self, seed: int = 7, n_workstations: int = 20, start_hour: float = 8.0, chunk_hours: float = 2.0):
        self.rng = np.random.default_rng(seed)
        self.net = Network(self.rng, n_ws=n_workstations)
        self.t0 = SIM_EPOCH + (start_hour - 8.0) * 3600
        self.start_hour = start_hour
        self.chunk_s = chunk_hours * 3600
        self.benign = pd.DataFrame()
        self.gen_until = self.t0
        self.pending: list[pd.DataFrame] = []
        self.campaigns: list[dict] = []
        self.blocked: dict[str, float] = {}
        self.events: list[dict] = []
        self._extend(self.t0 + self.chunk_s)

    def _extend(self, until: float):
        while self.gen_until < until:
            buf = FlowBuffer(self.rng)
            hour = self.start_hour + (self.gen_until - self.t0) / 3600
            _benign(buf, self.net, self.gen_until, int(self.chunk_s / 60), hour)
            df = buf.frame()
            df = finalise(df[(df["ts"] >= self.gen_until) & (df["ts"] < self.gen_until + self.chunk_s)])
            keep = self.benign[self.benign["ts"] >= self.gen_until - 6 * 3600] if len(self.benign) else self.benign
            self.benign = pd.concat([keep, df], ignore_index=True)
            self.gen_until += self.chunk_s

    def available(self, t_end: float) -> bool:
        return True

    def launch(self, template: str, at: float) -> dict:
        buf = FlowBuffer(self.rng)
        meta = Campaign(buf, self.net, template, at).run()
        df = buf.frame()
        if len(df):
            self.pending.append(finalise(df))
        meta["launched_at"] = at
        self.campaigns.append(meta)
        self.events.append({"ts": at, "kind": "attack", "text": f"attack launched: {template} (attacker {meta['attacker']})"})
        console("attack", f"attack started: {template} from {meta['attacker']}", at)
        return meta

    def isolate(self, ip: str, at: float):
        self.blocked[ip] = at
        self.events.append({"ts": at, "kind": "action", "text": f"host isolated: {ip}"})
        # an attack that still needs this host (its entry point / pivot) cannot continue after it is isolated
        for i, d in enumerate(self.pending):
            later = d["ts"] >= at
            if ((later & ((d["src_ip"] == ip) | (d["dst_ip"] == ip))) & (d["stage"] > 0)).any():
                self.pending[i] = d[~later]
                self.events.append({"ts": at, "kind": "action", "text": f"attack chain broken: {self.campaigns[i]['template']}"})
                console("action", f"attack chain broken: {self.campaigns[i]['template']} can no longer continue", at)

    def flows(self, a: float, b: float) -> pd.DataFrame:
        self._extend(b)
        parts = [d[(d["ts"] >= a) & (d["ts"] < b)] for d in [self.benign] + self.pending]
        df = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame()
        for ip, since in self.blocked.items():
            if since < b:
                hit = ((df["src_ip"] == ip) | (df["dst_ip"] == ip)) & (df["ts"] >= since)
                df = df[~hit]
        return df.sort_values("ts", kind="mergesort").reset_index(drop=True)


class ReplaySource:
    kind = "replay"

    def __init__(self, path, fmt: str = "auto", labels=None, window: float = 60.0):
        self.df = load(path, fmt, labels=labels)
        self.labelled = is_labelled(self.df)
        self.t0 = float(np.floor(self.df["ts"].min() / window) * window)
        self.t_last = float(self.df["ts"].max())
        self.events: list[dict] = []
        self.blocked: dict[str, float] = {}

    def available(self, t_end: float) -> bool:
        return t_end - 60 <= self.t_last

    def isolate(self, ip: str, at: float):
        self.blocked[ip] = at
        self.events.append({"ts": at, "kind": "action", "text": f"host isolated (replay: traffic removed): {ip}"})

    def flows(self, a: float, b: float) -> pd.DataFrame:
        d = self.df
        df = d[(d["ts"] >= a) & (d["ts"] < b)]
        for ip, since in self.blocked.items():
            df = df[~(((df["src_ip"] == ip) | (df["dst_ip"] == ip)) & (df["ts"] >= since))]
        return df.reset_index(drop=True)


class CaptureSource:
    """Live packets from an interface. Each window, every open flow is exported (active timeout = window)."""
    kind = "capture"
    labelled = False

    def __init__(self, iface: str | None = None, bpf: str = "ip or ip6", window: float = 60.0):
        from scapy.all import IP, IPv6, AsyncSniffer  # imported lazily: needs capture rights
        from .io.pcap import FlowAssembler
        self.asm = FlowAssembler(idle_timeout=window, active_timeout=window)
        self.lock = threading.Lock()
        self.IP, self.IPv6 = IP, IPv6
        self.window = window
        self.t0 = float(np.floor(time.time() / window) * window)
        self.events: list[dict] = []
        self.blocked: dict[str, float] = {}
        self.packets = 0
        self.sniffer = AsyncSniffer(iface=iface, filter=bpf, prn=self._pkt, store=False)
        self.sniffer.start()

    def _pkt(self, pkt):
        layer, lt = (pkt[self.IP], 228) if self.IP in pkt else ((pkt[self.IPv6], 229) if self.IPv6 in pkt else (None, 0))
        if layer is None:
            return
        data = bytes(layer)
        with self.lock:
            self.asm.add(float(pkt.time), lt, data, len(data))
            self.packets += 1

    def available(self, t_end: float) -> bool:
        return time.time() >= t_end

    def isolate(self, ip: str, at: float):
        self.events.append({"ts": at, "kind": "action", "text": f"recommended: isolate {ip} (passive sensor - not enforced)"})

    def flows(self, a: float, b: float) -> pd.DataFrame:
        from .io.pcap import FlowAssembler
        with self.lock:
            rows = self.asm.drain()
        df = FlowAssembler.to_frame(rows) if rows else pd.DataFrame(columns=["ts"])
        if len(df):
            df["ts"] = df["ts"].clip(lower=a, upper=b - 1e-3)
        return df

    def stop(self):
        try:
            self.sniffer.stop()
        except Exception:  # noqa: BLE001
            pass


def list_interfaces() -> list[str]:
    try:
        from scapy.all import get_if_list
        return list(get_if_list())
    except Exception:  # noqa: BLE001
        return []


# ------------------------------------------------------------------ engine
KEY_FEATURES = ["log_flows", "syn_only_ratio", "failed_conn_ratio", "log_max_ports_per_src", "seq_port_score",
                "low_win_ratio", "ttl_std", "lateral_port_ratio", "new_edge_ratio", "beacon_score",
                "log_periodic_pairs", "out_ext_byte_ratio", "log_max_out_bytes", "dns_ratio", "inbound_ext_ratio"]


class LiveEngine:
    def __init__(self, fc: Forecaster, source, keep_windows: int = 180, samples: int = 32):
        self.fc, self.src = fc, source
        self.W = float(fc.cfg["window"])
        self.t = float(np.floor(source.t0 / self.W) * self.W)
        self.start = self.t
        self.keep = keep_windows
        self.samples = samples
        self.buf: deque = deque(maxlen=keep_windows)
        self.rows: list[dict] = []
        self.alerts: list[dict] = []
        self.leaves: list[bytes] = []
        self.latest: dict = {}
        self.lock = threading.Lock()
        self.inside = make_internal_fn()
        self.flow_total = 0
        self.step_ms = 0.0
        self.contained: set[str] = set()

    def contain(self, ip: str):
        """Isolate a host. With a simulated/replayed network the host's traffic really stops, and it also leaves
        the network state the model forecasts on (a quarantined host is no longer part of the live network).
        A passive live capture cannot enforce it, so there it stays a recommendation."""
        console("action", f"host isolated: {ip}" + (" (recommendation only: passive sensor)" if self.src.kind == "capture"
                                                     else ""), self.t)
        self.src.isolate(ip, self.t)
        if self.src.kind != "capture":
            self.contained.add(ip)

    @property
    def threshold(self):
        return self.fc.threshold

    def step(self, n: int = 1) -> int:
        """Advance by up to n windows; returns how many were processed."""
        t_first = time.time()
        added = 0
        for _ in range(n):
            if not self.src.available(self.t + self.W):
                break
            f = self.src.flows(self.t, self.t + self.W)
            self.buf.append((self.t, f))
            self.t += self.W
            added += 1
            self.flow_total += len(f)
        if not added:
            return 0
        frames = [f for _, f in self.buf if len(f)]
        if not frames:
            for k in range(added):
                self._store_empty(self.t - (added - k) * self.W)
            return added
        allf = pd.concat(frames, ignore_index=True)
        if self.contained:
            allf = allf[~(allf["src_ip"].isin(self.contained) | allf["dst_ip"].isin(self.contained))]
            if not len(allf):
                allf = frames[-1].iloc[:0]
        t_start = self.buf[0][0]
        labelled = bool(getattr(self.src, "labelled", False))
        wd = featurize(allf, window=self.W, max_nodes=self.fc.cfg["max_nodes"], t0=t_start, t_end=self.t,
                       labelled=labelled)
        with torch.no_grad():
            r = self.fc.run_windows(wd, samples=self.samples)
            fan = self.fc.model.rollout(r["_c"][-1:], samples=64)["p_infil_by_k"][0].numpy()
        res = Result(self.fc, allf, wd, r)
        tb = res.table
        T = len(tb)
        with self.lock:
            for k in range(added):
                i = T - added + k
                row = tb.iloc[i].to_dict()
                row["warming_up"] = (len(self.rows) < 10)
                if row["warming_up"]:
                    row["alarm"] = False
                self.rows.append(row)
                self.leaves.append(leaf_hash({"window": len(self.rows) - 1, "time": str(row["time"]),
                                              "p": round(float(row["p_infiltration"]), 6), "stage": row["stage_forecast"]}))
            last = T - 1
            hosts = res.hosts(last, 12)
            prev_alarm = len(self.rows) > added and self.rows[-added - 1]["alarm"]
            alert = None
            if self.rows[-1]["alarm"] and not prev_alarm:
                ex = res.explain(last)
                alert = {"time": self.rows[-1]["time"], "p": float(self.rows[-1]["p_infiltration"]),
                         "stage": self.rows[-1]["stage_forecast"], "narrative": ex["narrative"],
                         "techniques": (ex.get("techniques_observed") or
                                        self._context_techniques(allf, wd, r, last, t_start))[:3],
                         "expected": ex.get("techniques_expected", [])[:3],
                         "host": next((h["host"] for h in ex.get("hosts", []) if h.get("internal")), None),
                         "groups": ex["groups"][:4]}
                self.alerts.insert(0, alert)
                tech = alert["techniques"][0] if alert["techniques"] else None
                console("alert", f"{alert['p']:.0%} infiltration within {len(r['p_by_k'][last])} min · forecast "
                                 f"{alert['stage']}" + (f" · target {alert['host']}" if alert["host"] else "")
                        + (f" · {tech['technique']} {tech['name']}" if tech else ""), self.t - self.W)
            zs = pd.DataFrame(r["seq"].X[-60:], columns=FEATURE_NAMES)[KEY_FEATURES]
            self.latest = {
                "p_by_k": r["p_by_k"][last], "fan": fan, "stage_future": r["stage_future"][last],
                "stage_now": r["stage_now"][last], "hosts": hosts, "node_ips": wd.node_ips[last],
                "node_risk": r["host_risk"][last][:len(wd.node_ips[last])], "adj": wd.adj[last],
                "flagged": res.flagged_flows(last, 12), "z": zs, "times": tb["time"].iloc[-60:].tolist(),
                "flows_in_window": int(wd.n_flows[last]), "n_windows_ctx": T,
                "merkle_root": merkle_root(self.leaves).hex(), "features_now": dict(zip(FEATURE_NAMES, wd.X[last])),
            }
        self.step_ms = (time.time() - t_first) * 1000
        return added

    def _context_techniques(self, flows, wd, r, last, t_start, n=30):
        """ATT&CK evidence from the minutes the model looked at (the alarm minute itself may be quiet). Only
        techniques of the stage the model believed each minute was in count, most persistent first, so everyday
        traffic that happens to match a rule (office SMB, downloads) is not reported as the attack."""
        from .knowledge import observed
        seen, count = {}, {}
        for t in range(max(0, last - n + 1), last + 1):
            f = flows[wd.flow_window == t]
            stage_t = STAGES[int(np.argmax(r["stage_now"][t]))]
            if not len(f) or stage_t == "Benign":
                continue
            raw = dict(zip(FEATURE_NAMES, wd.X[t].tolist()))
            z = dict(zip(FEATURE_NAMES, r["seq"].X[t].tolist()))
            when = pd.to_datetime(t_start + t * self.W, unit="s").strftime("%H:%M")
            for o in observed(raw, f, self.inside, z):
                if o["stage"] == stage_t:
                    seen[o["technique"]] = dict(o, evidence=f"{when}: {o['evidence']}")
                    count[o["technique"]] = count.get(o["technique"], 0) + 1
        return sorted(seen.values(), key=lambda o: -count[o["technique"]])

    def _store_empty(self, t):
        with self.lock:
            self.rows.append({"time": pd.to_datetime(t, unit="s"), "flows": 0, "p_infiltration": 0.0, "p_low": 0.0,
                              "p_high": 0.0, "alarm": False, "stage_now": "Benign", "stage_forecast": "Benign",
                              "warming_up": True})

    def table(self) -> pd.DataFrame:
        with self.lock:
            return pd.DataFrame(self.rows[-self.keep * 4:])


class LiveRunner:
    """Background thread that keeps an engine stepping at `speed` windows per second (sim / replay)
    or whenever a real window completes (capture)."""

    def __init__(self, engine: LiveEngine, speed: float = 1.0):
        self.engine, self.speed = engine, speed
        self.running = False
        self.error = None
        self._thread = None
        self._stop = threading.Event()
        self.schedule: list[tuple[float, str, str]] = []   # (sim time, kind, arg)
        self.last_seen = time.time()                        # the dashboard updates this on every refresh
        self.idle_pause = 15.0                              # sim/replay pause when nobody is watching

    def start(self):
        if self._thread and self._thread.is_alive():
            self.running = True
            return
        self._stop.clear()
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def pause(self):
        self.running = False

    def stop(self):
        self.running = False
        self._stop.set()
        if hasattr(self.engine.src, "stop"):
            self.engine.src.stop()

    def _loop(self):
        acc = 0.0
        while not self._stop.is_set():
            t0 = time.time()
            idle = self.engine.src.kind != "capture" and time.time() - self.last_seen > self.idle_pause
            if self.running and not idle:
                try:
                    self._run_schedule()
                    if self.engine.src.kind == "capture":
                        self.engine.step(1)
                    else:
                        acc += self.speed
                        n = int(acc)
                        if n:
                            acc -= n
                            self.engine.step(n)
                except Exception as exc:  # noqa: BLE001 - surface in the UI instead of killing the thread
                    self.error = f"{type(exc).__name__}: {exc}"
                    self.running = False
            time.sleep(max(0.05, 1.0 - (time.time() - t0)))

    def _run_schedule(self):
        src, now = self.engine.src, self.engine.t
        due = [s for s in self.schedule if s[0] <= now]
        self.schedule = [s for s in self.schedule if s[0] > now]
        for _, kind, arg in due:
            if kind == "attack" and hasattr(src, "launch"):
                src.launch(arg, now)


def demo_schedule(t0: float) -> list[tuple[float, str, str]]:
    """Hands-free demo: 10 min of normal traffic, then a web intrusion (recon -> exploit -> C2 -> lateral -> exfil)."""
    return [(t0 + 10 * 60, "attack", "web_exploit")]
