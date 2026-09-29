"""Command line: python -m sentinet <command> ...

  app        start the offline web interface (Streamlit)
  forecast   run the world model on a PCAP / CSV and write a report
  extract    PCAP -> flow CSV (flow + packet-level features)
  generate   create synthetic multi-stage attack scenarios
  train      train the world model (+ logistic-regression baseline)
  benchmark  compare the world model with the baseline on labelled data
  verify     check a forecast receipt file (Merkle root + Ed25519 signature)
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def torch_threads():
    """One PyTorch process should not oversubscribe the CPU (spin-waiting threads slow everything down)."""
    import os
    import torch
    torch.set_num_threads(max(1, min(4, os.cpu_count() or 1)))


BANNER = r"""
   ____             _   _ _   _      _
  / ___|  ___ _ __ | |_(_) \ | | ___| |_
  \___ \ / _ \ '_ \| __| |  \| |/ _ \ __|
   ___) |  __/ | | | |_| | |\  |  __/ |_
  |____/ \___|_| |_|\__|_|_| \_|\___|\__|
"""


class _C:
    """ANSI colours (turned on for Windows 10+ consoles too)."""
    on = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
    RED, GREEN, YELLOW, BLUE, ORANGE = "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[38;5;208m"

    @classmethod
    def c(cls, text, *codes):
        return "".join(codes) + str(text) + cls.RESET if cls.on else str(text)


def _console_setup():
    if os.name == "nt":
        os.system("")                                     # enables ANSI escape codes in cmd.exe / PowerShell
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass


def _free_port(port: int) -> int:
    import socket
    for p in range(port, port + 50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if os.name != "nt":   # a port that was just closed (TIME_WAIT) is free to reuse
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    return port


def _check(label, detail, secs=None):
    t = _C.c(f" ({secs:.1f}s)", _C.DIM) if secs is not None else ""
    print(f"  {_C.c('[ok]', _C.GREEN, _C.BOLD)} {label:<17}{detail}{t}", flush=True)


_EVENT_STYLE = {"alert": ("ALERT ", "RED"), "attack": ("ATTACK", "YELLOW"), "action": ("ACTION", "BLUE"),
                "info": ("INFO  ", "GREEN")}


def _relay(proc, log_path):
    """Show SentiNet's live events; everything Streamlit prints goes to the log file."""
    with open(log_path, "w", encoding="utf-8") as log:
        for line in proc.stdout:
            if line.startswith("SENTINET|"):
                _, kind, clock, text = (line.rstrip("\n").split("|", 3) + ["", "", ""])[:4]
                tag, col = _EVENT_STYLE.get(kind, (kind.upper()[:6], "DIM"))
                print(f"  {_C.c(clock, _C.DIM)}  {_C.c(tag, getattr(_C, col), _C.BOLD)}  {text}", flush=True)
            else:
                log.write(line)
                log.flush()


def cmd_app(a):
    import tempfile
    import threading
    import time
    import urllib.request
    import webbrowser
    _console_setup()
    print(_C.c(BANNER, _C.ORANGE, _C.BOLD) + _C.c("  AI network attack forecasting  ·  world model  ·  SIH26153 (NTRO)\n", _C.BOLD))

    t = time.time()
    torch_threads()
    from .engine import Forecaster
    fc = Forecaster.load()
    n = sum(p.numel() for p in fc.model.parameters())
    _check("World model", f"{n:,} parameters · graph network + temporal Transformer + latent dynamics", time.time() - t)
    cfg = fc.cfg
    _check("Forecast", f"{cfg.get('samples', 64)} imagined futures x {cfg['horizon']} min ahead, every "
                       f"{cfg['window']:.0f} s · alarm at {fc.threshold:.0%}")
    _check("Explainability", "exact Shapley values · attention · MITRE ATT&CK / CAPEC knowledge base")
    _check("Integrity", "every forecast in an Ed25519-signed Merkle receipt")
    try:
        import logging
        import warnings
        warnings.filterwarnings("ignore")
        logging.getLogger("scapy").setLevel(logging.ERROR)
        from .live import list_interfaces
        nif = len(list_interfaces())
    except Exception:  # noqa: BLE001
        nif = 0
    _check("Traffic sources", "simulated network · replay PCAP/CSV · live capture"
           + (f" ({nif} interfaces found)" if nif else " (needs Npcap/admin rights)"))
    _check("Privacy", "100% offline: no cloud, no external API calls")

    port = _free_port(a.port)
    url = f"http://localhost:{port}"
    t = time.time()
    env = dict(os.environ, SENTINET_CONSOLE="1", PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    args = [sys.executable, "-m", "streamlit", "run", str(ROOT / "app.py"), "--server.port", str(port),
            "--server.headless", "true", "--browser.gatherUsageStats", "false", "--logger.level", "error"]
    proc = subprocess.Popen(args, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            encoding="utf-8", errors="replace", bufsize=1)
    log_path = Path(tempfile.gettempdir()) / "sentinet_app.log"
    threading.Thread(target=_relay, args=(proc, log_path), daemon=True).start()
    ready = False
    while time.time() - t < 120 and proc.poll() is None:
        try:
            ready = urllib.request.urlopen(f"http://127.0.0.1:{port}/_stcore/health", timeout=2).status == 200
        except Exception:  # noqa: BLE001
            ready = False
        if ready:
            break
        time.sleep(0.4)
    if not ready:
        print(_C.c("\n  The dashboard did not start. Details: ", _C.RED) + str(log_path))
        time.sleep(0.5)
        print(log_path.read_text(encoding="utf-8", errors="replace")[-3000:] if log_path.exists() else "")
        proc.terminate()
        raise SystemExit(1)
    _check("Dashboard", _C.c(url, _C.BOLD), time.time() - t)
    print(_C.c("\n  Live events appear below. Ctrl+C to stop.\n", _C.DIM), flush=True)
    if not a.headless:
        webbrowser.open(url)
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            proc.kill()
        print(_C.c("\n  SentiNet stopped.", _C.DIM))


def cmd_forecast(a):
    from .engine import Forecaster
    from .ledger import make_receipts
    from .report import write_report
    fc = Forecaster.load(a.weights)
    print(f"loading {a.input} ...")
    res = fc.run(a.input, fmt=a.format, labels=a.labels, samples=a.samples, assets=a.assets)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    res.table.to_csv(out / "forecast.csv", index=False)
    alarms = res.alarms()
    alarms.to_csv(out / "alarms.csv", index=False)
    # explain where alarms start (why did it fire?), then the riskiest remaining windows
    top = res.alarm_onsets(a.explain_top)
    for w in res.table.sort_values("p_infiltration", ascending=False)["window"].tolist():
        if len(top) >= a.explain_top:
            break
        if w not in top:
            top.append(int(w))
    explanations = {int(t): res.explain(int(t)) for t in top}
    flagged = [res.flagged_flows(int(t)).assign(window=int(t)) for t in top]
    if flagged:
        import pandas as pd
        pd.concat(flagged, ignore_index=True).to_csv(out / "flagged_flows.csv", index=False)
    (out / "explanations.json").write_text(json.dumps(explanations, indent=1, default=str))
    recs = [{"window": int(r.window), "time": str(r.time), "p_infiltration": round(float(r.p_infiltration), 6),
             "stage_forecast": r.stage_forecast, "alarm": bool(r.alarm)} for r in res.table.itertuples()]
    (out / "receipts.json").write_text(json.dumps(make_receipts(recs, source=str(a.input)), indent=1))
    write_report(res, explanations, out / "report.html", source=str(a.input))
    print(f"{len(res.table)} windows, {len(alarms)} alarm windows (threshold {fc.threshold:.2f}).")
    if len(alarms):
        first = alarms.iloc[0]
        print(f"first alarm: {first.time}  P={first.p_infiltration:.0%}  forecast stage: {first.stage_forecast}")
    print(f"wrote {out}/report.html, forecast.csv, alarms.csv, flagged_flows.csv, explanations.json, receipts.json")


def cmd_extract(a):
    from .io.pcap import pcap_to_csv
    df = pcap_to_csv(a.input, a.out)
    print(f"{df.attrs.get('packets', '?')} packets -> {len(df)} flows -> {a.out}")


def cmd_generate(a):
    from .synth.generator import generate_dataset
    tpl = a.templates.split(",") if a.templates else None
    camp = a.campaigns.split(",") if a.campaigns else None
    generate_dataset(a.out, n_scenarios=a.scenarios, hours=a.hours, seed0=a.seed, templates=tpl, campaigns=camp)


def cmd_train(a):
    from .train import train
    train(a.data, a.out, fmt=a.format, val_paths=a.val, epochs=a.epochs, steps_per_epoch=a.steps,
          batch_size=a.batch_size, window=a.window, horizon=a.horizon, context=a.context, seed=a.seed)


def cmd_benchmark(a):
    from .benchmark import run_benchmark, save_results, to_markdown
    from .engine import Forecaster
    fc = Forecaster.load(a.weights)
    torch_threads()
    res = run_benchmark(fc, a.data, fmt=a.format, samples=a.samples, name=a.name)
    prev = []
    jp = Path(a.out) / "benchmark.json"
    if a.append and jp.exists():
        prev = [r for r in json.loads(jp.read_text()) if r["name"] != a.name]
    save_results(prev + [res], a.out)
    print(to_markdown([res]))


def cmd_verify(a):
    from .ledger import verify_receipts
    ok, msg = verify_receipts(json.loads(Path(a.receipts).read_text()))
    print(("OK: " if ok else "FAILED: ") + msg)
    raise SystemExit(0 if ok else 1)


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m sentinet", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("app", help="start the web interface")
    s.add_argument("--port", type=int, default=8501)
    s.add_argument("--headless", action="store_true", help="do not open a browser")
    s.set_defaults(fn=cmd_app)

    s = sub.add_parser("forecast", help="forecast attacks in a PCAP or CSV")
    s.add_argument("--input", "-i", required=True)
    s.add_argument("--format", default="auto", choices=["auto", "sentinet", "cicflowmeter", "ctu13", "unsw", "pcap"])
    s.add_argument("--labels", help="optional rules CSV (start,end,ip,stage) to label a PCAP")
    s.add_argument("--assets", help="optional asset list CSV (ip,cvss[,cves]) - known vulnerabilities raise host risk")
    s.add_argument("--weights", default=None)
    s.add_argument("--out", "-o", default="report")
    s.add_argument("--samples", type=int, default=None, help="Monte-Carlo futures per window (default 64)")
    s.add_argument("--explain-top", type=int, default=5, help="explain N windows (alarm onsets first)")
    s.set_defaults(fn=cmd_forecast)

    s = sub.add_parser("extract", help="PCAP -> flow CSV")
    s.add_argument("--input", "-i", required=True)
    s.add_argument("--out", "-o", required=True)
    s.set_defaults(fn=cmd_extract)

    s = sub.add_parser("generate", help="synthetic multi-stage attack scenarios")
    s.add_argument("--out", "-o", default="data/synthetic")
    s.add_argument("--scenarios", type=int, default=48)
    s.add_argument("--hours", type=float, default=12)
    s.add_argument("--seed", type=int, default=0)
    s.add_argument("--templates", help="comma list, e.g. web_exploit,phishing,bruteforce,failed_attack,ddos")
    s.add_argument("--campaigns", help="explicit comma list of campaigns to play in every scenario")
    s.set_defaults(fn=cmd_generate)

    s = sub.add_parser("train", help="train the world model")
    s.add_argument("--data", "-d", nargs="+", required=True, help="files or folders (one capture per file)")
    s.add_argument("--val", nargs="+", default=None, help="validation files/folders (default: 20%% of --data)")
    s.add_argument("--format", default="auto")
    s.add_argument("--out", "-o", default="weights")
    s.add_argument("--epochs", type=int, default=None)
    s.add_argument("--steps", type=int, default=None, help="steps per epoch")
    s.add_argument("--batch-size", type=int, default=None)
    s.add_argument("--window", type=float, default=None, help="window length in seconds (default 60)")
    s.add_argument("--horizon", type=int, default=None, help="K windows to forecast (default 10)")
    s.add_argument("--context", type=int, default=None, help="past windows the model sees (default 30)")
    s.add_argument("--seed", type=int, default=None)
    s.set_defaults(fn=cmd_train)

    s = sub.add_parser("benchmark", help="world model vs logistic regression")
    s.add_argument("--data", "-d", nargs="+", required=True)
    s.add_argument("--weights", default=None)
    s.add_argument("--format", default="auto")
    s.add_argument("--samples", type=int, default=32)
    s.add_argument("--name", default="test")
    s.add_argument("--out", "-o", default="results")
    s.add_argument("--append", action="store_true", help="add to an existing results/benchmark.json")
    s.set_defaults(fn=cmd_benchmark)

    s = sub.add_parser("verify", help="verify forecast receipts")
    s.add_argument("receipts")
    s.set_defaults(fn=cmd_verify)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
