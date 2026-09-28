"""Rebuild the files in samples/ (deterministic).

  python scripts/make_samples.py
"""
import gzip
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sentinet.synth.generator import generate_scenario, write_flows  # noqa: E402
from sentinet.synth.pcapgen import flows_to_pcap, label_rules_from_flows  # noqa: E402

out = ROOT / "samples"
out.mkdir(exist_ok=True)

# 12 h of an enterprise network: an internet scanner, a failed brute-force attempt, then a real
# web intrusion that goes recon -> exploit -> C2 -> lateral movement -> exfiltration.
flows, meta = generate_scenario(9001, hours=12, campaigns=["failed_attack", "web_exploit"], background_scan=True,
                                start_hour=6)
write_flows(flows, out / "demo_enterprise_12h.csv.gz")
print("demo_enterprise_12h.csv.gz:", len(flows), "flows", [c["template"] for c in meta["campaigns"]])

# 3 h PCAP of a smaller network with one web intrusion, plus its ground-truth label rules
flows, meta = generate_scenario(9002, hours=3, campaigns=["web_exploit"], n_workstations=8, start_hour=7,
                                background_scan=False)
tmp = out / "demo_web_intrusion.pcap"
n = flows_to_pcap(flows, tmp)
with open(tmp, "rb") as a, gzip.open(str(tmp) + ".gz", "wb", compresslevel=9) as b:
    shutil.copyfileobj(a, b)
tmp.unlink()
label_rules_from_flows(flows).to_csv(out / "demo_web_intrusion_labels.csv", index=False)
print("demo_web_intrusion.pcap.gz:", n, "packets,", len(flows), "flows")
