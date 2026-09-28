"""Attack stages and how dataset labels map onto them.

The world model forecasts one of these stages for every future window. The
numbering is the model's class index; the order follows the MITRE ATT&CK
tactic order used in the problem statement.
"""
from __future__ import annotations

import re

STAGES = [
    "Benign",
    "Reconnaissance",
    "Initial Access",
    "Lateral Movement",
    "Command & Control",
    "Exfiltration",
    "Impact",
]
N_STAGES = len(STAGES)

BENIGN, RECON, INITIAL_ACCESS, LATERAL, C2, EXFIL, IMPACT = range(N_STAGES)

# Stages that mean the attacker is inside the network ("infiltration").
# Impact (DoS/DDoS from outside) is reported but is not an infiltration.
INFILTRATION = (INITIAL_ACCESS, LATERAL, C2, EXFIL)

ATTACK_TACTIC = {
    BENIGN: ("-", "-"),
    RECON: ("TA0043", "Reconnaissance / Discovery  (T1595, T1046)"),
    INITIAL_ACCESS: ("TA0001", "Initial Access  (T1190, T1110, T1133)"),
    LATERAL: ("TA0008", "Lateral Movement  (T1021, T1570, T1046 internal)"),
    C2: ("TA0011", "Command and Control  (T1071, T1573, T1571)"),
    EXFIL: ("TA0010", "Exfiltration  (T1041, T1048)"),
    IMPACT: ("TA0040", "Impact  (T1498, T1499)"),
}

STAGE_COLORS = {
    BENIGN: "#9aa5b1",
    RECON: "#f4a261",
    INITIAL_ACCESS: "#e76f51",
    LATERAL: "#d62828",
    C2: "#7b2cbf",
    EXFIL: "#1d3557",
    IMPACT: "#6d6875",
}

# ---------------------------------------------------------------- label maps
# Each rule is (regex, stage). First match wins. Matching is case-insensitive
# on the dataset's raw label string.
_RULES = [
    # benign / background
    (r"^(benign|normal|background|0|false|-)$", BENIGN),
    (r"flow=(background|to-background|from-background|from-normal|to-normal|normal)", BENIGN),
    # Distrinet / improved CIC-IDS2017: failed attempts ("... - Attempted") never got in -> treat as recon
    (r"attempted", RECON),
    # our own synthetic labels "stage:<n>:..." are handled before the rules
    # CIC-IDS2017 / CSE-CIC-IDS2018
    (r"portscan|port scan|reconnaissance|fuzzers|analysis|scan", RECON),
    (r"patator|brute ?force|bruteforce|web attack|sql injection|xss|exploits|shellcode|generic", INITIAL_ACCESS),
    (r"infilt(r)?ation|infilteration|worms?|lateral", LATERAL),
    (r"\bbot\b|botnet|backdoors?|c&c|\bcc\b|-cc|command", C2),
    (r"exfil", EXFIL),
    (r"ddos|dos|heartbleed|loic|hoic|hulk|slowloris|slowhttptest|goldeneye|spam|clickfraud", IMPACT),
]
_COMPILED = [(re.compile(p, re.I), s) for p, s in _RULES]


def label_to_stage(label) -> int:
    """Map a raw dataset label to a stage index. Unknown attack labels map to
    Initial Access (an unknown intrusion is treated as a compromise signal)."""
    if label is None:
        return BENIGN
    s = str(label).strip()
    if s == "" or s.lower() == "nan":
        return BENIGN
    if s.startswith("stage:"):
        return int(s.split(":")[1])
    if s.isdigit():
        v = int(s)
        return v if 0 <= v < N_STAGES else INITIAL_ACCESS
    for rx, stage in _COMPILED:
        if rx.search(s):
            return stage
    # CTU-13 botnet flows that did not match a more specific rule
    if "botnet" in s.lower():
        return C2
    return INITIAL_ACCESS


def is_infiltration(stage: int) -> bool:
    return int(stage) in INFILTRATION
