"""Tamper-evident forecast receipts.

Every forecast row is serialised canonically and hashed (SHA-256). The hashes
are the leaves of a Merkle tree (RFC 6962 style: 0x00 leaf prefix, 0x01 node
prefix); the root is signed with an Ed25519 key kept on the sensor. Anyone with
the receipt file and the public key can re-check that no forecast was changed,
added or removed after the fact - and later score the forecasts against what
really happened.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path

KEY_DIR = Path.home() / ".sentinet"


def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def leaf_hash(record: dict) -> bytes:
    return _h(b"\x00" + json.dumps(record, sort_keys=True, separators=(",", ":"), default=str).encode())


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return _h(b"")
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_h(b"\x01" + level[i] + level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
    return level[0]


def _load_key(key_dir: Path = KEY_DIR):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key_dir.mkdir(parents=True, exist_ok=True)
    kp = key_dir / "sensor_ed25519.pem"
    if kp.exists():
        return serialization.load_pem_private_key(kp.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    try:
        kp.chmod(0o600)
    except OSError:
        pass
    return key


def _pub_b64(key) -> str:
    from cryptography.hazmat.primitives import serialization
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def make_receipts(records: list[dict], source: str = "", key_dir: Path = KEY_DIR) -> dict:
    leaves = [leaf_hash(r) for r in records]
    root = merkle_root(leaves)
    try:
        key = _load_key(key_dir)
        sig, pub, alg = base64.b64encode(key.sign(root)).decode(), _pub_b64(key), "ed25519"
    except Exception as exc:  # cryptography missing or key dir not writable
        sig, pub, alg = "", "", f"unsigned ({exc.__class__.__name__})"
    return {"version": 1, "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "source": source,
            "count": len(records), "merkle_root": root.hex(), "signature": sig, "public_key": pub,
            "algorithm": alg, "records": records}


def verify_receipts(doc: dict) -> tuple[bool, str]:
    leaves = [leaf_hash(r) for r in doc["records"]]
    root = merkle_root(leaves)
    if root.hex() != doc["merkle_root"]:
        return False, "Merkle root does not match the records: a forecast was changed, added or removed"
    if doc.get("algorithm") != "ed25519":
        return True, "records match the Merkle root (receipt is not signed)"
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(doc["public_key"]))
    try:
        pub.verify(base64.b64decode(doc["signature"]), root)
    except InvalidSignature:
        return False, "signature does not match the Merkle root"
    return True, f"{doc['count']} forecasts verified: Merkle root and Ed25519 signature are valid"
