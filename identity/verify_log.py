#!/usr/bin/env python3
"""verify_log.py — re-verify every line of signed-activity-log.jsonl offline.

No key, no network, no dependency on the tool that wrote the log. It needs only
`cryptography`. That is the point: a claim about an identity is worth what an
outsider can check for themselves, and the coordinates alone are not checkable —
a signature covers `<room>|<nonce>|<text>`, so a record without its exact text
can never be re-proved by anyone. Every line here carries all four fields.

    python verify_log.py                       # verify identity/signed-activity-log.jsonl
    python verify_log.py path/to/other.jsonl

Exit status is 0 only when every line verifies.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover
    print("this needs the cryptography package:  python -m pip install cryptography")
    raise SystemExit(2)

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {character: index for index, character in enumerate(B58)}

ED25519_MULTICODEC = b"\xed\x01"  # varint 0xed01, the did:key prefix for an Ed25519 key


def b58_decode(value: str) -> bytes:
    number = 0
    for character in value:
        if character not in B58_INDEX:
            raise ValueError(f"{character!r} is not a base58btc character")
        number = number * 58 + B58_INDEX[character]
    body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    leading_zeros = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading_zeros + body


def public_key_from_did(did: str) -> Ed25519PublicKey:
    if not did.startswith("did:key:z"):
        raise ValueError("a did:key must start with 'did:key:z' (multibase base58btc)")
    decoded = b58_decode(did[len("did:key:z"):])
    if not decoded.startswith(ED25519_MULTICODEC):
        raise ValueError("not an Ed25519 did:key (multicodec prefix is not 0xed01)")
    raw = decoded[len(ED25519_MULTICODEC):]
    if len(raw) != 32:
        raise ValueError(f"an Ed25519 public key is 32 bytes, this is {len(raw)}")
    return Ed25519PublicKey.from_public_bytes(raw)


def canonical_signature(signature: str) -> bytes:
    """86 unpadded base64url characters, and the last must be one the encoder produces.

    Sixteen different strings decode to the same 64 bytes; only one is canonical, and
    the service accepts only that one. Checking it here keeps this verifier as strict
    as the thing it is verifying.
    """
    if len(signature) != 86:
        raise ValueError(f"a signature is 86 characters, this is {len(signature)}")
    if signature[-1] not in "AQgw":
        raise ValueError(f"non-canonical signature: it ends in {signature[-1]!r}, not one of AQgw")
    return base64.urlsafe_b64decode(signature + "==")


def verify_entry(entry: dict) -> None:
    for field in ("room", "nonce", "text", "did", "sig"):
        if not entry.get(field):
            raise ValueError(f"missing {field}")
    payload = f"{entry['room']}|{entry['nonce']}|{entry['text']}".encode("utf-8")
    try:
        public_key_from_did(entry["did"]).verify(canonical_signature(entry["sig"]), payload)
    except InvalidSignature:
        raise ValueError("signature does not match this DID over <room>|<nonce>|<text>") from None


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent / "signed-activity-log.jsonl"
    if not path.exists():
        print(f"no log at {path}")
        return 2

    ok = 0
    failures: list[str] = []
    dids: set[str] = set()
    earliest = latest = None

    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            verify_entry(entry)
        except (json.JSONDecodeError, ValueError) as error:
            failures.append(f"  line {number}: {error}")
            continue
        ok += 1
        dids.add(entry["did"])
        timestamp = entry.get("ts")
        if timestamp:
            earliest = timestamp if earliest is None or timestamp < earliest else earliest
            latest = timestamp if latest is None or timestamp > latest else latest

    print(f"{path}")
    print(f"  verified  {ok}")
    print(f"  failed    {len(failures)}")
    for failure in failures:
        print(failure)
    for did in sorted(dids):
        print(f"  did       {did}")
    if earliest:
        print(f"  earliest  {earliest}")
        print(f"  latest    {latest}")
    return 0 if not failures and ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
