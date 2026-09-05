#!/usr/bin/env python3
"""Sample a Technocore room, verify every signature offline, and report who is actually there.

The service accepts anonymous writes and self-issued did:key signatures alike. This tool
answers a narrower question than "how busy is the room": it verifies each signature against
the exact payload the protocol specifies, then measures how the signing keys are *used* --
how many post once and never again, how much of the text is templated, which client
implementations are present.

Reads only. It never writes to a room, never needs a key, and never sends anything anywhere.

Usage:
    python technocore_audit.py lobby --seconds 300
    python technocore_audit.py lobby --seconds 60 --json out.json

MIT licensed.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import time
import unicodedata
from collections import Counter
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

APP = "technocore-audit/1.0.0"
DEFAULT_BASE = "https://technocore.chat"
MULTICODEC_ED25519 = b"\xed\x01"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {c: i for i, c in enumerate(B58)}
INVISIBLE = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})

# Nonces reach 19 digits, past float precision. Never let a JSON parser see them as numbers.
NONCE_RE = re.compile(rb'"nonce":\s*(\d+)')


def b58_decode(value: str) -> bytes:
    n = 0
    for ch in value:
        d = B58_INDEX.get(ch)
        if d is None:
            raise ValueError(f"invalid base58btc character: {ch!r}")
        n = n * 58 + d
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(value) - len(value.lstrip("1"))) + body


def public_key_from_did(did: str) -> Ed25519PublicKey:
    """did:key:z6Mk... -> verification key. Resolution is offline; there is no registry."""
    if not isinstance(did, str) or not did.startswith("did:key:"):
        raise ValueError("not a did:key")
    mb = did[len("did:key:"):]
    if len(mb) != 48 or not mb.startswith("z6Mk"):
        raise ValueError("not the canonical 48-char Ed25519 multibase form")
    raw = b58_decode(mb[1:])
    if len(raw) != 34 or not raw.startswith(MULTICODEC_ED25519):
        raise ValueError("not an ed25519-pub key")
    return Ed25519PublicKey.from_public_bytes(raw[2:])


def single_line_sweep(text: str) -> str:
    """The server's normalization. Signatures cover the text AFTER this, not the raw input."""
    return "".join(
        " " if unicodedata.category(c) in INVISIBLE else c for c in text
    ).strip()


def canonical_sig(sig: str) -> bool:
    """64 bytes leave the last character's low four bits zero, so it is one of AQgw."""
    return isinstance(sig, str) and len(sig) == 86 and sig[-1] in "AQgw"


def verify(room: str, msg: dict[str, Any]) -> tuple[bool, str]:
    """Verify one message. Returns (ok, reason)."""
    frm = msg.get("from")
    if not isinstance(frm, str) or not frm.startswith("did:key:"):
        return False, "unsigned"
    sig = msg.get("sig")
    if not canonical_sig(sig):
        return False, "non-canonical-signature"
    try:
        key = public_key_from_did(frm)
    except ValueError:
        return False, "undecodable-did"
    payload = f"{room}|{msg.get('nonce')}|{msg.get('text')}".encode()
    try:
        key.verify(base64.urlsafe_b64decode(sig + "=="), payload)
    except (InvalidSignature, ValueError):
        return False, "bad-signature"
    return True, "ok"


def fetch(url: str, timeout: float) -> dict[str, Any]:
    req = Request(url, method="GET", headers={"Accept": "application/json", "User-Agent": APP})
    try:
        with urlopen(req, timeout=timeout) as r:
            raw = r.read(8 * 1024 * 1024)
    except (HTTPError, URLError, TimeoutError, OSError) as e:
        raise RuntimeError(f"fetch failed: {e}") from e
    return json.loads(NONCE_RE.sub(rb'"nonce":"\1"', raw))


def collect(room: str, seconds: float, base: str, interval: float, timeout: float) -> list[dict]:
    by_seq: dict[int, dict] = {}
    seed = fetch(f"{base}/r/{room}?format=json&limit=200", timeout)
    cursor = seed["last_seq"]
    for m in seed["messages"]:
        by_seq[m["seq"]] = m
    started = time.monotonic()
    polls = 0
    while time.monotonic() - started < seconds:
        d = fetch(f"{base}/r/{room}?format=json&limit=200&since={cursor}&n={polls}", timeout)
        polls += 1
        if d["messages"]:
            for m in d["messages"]:
                by_seq[m["seq"]] = m
            cursor = max(cursor, d["last_seq"])
        print(f"\r  collected {len(by_seq)} messages ({polls} polls)", end="", file=sys.stderr)
        time.sleep(interval)
    print(file=sys.stderr)
    return [by_seq[s] for s in sorted(by_seq)]


def analyse(room: str, msgs: list[dict]) -> dict[str, Any]:
    results = [verify(room, m) for m in msgs]
    reasons = Counter(r for _, r in results)
    signed = [m for m, (ok, _) in zip(msgs, results) if ok]

    # An anonymous write is a supported protocol mode, not a broken signature.
    # Counting the two together is the easiest way to publish a wrong number.
    anonymous = reasons.pop("unsigned", 0)

    per_key = Counter(m["from"] for m in signed)
    posts_hist = Counter(min(c, 5) for c in per_key.values())  # 5 == "5 or more"

    texts = Counter(m.get("text", "") for m in msgs)
    nonce_digits = Counter(len(str(m.get("nonce", ""))) for m in msgs)
    self_did = sum(1 for m in msgs if isinstance(m.get("text"), str) and m["from"] in m["text"])
    swept = sum(1 for m in msgs if isinstance(m.get("text"), str)
                and m["text"] != single_line_sweep(m["text"]))

    seq_lo, seq_hi = msgs[0]["seq"], msgs[-1]["seq"]
    span = seq_hi - seq_lo + 1
    secs = (_ts(msgs[-1]) - _ts(msgs[0])) or 1.0

    return {
        "room": room,
        "captured": len(msgs),
        "seq_range": [seq_lo, seq_hi],
        "seq_span": span,
        "coverage_pct": round(100 * len(msgs) / span, 1),
        "window_seconds": round(secs, 1),
        "messages_per_second": round(span / secs, 1),
        "signed_and_verified": reasons["ok"],
        "anonymous_writes": anonymous,
        "signature_failures": {k: v for k, v in reasons.items() if k != "ok"},
        "distinct_keys": len(per_key),
        "keys_per_message": round(len(per_key) / max(len(signed), 1), 3),
        "posts_per_key": {("5+" if k == 5 else str(k)): v for k, v in sorted(posts_hist.items())},
        "max_posts_by_one_key": max(per_key.values(), default=0),
        "unique_texts": len(texts),
        "duplicate_text_pct": round(100 * (1 - len(texts) / len(msgs)), 1),
        "top_texts": texts.most_common(10),
        "nonce_digit_classes": dict(sorted(nonce_digits.items())),
        "text_contains_own_did": self_did,
        "text_altered_by_sweep": swept,
    }


def _ts(m: dict) -> float:
    return time.mktime(time.strptime(m["ts"][:19], "%Y-%m-%dT%H:%M:%S"))


def compare(cap_a: dict, cap_b: dict) -> dict[str, Any]:
    """Do the keys in one capture come back in a later one?

    A single window cannot tell a one-shot key from an infrequent one: both look like
    "posted once". Two separated windows can. This is the measurement that decides whether
    a room is a churn of disposable identities or a population of quiet regulars.
    """
    a, b = cap_a["messages"], cap_b["messages"]
    if a[0]["seq"] > b[0]["seq"]:
        a, b = b, a
    keys_a = {m["from"] for m in a if str(m.get("from", "")).startswith("did:key:")}
    keys_b = {m["from"] for m in b if str(m.get("from", "")).startswith("did:key:")}
    both = keys_a & keys_b

    combined = Counter(m["from"] for m in a + b if str(m.get("from", "")).startswith("did:key:"))
    once = sum(1 for c in combined.values() if c == 1)
    repeat_msgs = sum(c for c in combined.values() if c > 1)

    return {
        "gap_in_sequences": b[0]["seq"] - a[-1]["seq"],
        "window_a": {"messages": len(a), "keys": len(keys_a)},
        "window_b": {"messages": len(b), "keys": len(keys_b)},
        "keys_in_both": len(both),
        "pct_of_window_b_keys_seen_before": round(100 * len(both) / max(len(keys_b), 1), 2),
        "combined_keys": len(combined),
        "combined_keys_posting_once": once,
        "combined_pct_posting_once": round(100 * once / max(len(combined), 1), 1),
        "messages_from_repeat_keys": repeat_msgs,
        "pct_traffic_from_repeat_keys": round(100 * repeat_msgs / max(len(a) + len(b), 1), 1),
        "max_posts_by_one_key": max(combined.values(), default=0),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Sample a Technocore room and verify every signature offline.")
    p.add_argument("room", nargs="?", help="room to sample (omit when using --compare)")
    p.add_argument("--seconds", type=float, default=120.0, help="how long to sample")
    p.add_argument("--interval", type=float, default=1.3, help="seconds between polls")
    p.add_argument("--timeout", type=float, default=20.0)
    p.add_argument("--base-url", default=DEFAULT_BASE)
    p.add_argument("--json", help="also write the raw captured messages here")
    p.add_argument("--compare", nargs=2, metavar=("EARLIER.json", "LATER.json"),
                   help="compare two captures: do the same keys come back?")
    a = p.parse_args(argv)

    if a.compare:
        caps = []
        for path in a.compare:
            with open(path, encoding="utf-8") as f:
                caps.append(json.load(f))
        print(json.dumps(compare(caps[0], caps[1]), ensure_ascii=False, indent=2))
        return 0

    if not a.room:
        p.error("a room is required unless --compare is used")

    try:
        msgs = collect(a.room, a.seconds, a.base_url.rstrip("/"), a.interval, a.timeout)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if not msgs:
        print("error: captured nothing", file=sys.stderr)
        return 1

    report = analyse(a.room, msgs)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump({"report": report, "messages": msgs}, f, ensure_ascii=False, indent=1)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
