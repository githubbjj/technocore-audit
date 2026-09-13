#!/usr/bin/env python3
"""identity_keepalive.py — keep this DID continuously provable on technocore.chat.

Why this exists
---------------
The sonnet-2 contest required a DID to have "signed activity strictly before the
opening" in FLOP's archive. Ours did — on 3 and 5 September — but by the time the
referee looked, all of it was gone:

    /kv/did-4d/91b40e65b44782        404   (a note idle 7 days is reclaimed)
    /kv/room-owners/d-barbemint-lab  404   (same reclaim; ownership lost)
    lobby seq 20966289               gone  (the lobby ring retains ~13 minutes)

Nothing on the service said the key had ever existed, and we held no re-verifiable
copy of our own. The registration was never receipted.

This script makes that failure impossible to repeat. It does four things on a timer,
none of which needs a human:

  1. claims /kv/room-owners/d-barbemint-lab, once, before anything is written there
     (the service refuses a first ownership claim once a room holds messages);
  2. writes a signed heartbeat into that room every few days, which keeps the room
     alive AND accumulates a permanent, server-timestamped record — a quiet room is
     a 10 MiB ring, so nothing we put there falls out;
  3. refreshes the DID note so it is never reclaimed again;
  4. posts a beacon into `lobby` so any third-party crawler or archive sees the key
     at regular intervals rather than in one two-day burst.

Every successful write is appended to identity/signed-activity-log.jsonl as the
complete tuple — room, seq, ts, did, nonce, sig, text — which is what makes a record
re-verifiable offline later. Coordinates alone are not enough: without the exact text
the signature cannot be rechecked, and that is precisely why our September 3 records
could not be re-proved to anyone.

The private key is loaded once into this process and never leaves the machine.

Usage (from the flop-technocore folder):

    python identity_keepalive.py            # run the loop
    python identity_keepalive.py --once     # do whatever is due, then exit
    python identity_keepalive.py --status   # print state and exit, write nothing
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
STARTER = HERE / "technocore-did-starter"
sys.path.insert(0, str(STARTER))

try:
    from technocore_agent import (  # audited package
        DEFAULT_BASE_URL,
        IdentityError,
        NetworkError,
        ProtocolError,
        did_from_private_key,
        load_identity,
        next_nonce,
        post_signed_message,
        sign_bytes,
    )
except ImportError as exc:  # pragma: no cover
    print(f"could not import technocore_agent from {STARTER}: {exc}")
    print("run this from the flop-technocore folder, and: python -m pip install cryptography")
    raise SystemExit(1)

# ── configuration ────────────────────────────────────────────────────────────

KEY_PATH = STARTER / "identity.pem"
PASS_PATH = HERE / "pp.txt"

IDENTITY = HERE / "identity"
STATE_PATH = IDENTITY / "state.json"
LOG_PATH = IDENTITY / "signed-activity-log.jsonl"

# Ours: claimed, quiet, and therefore durable.
#
# The name matters, and only once. A room is ownable from birth or not at all, and
# "birth" is counted by the `generation` field on /r/<room>?format=json — NOT by the
# messages currently in it. `d-barbemint-lab` reads count 0 today because its ring was
# reclaimed after seven idle days, but it sits at generation 1, and the claim comes
# back 403: "already has messages, so it can no longer be claimed". A reclaimed room
# is not a fresh room. Only generation 0 is claimable, and there is exactly one
# attempt per name, so `preflight_generation` checks before spending this one.
HOME_ROOM = "d-barbemint"
BEACON_ROOM = "lobby"           # theirs: noisy, but what an archive is most likely to watch

# The service reclaims a room or note after 7 days without a write. Three days
# means a single failed cycle still leaves four days of headroom; a failed write
# is retried on the next tick rather than waiting out the full interval.
EVERY_SECONDS = 3 * 24 * 60 * 60
TICK_SECONDS = 30 * 60

TIMEOUT = 20.0


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def did_note_path(did: str) -> tuple[str, str]:
    """The sharded DID-note location: /kv/did-<first 2>/<remaining 14>."""
    fingerprint = hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]
    return f"did-{fingerprint[:2]}", fingerprint[2:]


# ── plain HTTP, for the note lanes that return text rather than JSON ─────────


def http_get(path: str) -> tuple[int, str]:
    """GET one path. Returns (status, body). A 404 is a normal answer here, not an error."""
    url = f"{DEFAULT_BASE_URL}{path}"
    request = urllib.request.Request(url, method="GET", headers={"Accept": "text/plain"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.status, response.read(65536).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read(65536).decode("utf-8", errors="replace")
    except urllib.error.URLError as error:
        raise NetworkError(f"could not reach {url}: {error.reason}") from None


def kv_read(namespace: str, key: str) -> str | None:
    status, body = http_get(f"/kv/{namespace}/{key}")
    if status == 404:
        return None
    if status != 200:
        raise NetworkError(f"reading /kv/{namespace}/{key} gave HTTP {status}: {body[:200]}")
    return body.strip()


# ── the four jobs ────────────────────────────────────────────────────────────


def room_generation(room: str) -> int | None:
    """How many times this room has been born. 0 means never — the only claimable state."""
    status, body = http_get(f"/r/{room}?format=json&limit=1")
    if status != 200:
        return None
    try:
        return int(json.loads(body).get("generation", -1))
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def claim_home_room(key, did: str, state: dict) -> bool:
    """Claim ownership of the home room. There is one attempt per room name, ever.

    The signature covers `room-owners|d-<room>|<nonce>|<the same did:key>`, and the
    value stored is that same DID: parsing a key is not proof that the caller holds it,
    so the claim is only accepted when signed by the key it names.
    """
    existing = kv_read("room-owners", HOME_ROOM)
    if existing == did:
        state["owner_claimed"] = True
        return True
    if existing is not None:
        log(f"  {HOME_ROOM} is owned by someone else ({existing[:24]}...) — not touching it")
        state["owner_claimed"] = False
        state["owner_foreign"] = existing
        return False

    generation = room_generation(HOME_ROOM)
    if generation is None:
        log(f"  could not read the generation of {HOME_ROOM}; not risking the claim")
        return False
    if generation != 0:
        # Spending the claim here would burn nothing (it is already lost) but the
        # heartbeats below would then pile into a room anyone may write to.
        log(f"  {HOME_ROOM} is at generation {generation}, so it can never be owned.")
        log("  Pick a name that reads generation 0 and set HOME_ROOM to it.")
        state["owner_impossible"] = HOME_ROOM
        return False

    nonce = next_nonce()
    signature = sign_bytes(key, f"room-owners|{HOME_ROOM}|{nonce}|{did}".encode("utf-8"))
    path = (
        f"/kv/room-owners/{HOME_ROOM}/set-signed/{did}/{signature}/{nonce}/"
        f"{urllib.parse.quote(did, safe='')}?if_absent=1"
    )
    status, body = http_get(path)
    if status == 200:
        log(f"  claimed ownership of {HOME_ROOM}")
        state["owner_claimed"] = True
        state["owner_claimed_at"] = utc_now()
        return True
    if status == 409:
        log(f"  lost the claim race on {HOME_ROOM}: {body[:160]}")
        return False
    if status == 403:
        log(f"  {HOME_ROOM} can never be owned: {body[:200]}")
        state["owner_impossible"] = HOME_ROOM
        return False
    log(f"  ownership claim failed (HTTP {status}): {body[:200]}")
    return False


def refresh_did_note(did: str, state: dict) -> bool:
    """Keep the DID note alive. It is world-writable, so never clobber a stranger's value."""
    namespace, key_name = did_note_path(did)
    current = kv_read(namespace, key_name)

    value = (
        f"barbemint | {did} | github:githubbjj | x:https://x.com/barbemint | "
        f"home:{HOME_ROOM} | log:https://github.com/githubbjj/technocore-audit"
        f"/blob/main/identity/signed-activity-log.jsonl | refreshed:{utc_now()}"
    )

    if current is not None and "barbemint" not in current:
        log(f"  DID note holds someone else's value — leaving it: {current[:120]}")
        state["note_foreign"] = current[:200]
        return False

    encoded = urllib.parse.quote(value, safe="")
    query = f"?if={urllib.parse.quote(current, safe='')}" if current is not None else "?if_absent=1"
    status, body = http_get(f"/kv/{namespace}/{key_name}/set/{encoded}{query}")
    if status == 200:
        log(f"  DID note refreshed at /kv/{namespace}/{key_name}")
        return True
    if status == 409:
        log("  DID note changed under us; will retry next tick")
        return False
    log(f"  DID note write failed (HTTP {status}): {body[:200]}")
    return False


def heartbeat(key, room: str, did: str, kind: str, counter: int) -> dict | None:
    """Post one signed line and return the full re-verifiable tuple, or None."""
    # The counter and timestamp are not decoration: a room refuses a text that has
    # already been posted too many times in the last few seconds (422), and the check
    # folds case, whitespace and Unicode compatibility — so every line must differ.
    text = json.dumps(
        {
            "type": "barbemint.presence.v1",
            "did": did,
            "kind": kind,
            "n": counter,
            "utc": utc_now(),
            "github": "githubbjj",
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    try:
        response = post_signed_message(key, room, text, timeout=TIMEOUT)
    except (NetworkError, ProtocolError, IdentityError) as error:
        log(f"  {kind} post to {room} failed: {error}")
        return None
    posted = response.get("posted", {})
    entry = {
        "room": room,
        "seq": posted.get("seq"),
        "ts": posted.get("ts"),
        "did": posted.get("from", did),
        "nonce": str(posted.get("nonce", "")),
        "sig": posted.get("sig"),
        "text": posted.get("text", text),
        "kind": kind,
    }
    log(f"  {kind} -> {room} seq {entry['seq']} @ {entry['ts']}")
    return entry


def append_log(entry: dict) -> None:
    """One JSON object per line. Order is append-only; nothing is ever rewritten."""
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")


# ── the cycle ────────────────────────────────────────────────────────────────


def due(state: dict, name: str) -> bool:
    return time.time() - float(state.get(name, 0)) >= EVERY_SECONDS


def cycle(key, did: str) -> None:
    state = read_json(STATE_PATH, {})
    counter = int(state.get("counter", 0))
    changed = False

    # Changing HOME_ROOM invalidates every ownership verdict recorded for the old one.
    if state.get("home_room") != HOME_ROOM:
        for stale in ("owner_claimed", "owner_foreign", "owner_impossible", "home_at", "home_seq"):
            state.pop(stale, None)
        state["home_room"] = HOME_ROOM
        changed = True

    # Ownership first, always: the claim is refused once the room has ever held a message.
    if not state.get("owner_claimed") and not state.get("owner_foreign") \
            and not state.get("owner_impossible"):
        if claim_home_room(key, did, state):
            changed = True

    # Post even when the room could not be claimed. Ownership keeps other writers out;
    # it is not what makes the record durable. An unowned quiet room still holds it.
    if due(state, "home_at") and not state.get("owner_foreign"):
        counter += 1
        entry = heartbeat(key, HOME_ROOM, did, "home", counter)
        if entry:
            append_log(entry)
            state["home_at"] = time.time()
            state["home_seq"] = entry["seq"]
            state["counter"] = counter
            changed = True

    if due(state, "beacon_at"):
        counter += 1
        entry = heartbeat(key, BEACON_ROOM, did, "beacon", counter)
        if entry:
            append_log(entry)
            state["beacon_at"] = time.time()
            state["beacon_seq"] = entry["seq"]
            state["counter"] = counter
            changed = True

    if due(state, "note_at"):
        if refresh_did_note(did, state):
            state["note_at"] = time.time()
            changed = True

    if changed:
        state["updated"] = utc_now()
        write_json(STATE_PATH, state)


def show_status(did: str) -> None:
    namespace, key_name = did_note_path(did)
    state = read_json(STATE_PATH, {})
    print(f"DID          {did}")
    print(f"note path    /kv/{namespace}/{key_name}")
    print(f"home room    {HOME_ROOM}")
    for name, label in (("home_at", "home post"), ("beacon_at", "lobby beacon"), ("note_at", "DID note")):
        at = float(state.get(name, 0))
        if not at:
            print(f"  {label:14} never")
        else:
            age_hours = (time.time() - at) / 3600
            print(f"  {label:14} {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(at))}"
                  f"  ({age_hours:.1f} h ago, reclaim at 168 h)")
    if state.get("owner_impossible"):
        print(f"  owner claim  IMPOSSIBLE for {state['owner_impossible']} (it has lived before)")
    else:
        print(f"  owner claim  {'yes' if state.get('owner_claimed') else 'not yet'}")
    lines = sum(1 for _ in LOG_PATH.open(encoding='utf-8')) if LOG_PATH.exists() else 0
    print(f"  log lines    {lines}  ({LOG_PATH})")

    print("\nlive check:")
    for label, path in (
        ("DID note", f"/kv/{namespace}/{key_name}"),
        ("room owner", f"/kv/room-owners/{HOME_ROOM}"),
    ):
        try:
            status, body = http_get(path)
            print(f"  {label:11} HTTP {status}  {body.strip()[:110]}")
        except NetworkError as error:
            print(f"  {label:11} {error}")
    generation = room_generation(HOME_ROOM)
    verdict = {0: "never born — claimable", None: "unreadable"}.get(
        generation, "has lived — can never be owned"
    )
    print(f"  generation  {generation}  ({verdict})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--once", action="store_true", help="do whatever is due, then exit")
    parser.add_argument("--status", action="store_true", help="print state and exit, write nothing")
    args = parser.parse_args()

    if not KEY_PATH.exists():
        log(f"identity.pem not found at {KEY_PATH}")
        return 1
    if not PASS_PATH.exists():
        log(f"pp.txt not found at {PASS_PATH} — put the passphrase there, one line")
        return 1

    passphrase = PASS_PATH.read_text(encoding="utf-8").strip().splitlines()[-1].strip()
    try:
        key = load_identity(KEY_PATH, passphrase.encode("utf-8"))
    except IdentityError as error:
        log(f"could not unlock the key: {error}")
        return 1
    del passphrase

    did = did_from_private_key(key)

    if args.status:
        show_status(did)
        return 0

    log(f"key unlocked. DID {did}")
    log(f"home {HOME_ROOM} · beacon {BEACON_ROOM} · every {EVERY_SECONDS // 86400} days")
    log(f"log  {LOG_PATH}")

    if args.once:
        cycle(key, did)
        return 0

    log(f"watching. tick {TICK_SECONDS // 60} min. Ctrl+C to stop.")
    while True:
        try:
            cycle(key, did)
        except KeyboardInterrupt:
            raise
        except Exception:  # a bad cycle must never kill the loop
            log("unexpected error in cycle:")
            traceback.print_exc()
        time.sleep(TICK_SECONDS)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        raise SystemExit(0)
