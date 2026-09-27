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

  1. claims /kv/room-owners/d-barbemint, once, before anything is written there
     (the service refuses a first ownership claim once a room holds messages);
  2. writes a signed heartbeat into that room every few days, which keeps the room
     alive AND accumulates a permanent, server-timestamped record — a quiet room is
     a 10 MiB ring, so nothing we put there falls out;
  3. refreshes the DID note so it is never reclaimed again — and, since a room is
     announced in /r/events only once and that ring holds about six days, the note
     ends up being the only pointer to our records that does not expire;
  4. posts a beacon into `lobby` and `technocore` so a reader already watching the
     busy rooms sees the key at regular intervals rather than in one two-day burst.

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
RUN_LOG = IDENTITY / "run.log"

# Ours: claimed, quiet, and therefore durable.
#
# The name matters, and only once. A room is ownable from birth or not at all, and
# "birth" is counted by the `generation` field on /r/<room>?format=json — NOT by the
# messages currently in it. `d-barbemint-lab` reads count 0 today because its ring was
# reclaimed after seven idle days, but it sits at generation 1, and the claim comes
# back 403: "already has messages, so it can no longer be claimed". A reclaimed room
# is not a fresh room. Only generation 0 is claimable, and there is exactly one
# attempt per name, so `room_generation` checks before spending this one.
HOME_ROOM = "d-barbemint"

# Theirs. Neither retains our record for long — `lobby` holds about twenty minutes of
# traffic and `technocore` under an hour — so these are not where the evidence lives.
# They are where a reader who is already watching sees the key without having to
# discover anything, which matters because discovery of our own room expires: a room
# is announced once in /r/events ("created d-barbemint") and that ring holds about six
# days. After that the DID note is the only unexpiring pointer to where our records
# are, which is why it is refreshed rather than written once.
BEACON_ROOMS = ("lobby", "technocore")

# A mailbox others can write to. `mb-` refuses the unsigned lane, so every message
# that lands is attributable to a did:key; the `p-` class keeps the name out of
# /rooms, so it is reachable only from the DID note that advertises it. The name is
# the whole secret: if it is ever flooded, mint a new one and the note republishes it.
MAILBOX_ROOM = "mb-p-bm8f4fb1692c17b7b6"

# A room still holding its FIRST message is reclaimed after `stillborn_seconds` —
# 43200 on this deployment, twelve hours — while a room past that lives on the seven-day
# idle rule instead. Any heartbeat slower than twelve hours therefore cannot keep a room
# alive one line at a time: every post creates the room, sits alone in it, and is reaped
# long before the next one. That is not a theory. `d-barbemint` was claimed and written at
# 2026-09-13T06:02:00Z and read back `count: 0` thirty-three hours later, and the same
# thing had already happened once before that.
#
# Two messages is the whole fix: at two the stillborn rule no longer applies. So every
# cycle checks the count and tops the room up, which also repairs a room that was reaped
# while nobody was looking.
MIN_ROOM_MESSAGES = 2

# The service accepts a nonce of 1-19 digits and refuses anything longer.
MAX_NONCE_DIGITS = 19

# The service reclaims a room or note after 7 days without a write.
RECLAIM_SECONDS = 7 * 24 * 60 * 60

# Survival only needs a write inside that window, and three days did that. But the
# archive is the point: an eligibility check reads what a public room's ring actually
# retained, and `lobby` rotates its 10 MiB ring in roughly a quarter of an hour. Whether
# any one beacon is still there when someone looks is luck; the only lever we hold is how
# many times we roll the dice. A daily cycle triples the attempts for four writes a day —
# nothing against a 300/min limit — and still leaves six days of headroom after a failure.
EVERY_SECONDS = 24 * 60 * 60
# How early a timer may fire. See due() — the scheduler tick and the cadence are both
# daily, so a slack that is too small lets them race and the cadence loses. Twelve hours
# is the widest slack that still cannot double-post: two scheduler ticks are always a full
# day apart, so only a manual re-run inside the same half-day could land twice, and that
# is exactly the case the timer exists to suppress.
DUE_SLACK_SECONDS = 12 * 60 * 60
TICK_SECONDS = 30 * 60
# At a daily cycle a timer this old means three cycles in a row did not write, which is
# already abnormal. Saying so at 72 h leaves four days to notice and act.
WARN_SECONDS = 3 * 24 * 60 * 60

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


BANNER_PREFIX = "!! UNTRUSTED CONTENT"


def strip_banner(body: str) -> str:
    """Return the stored value alone, without the service's reader-facing decoration.

    Every /kv read is served as a safety banner, a blank line, then the value and a
    trailing newline — in every format; there is no raw lane. That decoration is not
    part of what is stored, and two things break if it is treated as though it were:

      * a conditional write compares `?if=` against the STORED value, so an `?if=`
        built from the raw body can never match and the write fails 409 forever; and
      * `existing == did` on a room-owners read is false against a banner-wrapped
        body, so our own room reads back as somebody else's and the daemon stops
        writing to it.

    The first cost us a note refresh; the second was still waiting to happen.
    /r/<room> responses carry no banner, so this applies to /kv reads only.
    """
    if body.startswith(BANNER_PREFIX):
        _, _, body = body.partition("\n\n")
    return body.rstrip("\n")


def kv_read(namespace: str, key: str) -> str | None:
    status, body = http_get(f"/kv/{namespace}/{key}")
    if status == 404:
        return None
    if status != 200:
        raise NetworkError(f"reading /kv/{namespace}/{key} gave HTTP {status}: {body[:200]}")
    return strip_banner(body)


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


def retained_at_least(room: str, want: int) -> int | None:
    """min(messages the room holds, `want`). None if it could not be read.

    `count` is the size of THIS reply, not of the room: asked with `limit=1` it reads 1
    for a room holding a thousand. Reading it as a room total made the floor check below
    always see one message and post an anchor on every single run — a write per cycle,
    forever, while never actually testing the thing it was there to test.

    So ask for exactly the floor. The answer saturates at `want`, which is all the caller
    needs and the smallest reply that can carry it; `limit` is advisory and clamped to
    1..200, so a floor inside that range is answered exactly.
    """
    want = max(1, min(int(want), 200))
    status, body = http_get(f"/r/{room}?format=json&limit={want}")
    if status != 200:
        return None
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return None
    # Prefer the messages actually delivered over the summary field: `count` is the
    # server's word for the same thing, but the list is the thing itself.
    messages = payload.get("messages")
    if isinstance(messages, list):
        return len(messages)
    try:
        return int(payload.get("count", -1))
    except (TypeError, ValueError):
        return None


def keep_room_alive(key, did: str, room: str, kind: str, counter: int,
                    done: list) -> tuple[int, bool]:
    """Top a room up to MIN_ROOM_MESSAGES so the stillborn reaper cannot take it.

    Runs every cycle, not only when the heartbeat is due: the point is to notice a room
    that is already gone.

    It clears the floor in ONE invocation rather than a message per run. A single post
    into an empty room leaves it holding exactly one message — still stillborn, still
    reaped twelve hours later, long before a daily run could add the second. Topping up
    one at a time would reproduce the original bug with more steps.

    The posts are bounded by the floor, and the first failure stops the rest: if the
    service is refusing writes, sending the same request again in the same run only
    spends the write budget on the same refusal.
    """
    count = retained_at_least(room, MIN_ROOM_MESSAGES)
    if count is None:
        log(f"  could not read the message count of {room}; leaving it alone")
        return counter, False
    if count >= MIN_ROOM_MESSAGES:
        return counter, False

    log(f"  {room} holds {count} message(s), below the floor of {MIN_ROOM_MESSAGES}; anchoring")
    posted_any = False
    for _ in range(MIN_ROOM_MESSAGES - count):
        counter += 1
        entry, reason = heartbeat(key, room, did, kind, counter)
        if not entry:
            done.append(f"anchor:{room}:FAILED({reason})")
            break
        append_log(entry)
        done.append(f"anchor:{room}:{entry['seq']}")
        posted_any = True
    return counter, posted_any


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


def ownership_nonce() -> int | None:
    """A nonce the ownership namespace will accept.

    `room-owners` and `room-allow` share `/kv/room-nonce/<room>` as one replay counter,
    and a signed note write must exceed whatever is in it. A wall clock is normally
    already past it, but not necessarily — the counter is whatever the last accepted
    write put there — so take the larger of the two rather than assuming.

    Both sides are parsed rather than trusted to be numbers. `next_nonce()` hands back
    digits as a string, and comparing that to an int raises instead of picking a nonce;
    the counter comes off the wire and could be anything at all.
    """
    def digits(value, default=None):
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return default

    clock = digits(next_nonce(), default=int(time.time() * 1000))
    try:
        stored = digits(kv_read("room-nonce", HOME_ROOM))
    except NetworkError as error:
        log(f"  could not read the ownership nonce ({error}); using the clock")
        stored = None
    chosen = clock if stored is None else max(clock, stored + 1)

    # The service takes 1-19 digits. A counter already at the ceiling makes every
    # successor too long, and the request would be refused for a reason the log would
    # not name. Only our own accepted writes can move this counter, so reaching it means
    # something wrote a nonsense nonce — worth saying out loud rather than sending a
    # request that cannot be accepted.
    if not 1 <= len(str(chosen)) <= MAX_NONCE_DIGITS:
        log(f"  cannot build a legal nonce: {chosen} is not 1-{MAX_NONCE_DIGITS} digits "
            f"(shared counter reads {stored})")
        return None
    return chosen


def refresh_room_ownership(key, did: str, state: dict) -> bool:
    """Rewrite the ownership note so the reaper never collects it.

    The claim was written once and then left alone, which was a mistake: `room-owners`
    holds an ordinary note, and a note with no write for seven days is deleted like any
    other. Nothing warns you — the room simply stops being owned.

    That is not a loss you can undo. A room is ownable from birth or not at all, so once
    `d-barbemint` has lived the claim cannot be re-made by us or by anyone; the room would
    fall back to world-writable for good, and a stranger could then flood the ring the
    archive lives in. Refreshing on the daily heartbeat keeps it six days clear of
    the deadline.

    Writing the same DID over our own claim is the handover operation pointed back at
    ourselves, which is what the service documents for this namespace, and `?if=` makes it
    a compare-and-set so a genuine handover in flight is not clobbered.
    """
    try:
        current = kv_read("room-owners", HOME_ROOM)
    except NetworkError as error:
        log(f"  could not read the ownership note ({error}); leaving it alone")
        return False

    if current is not None and current != did:
        log(f"  {HOME_ROOM} is owned by {current[:24]}... — not touching it")
        state["owner_foreign"] = current
        state["owner_claimed"] = False
        return False

    if current is None:
        # Either it was never claimed, or the reaper has already taken it. claim_home_room
        # tells the two apart and refuses to spend the attempt on a room that has lived.
        log(f"  the ownership note for {HOME_ROOM} is GONE — trying to re-establish it")
        state["owner_claimed"] = False
        return claim_home_room(key, did, state)

    nonce = ownership_nonce()
    if nonce is None:
        return False
    signature = sign_bytes(key, f"room-owners|{HOME_ROOM}|{nonce}|{did}".encode("utf-8"))
    path = (
        f"/kv/room-owners/{HOME_ROOM}/set-signed/{did}/{signature}/{nonce}/"
        f"{urllib.parse.quote(did, safe='')}"
        f"?if={urllib.parse.quote(current, safe='')}"
    )
    status, body = http_get(path)
    if status == 200:
        log(f"  ownership note for {HOME_ROOM} refreshed")
        state["owner_claimed"] = True
        state["owner_refreshed_at"] = utc_now()
        return True
    if status == 409:
        # Someone else's write landed between the read and this one. Their value is in
        # the body; the next cycle re-reads and decides on it rather than fighting.
        log(f"  ownership note changed under us: {body[:160]}")
        return False
    log(f"  ownership refresh failed (HTTP {status}): {body[:200]}")
    return False


def note_value(did: str, stamp: str) -> str:
    return (
        f"barbemint | {did} | github:githubbjj | x:https://x.com/barbemint | "
        f"home:{HOME_ROOM} | mailbox:{MAILBOX_ROOM} | "
        f"log:https://github.com/githubbjj/technocore-audit"
        f"/blob/main/identity/signed-activity-log.jsonl | refreshed:{stamp}"
    )


def note_stale(value: str | None) -> str:
    """The note without its timestamp, so two notes can be compared for real changes."""
    return (value or "").rsplit(" | refreshed:", 1)[0]


def refresh_did_note(did: str, state: dict) -> bool:
    """Keep the DID note alive. It is world-writable, so never clobber a stranger's value."""
    namespace, key_name = did_note_path(did)
    current = kv_read(namespace, key_name)
    value = note_value(did, utc_now())

    if current is not None and "barbemint" not in current:
        log(f"  DID note holds someone else's value — leaving it: {current[:120]}")
        state["note_foreign"] = current[:200]
        return False

    encoded = urllib.parse.quote(value, safe="")

    def attempt(seen: str | None) -> tuple[int, str]:
        guard = f"?if={urllib.parse.quote(seen, safe='')}" if seen is not None else "?if_absent=1"
        return http_get(f"/kv/{namespace}/{key_name}/set/{encoded}{guard}")

    status, body = attempt(current)
    if status == 409:
        # Someone wrote between our read and our write. Re-read once: if the note is
        # still ours, take the new value as the guard and try again. If it is not,
        # leave it alone — a 409 is the guard doing its job, not an error to force past.
        current = kv_read(namespace, key_name)
        if current is None or "barbemint" in current:
            status, body = attempt(current)
        else:
            log(f"  DID note was taken over between read and write: {current[:120]}")
            state["note_foreign"] = current[:200]
            return False
    if status == 200:
        log(f"  DID note refreshed at /kv/{namespace}/{key_name}")
        return True
    if status == 409:
        log("  DID note changed under us twice; will retry next tick")
        return False
    log(f"  DID note write failed (HTTP {status}): {body[:200]}")
    return False


def failure_reason(error: Exception) -> str:
    """One short line naming why a post failed, safe to put in run.log.

    run.log is the only record a scheduled run leaves behind: the scheduler discards
    stdout, so `log()` output is gone the moment the process exits. Recording just
    "FAILED" made `beacon:lobby` fail on three of five days with no way to tell a
    timeout from a refusal — five days of the same fault, undiagnosable. The reason
    is collapsed onto one line and clipped, because a traceback in a log meant to be
    skimmed is the same as no log at all.
    """
    text = " ".join(f"{type(error).__name__}: {error}".split())
    return text[:117] + "..." if len(text) > 120 else text


def heartbeat(key, room: str, did: str, kind: str, counter: int) -> tuple[dict | None, str]:
    """Post one signed line. Returns (tuple, "") or (None, reason)."""
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
        reason = failure_reason(error)
        log(f"  {kind} post to {room} failed: {reason}")
        return None, reason
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
    return entry, ""


def append_log(entry: dict) -> None:
    """One JSON object per line. Order is append-only; nothing is ever rewritten."""
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")


def note_run(outcome: str) -> None:
    """Record that this ran at all, separately from whether it had anything to do.

    Under a scheduler there is no console to watch, and on a quiet day a healthy run
    writes nothing — so `state.json` looks identical whether the run succeeded with
    nothing due or never happened. Those two are the difference between a live
    identity and one quietly counting down to reclaim, so they get their own file.
    """
    RUN_LOG.parent.mkdir(parents=True, exist_ok=True)
    try:
        lines = RUN_LOG.read_text(encoding="utf-8").splitlines()[-499:]
    except OSError:
        lines = []
    lines.append(f"{utc_now()} {outcome}")
    RUN_LOG.write_text("\n".join(lines) + "\n", encoding="utf-8")


def last_run() -> str | None:
    try:
        lines = [line for line in RUN_LOG.read_text(encoding="utf-8").splitlines() if line.strip()]
    except OSError:
        return None
    return lines[-1] if lines else None


# ── the cycle ────────────────────────────────────────────────────────────────


def timer_names() -> list[str]:
    return (["home_at"] + [f"beacon_at:{room}" for room in BEACON_ROOMS]
            + ["note_at", "owner_at"])


def due(state: dict, name: str) -> bool:
    # Fire early, on purpose. Nothing runs this as a 30-minute loop in practice; run.log
    # shows one invocation a day from the Windows scheduler, nominally at 00:00Z. Two ways
    # that tick misses an exact 24 h threshold, both seen in run.log:
    #
    #   - seconds: the tick lands a few seconds before the moment yesterday's write
    #     finished, reads 23:59:5x, and returns False (09-19 would have been skipped).
    #   - hours: the PC is off at 00:00, the scheduler runs the missed start on boot
    #     (09-26 ran at 05:12Z), and the next 00:00 tick is only 18.8 h later, so that
    #     day writes nothing at all (09-27 logged `nothing-due`).
    #
    # One hour of slack covered the first and not the second. Twelve covers both: any
    # boot time up to noon still leaves the next midnight tick past the threshold.
    return time.time() - float(state.get(name, 0)) >= EVERY_SECONDS - DUE_SLACK_SECONDS


def overdue(state: dict) -> list[str]:
    """Timers quiet long enough to be worth naming, before RECLAIM_SECONDS kills them."""
    return [
        name for name in timer_names()
        if state.get(name) and time.time() - float(state[name]) >= WARN_SECONDS
    ]


def cycle(key, did: str) -> str:
    """Do whatever is due. Returns a one-line summary of what actually happened."""
    state = read_json(STATE_PATH, {})
    counter = int(state.get("counter", 0))
    changed = False
    done: list[str] = []

    # A single beacon room became several; carry its clock over so adding a room does
    # not restart the cadence on the one that was already running.
    if "beacon_at" in state:
        state.setdefault("beacon_at:lobby", state.pop("beacon_at"))
        if "beacon_seq" in state:
            state.setdefault("beacon_seq:lobby", state.pop("beacon_seq"))
        changed = True

    # Changing HOME_ROOM invalidates every ownership verdict recorded for the old one.
    if state.get("home_room") != HOME_ROOM:
        for stale in ("owner_claimed", "owner_foreign", "owner_impossible", "home_at", "home_seq"):
            state.pop(stale, None)
        state["home_room"] = HOME_ROOM
        changed = True

    # Ownership first, always: the claim is refused once the room has ever held a message.
    if not state.get("owner_claimed") and not state.get("owner_impossible"):
        if claim_home_room(key, did, state):
            changed = True
            done.append("claim")

    # And then keep it. The claim is a note, and a note nobody writes to for seven days is
    # deleted — after which this room can never be owned again by anyone, because it has
    # lived. On the same daily clock as everything else, which leaves six days of slack.
    if (state.get("owner_claimed") and not state.get("owner_impossible")
            and not state.get("owner_foreign") and due(state, "owner_at")):
        if refresh_room_ownership(key, did, state):
            state["owner_at"] = time.time()
            changed = True
            done.append("owner")
        else:
            done.append("owner:FAILED")

    # Post even when the room could not be claimed. Ownership keeps other writers out;
    # it is not what makes the record durable. An unowned quiet room still holds it.
    #
    # The one thing that must stop a post is the room belonging to somebody else, and
    # that is re-read here rather than remembered. A remembered "not ours" is a latch
    # with no way out: one bad read — the banner bug did exactly this — and the daemon
    # goes quiet forever while every other check still reports healthy. A verdict this
    # consequential is worth one GET a day.
    if due(state, "home_at"):
        try:
            owner = kv_read("room-owners", HOME_ROOM)
        except NetworkError as error:
            log(f"  could not read the room owner: {error}")
            owner = did  # a failed read must not be treated as a takeover
        if owner is not None and owner != did:
            log(f"  {HOME_ROOM} now belongs to {owner[:32]}... — not posting there")
            state["owner_foreign"] = owner
            changed = True
            done.append("home:ROOM-TAKEN")
        else:
            state.pop("owner_foreign", None)
            counter += 1
            entry, reason = heartbeat(key, HOME_ROOM, did, "home", counter)
            if entry:
                append_log(entry)
                state["home_at"] = time.time()
                state["home_seq"] = entry["seq"]
                state["counter"] = counter
                changed = True
                done.append(f"home:{entry['seq']}")
            else:
                done.append(f"home:FAILED({reason})")

    # Whether or not the heartbeat was due, make sure the two rooms this identity owns
    # the meaning of are above the stillborn floor. The home room is the archive; the
    # mailbox has to be there before anyone writes to it, or a stranger's first message
    # lands alone in a fresh room and is reaped with it twelve hours later.
    if not state.get("owner_foreign"):
        counter, posted = keep_room_alive(key, did, HOME_ROOM, "anchor", counter, done)
        if posted:
            state["counter"] = counter
            changed = True
    counter, posted = keep_room_alive(key, did, MAILBOX_ROOM, "mailbox", counter, done)
    if posted:
        state["counter"] = counter
        changed = True

    for room in BEACON_ROOMS:
        timer = f"beacon_at:{room}"
        # A room added later starts with no timer of its own, so it fires on the next
        # cycle rather than inheriting the old single-beacon clock.
        if not due(state, timer):
            continue
        counter += 1
        entry, reason = heartbeat(key, room, did, "beacon", counter)
        if entry:
            append_log(entry)
            state[timer] = time.time()
            state[f"beacon_seq:{room}"] = entry["seq"]
            state["counter"] = counter
            changed = True
            done.append(f"beacon:{room}:{entry['seq']}")
        else:
            done.append(f"beacon:{room}:FAILED({reason})")

    # The timer is not the only reason to rewrite the note. Its body names the home
    # room and the log URL, and when either changes the published note is pointing
    # somewhere wrong — which is the whole failure this daemon exists to prevent. So
    # compare what is published against what it should say, ignoring the timestamp,
    # and correct a drifted note immediately rather than a day later.
    published = None
    if not due(state, "note_at"):
        try:
            published = kv_read(*did_note_path(did))
        except NetworkError as error:
            log(f"  could not read the DID note: {error}")
    drifted = published is not None and note_stale(published) != note_stale(note_value(did, ""))
    if drifted:
        log("  the published DID note no longer matches; correcting it now")
    if due(state, "note_at") or drifted:
        if refresh_did_note(did, state):
            state["note_at"] = time.time()
            changed = True
            done.append("note")
        else:
            done.append("note:FAILED")

    if changed:
        state["updated"] = utc_now()
        write_json(STATE_PATH, state)
    late = overdue(state)
    outcome = "ok " + (" ".join(done) if done else "nothing-due")
    if late:
        hours = {n: (time.time() - float(state[n])) / 3600 for n in late}
        outcome += " STALE " + " ".join(f"{n}={hours[n]:.0f}h" for n in late)
    return outcome


def show_status(did: str) -> None:
    namespace, key_name = did_note_path(did)
    state = read_json(STATE_PATH, {})
    print(f"DID          {did}")
    print(f"note path    /kv/{namespace}/{key_name}")
    print(f"home room    {HOME_ROOM}")
    print(f"mailbox      {MAILBOX_ROOM}")
    labels = {"home_at": f"{HOME_ROOM} post", "note_at": "DID note",
              "owner_at": "ownership note"}
    labels.update({f"beacon_at:{room}": f"{room} beacon" for room in BEACON_ROOMS})
    for name in timer_names():
        label = labels[name]
        at = float(state.get(name, 0))
        if not at:
            print(f"  {label:18} never")
        else:
            age_hours = (time.time() - at) / 3600
            mark = "  <-- STALE" if age_hours >= WARN_SECONDS / 3600 else ""
            print(f"  {label:18} {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(at))}"
                  f"  ({age_hours:.1f} h ago, reclaim at {RECLAIM_SECONDS // 3600} h){mark}")
    if state.get("owner_foreign"):
        print(f"  {'owner claim':18} ROOM TAKEN by {state['owner_foreign'][:40]}")
    elif state.get("note_foreign"):
        print(f"  {'owner claim':18} {'yes' if state.get('owner_claimed') else 'not yet'}"
              f"  (NOTE held by someone else)")
    elif state.get("owner_impossible"):
        print(f"  {'owner claim':18} IMPOSSIBLE for {state['owner_impossible']} (it has lived before)")
    else:
        print(f"  {'owner claim':18} {'yes' if state.get('owner_claimed') else 'not yet'}")
    lines = sum(1 for _ in LOG_PATH.open(encoding='utf-8')) if LOG_PATH.exists() else 0
    print(f"  {'log lines':18} {lines}  ({LOG_PATH})")
    # Separate from the timers above: this says the daemon ran, not that it wrote.
    print(f"  {'last run':18} {last_run() or 'never — nothing has invoked this yet'}")

    print("\nlive check:")
    # Read these the way the daemon reads them — through kv_read, which strips the
    # `!! UNTRUSTED CONTENT` banner every /kv reply carries. Printing the raw body put
    # the banner in the 110 characters this line has room for and pushed the value
    # itself off the end, so the one screen a human checks to confirm the note is
    # correct could not show the note. The banner already cost us a 409 once, by being
    # compared instead of stripped; here it cost the diagnostic its whole point.
    for label, ns, key in (
        ("DID note", namespace, key_name),
        ("room owner", "room-owners", HOME_ROOM),
    ):
        try:
            value = kv_read(ns, key)
            print(f"  {label:11} {'(absent)' if value is None else value.strip()[:110]}")
        except NetworkError as error:
            print(f"  {label:11} {error}")
    # The message count, not just the generation: a room at or below the stillborn floor
    # is one the reaper will take within twelve hours, however healthy everything else
    # looks. This is the number that was silently wrong for two days.
    # retained_at_least() asks for exactly MIN_ROOM_MESSAGES rows, so on a healthy room
    # the answer is capped at the floor. Print it as ">= 2", not "2", or a room holding
    # thirteen messages reads as if it were sitting on the edge.
    for label, room in (("home", HOME_ROOM), ("mailbox", MAILBOX_ROOM)):
        count = retained_at_least(room, MIN_ROOM_MESSAGES)
        if count is None:
            print(f"  {label + ' msgs':11} unreadable")
        elif count >= MIN_ROOM_MESSAGES:
            print(f"  {label + ' msgs':11} >= {MIN_ROOM_MESSAGES}  (at or above the stillborn floor)")
        else:
            print(f"  {label + ' msgs':11} {count}"
                  f"  <-- BELOW THE STILLBORN FLOOR ({MIN_ROOM_MESSAGES}); reaped within 12 h")
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
    log(f"home {HOME_ROOM} · beacon {', '.join(BEACON_ROOMS)} · every {EVERY_SECONDS // 3600} h")
    log(f"log  {LOG_PATH}")

    if args.once:
        try:
            outcome = cycle(key, did)
        except Exception as error:
            note_run(f"FAILED {type(error).__name__}: {error}")
            raise
        note_run(outcome)
        log(f"  {outcome}")
        return 0

    log(f"watching. tick {TICK_SECONDS // 60} min. Ctrl+C to stop.")
    while True:
        try:
            note_run(cycle(key, did))
        except KeyboardInterrupt:
            raise
        except Exception as error:  # a bad cycle must never kill the loop
            log("unexpected error in cycle:")
            traceback.print_exc()
            note_run(f"FAILED {type(error).__name__}: {error}")
        time.sleep(TICK_SECONDS)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        raise SystemExit(0)
