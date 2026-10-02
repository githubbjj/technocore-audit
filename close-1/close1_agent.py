#!/usr/bin/env python3
"""close1_agent.py - play Close Call (close-1) short with this folder's did:key.

The bet
-------
close-1 settles every account at S, the last xyz:NVDA trade on Hyperliquid before
10:00:00 UTC on Sunday 4 October 2026. Every owner key starts with 10,000 POLF and
every contract held ties up its entry price: no leverage. So for one key the game is
a direction and a size. The operator chose SHORT, at the largest size the mint can
carry (about 44 contracts at ~225).

How the price is chosen
-----------------------
The fee rule (fold `side_fees`) charges each side 1% of the trade's value, or, for
the side that got a better price than the sweep's close, that gap if it is larger.
For a seller that makes the effective entry min(0.99 x px, close): selling at or
above ~1.01 x close earns exactly the close, selling at the reference earns 0.99 x
the reference, and hitting a bid below it earns less again. So the agent posts its
own sell offers at 1.01 x the reference (what the room's other sellers use, and what
the room's takers countersign within seconds), and only hits someone else's bid when
it is at or above SELL_FLOOR x the reference.

On a loop:

  1. Registers the key once, with the owner message the rules give.
  2. Waits for the sweep that mints it.
  3. Keeps LIVE_OFFERS signed sell offers of OFFER_QTY contracts open, and sells into
     any bid at or above SELL_FLOOR x the reference. Every bid's maker signature is
     checked before we countersign it.
  4. Counts an offer as filled ("likely") when it sees a countersigned copy whose
     taker signature verifies.
  5. Keeps a running estimate of our POLF the way the fold does (every fill, in stamp
     order, costs qty x px plus the fee; a fill the remaining POLF cannot cover is
     void), never countersigns a bid bigger than that estimate can pay for, and exits
     once the estimate cannot buy MIN_QTY more.

What it cannot see
------------------
The referee publishes no per-key balance, a sweep's flow post lists only ~200 of
~1,000 settled ids, and the room moves ~11 messages a second, so a 200-message read
covers only the last ~20 seconds. A trade our remaining POLF cannot cover is void for
both sides and costs nothing, but it is void WHOLE: one 35-contract bid with 4,400
POLF left fills nothing. (v1 of this agent counted such a fill and stopped at about
25 contracts; v2 prices every fill against the POLF estimate, so a restart picks the
void up from state.json and carries on.) The estimate cannot see a trade voided for
the OTHER side's funds, so it can end a little short, never over.

Every message it posts is appended to close1/signed-posts.jsonl with the exact bytes
signed (same format as identity/signed-activity-log.jsonl; verify_log.py reads it).

Usage (from the flop-technocore folder):

    python close1_agent.py              # play, on a loop, until done
    python close1_agent.py --dry-run    # read the market and say what it would do; post nothing
    python close1_agent.py --status     # print what it has done so far
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import time
import traceback
from datetime import datetime, timezone
from decimal import ROUND_DOWN, Decimal
from pathlib import Path

HERE = Path(__file__).resolve().parent
STARTER = HERE / "technocore-did-starter"
sys.path.insert(0, str(STARTER))

try:
    from technocore_agent import (  # audited package
        IdentityError,
        NetworkError,
        ProtocolError,
        did_from_private_key,
        load_identity,
        post_signed_message,
        read_room,
        sign_bytes,
        verify_bytes,
    )
except ImportError as exc:  # pragma: no cover
    print(f"could not import technocore_agent from {STARTER}: {exc}")
    print("run this from the flop-technocore folder, and: python -m pip install cryptography")
    raise SystemExit(1)

# -- configuration -------------------------------------------------------------

KEY_PATH = STARTER / "identity.pem"
PASS_PATH = HERE / "pp.txt"

STATE_DIR = HERE / "close1"
STATE_PATH = STATE_DIR / "state.json"
RUN_LOG = STATE_DIR / "run.log"
SIGNED_LOG = STATE_DIR / "signed-posts.jsonl"

SEASON = "close-1"
TRADING_ROOM = "close1"
PRICE_ROOM = "d-close1-price"
FLOW_ROOM = "d-close1-flow"
PNL_ROOM = "d-close1-pnl"
POSITIONS_ROOM = "d-close1-positions"
REFEREE = "did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"

LOCK_SWEEP = 2556
LOCK_TIME = datetime(2026, 10, 4, 9, 0, 0, tzinfo=timezone.utc)

# The operator's call: short. We are the seller in every trade we make.
OUR_SIDE = "sell"
THEIR_SIDE = "buy"          # a bid we can hit is a maker on the buy side

# Every key is minted 10,000 POLF. Each fill costs qty x px plus the fee: 1%, or the
# gap to the sweep's close if we sold above it by more. COST_BUFFER covers that gap.
MINT = Decimal("10000")
COST_BUFFER = Decimal("1.012")

# Our offers: price = ASK_PREMIUM x reference (effective entry = the close; see top).
ASK_PREMIUM = Decimal("1.01")
LIVE_OFFERS = 2
OFFER_QTY = Decimal("3")
OFFER_UNTIL_AHEAD = 2       # an offer stays good for the landing sweep and two more

# Hitting someone else's bid: never below this fraction of the reference.
SELL_FLOOR = Decimal("0.998")
MAX_ACCEPTS_PER_CYCLE = 6

MIN_QTY = Decimal("0.1")
POLL_SECONDS = 10
TIMEOUT = 20.0
TERMS_KEYS = {"id", "maker", "px", "qty", "side", "taker", "until"}
CENT = Decimal("0.01")


# -- small helpers -------------------------------------------------------------

def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with RUN_LOG.open("a", encoding="utf-8") as handle:
            handle.write(f"{utc_now()} {msg}\n")
    except OSError:
        pass


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    tmp.replace(path)


def canonical(terms: dict) -> str:
    """The exact string both signatures cover: sorted keys, no spaces."""
    return json.dumps(terms, sort_keys=True, separators=(",", ":"))


def amount(value) -> Decimal | None:
    """A price or quantity as the fold reads it: at most two decimals, above zero."""
    if not isinstance(value, str) or not value or len(value) > 12:
        return None
    head, dot, tail = value.partition(".")
    if not head.isdigit() or (dot and (not tail.isdigit() or len(tail) > 2)):
        return None
    number = Decimal(value)
    return number if number > 0 else None


def money(value: Decimal) -> str:
    return str(value.quantize(CENT, rounding=ROUND_DOWN))


def short(did) -> str:
    return str(did)[8:20] + "..."


def append_signed(entry: dict) -> None:
    """Same format as the keepalive's log: the full tuple, re-verifiable offline."""
    SIGNED_LOG.parent.mkdir(parents=True, exist_ok=True)
    with SIGNED_LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")


def record(posted: dict, did: str, kind: str) -> dict:
    return {
        "room": TRADING_ROOM,
        "seq": posted.get("seq"),
        "ts": posted.get("ts"),
        "did": posted.get("from", did),
        "nonce": str(posted.get("nonce", "")),
        "sig": posted.get("sig"),
        "text": posted.get("text"),
        "kind": kind,
    }


def parse(text) -> dict | None:
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def signed_ok(did, sig, payload: str) -> bool:
    try:
        verify_bytes(did, sig, payload.encode("utf-8"))
        return True
    except (IdentityError, ProtocolError, TypeError, ValueError):
        return False


def clean_terms(terms) -> dict | None:
    """The seven terms keys only, or None. (Some relays copy extra keys into terms.)"""
    if not isinstance(terms, dict) or not TERMS_KEYS <= set(terms):
        return None
    return {k: terms[k] for k in TERMS_KEYS}


# -- reading the referee ---------------------------------------------------------

def referee_post(room: str) -> dict | None:
    """The newest post in a referee room, only if the referee signed it."""
    response = read_room(room, limit=1, timeout=TIMEOUT)
    for message in reversed(response.get("messages", [])):
        if message.get("from") == REFEREE:
            return parse(message.get("text"))
    return None


def market() -> dict:
    """Sweep number, the sweep our next trade lands in, the reference and the limits."""
    price = referee_post(PRICE_ROOM)
    if not price:
        raise NetworkError("no referee price post")
    ref = amount(str((price.get("ref") or {}).get("px", "")))
    n = price.get("n")
    lands = price.get("for", (n + 1) if isinstance(n, int) else None)
    if ref is None or not isinstance(n, int) or not isinstance(lands, int):
        raise NetworkError(f"price post not understood: {str(price)[:160]}")
    limits = price.get("limits")
    lo = hi = None
    if isinstance(limits, list) and len(limits) == 2:
        lo, hi = amount(str(limits[0])), amount(str(limits[1]))
    if lo is None or hi is None:
        lo, hi = ref * Decimal("0.95"), ref * Decimal("1.05")
    return {"n": n, "lands": lands, "ref": ref, "lo": lo, "hi": hi}


def ask_price(mk: dict) -> Decimal:
    return min(mk["hi"], (mk["ref"] * ASK_PREMIUM).quantize(CENT, rounding=ROUND_DOWN))


# -- reading the trading room ------------------------------------------------------

def open_bids(messages: list, did: str, mk: dict, taken: set) -> list:
    """Every signed bid in the window we could countersign right now, best first."""
    countersigned = set()
    for message in messages:
        body = parse(message.get("text"))
        if body and body.get("t") == "trade" and body.get("taker_sig"):
            terms = body.get("terms")
            if isinstance(terms, dict) and isinstance(terms.get("id"), str):
                countersigned.add(terms["id"])

    floor = mk["ref"] * SELL_FLOOR
    bids, seen = [], set()
    for message in messages:
        body = parse(message.get("text"))
        if not body or body.get("t") != "trade" or body.get("season") != SEASON:
            continue
        if "taker_sig" in body:
            continue
        terms, maker_sig = body.get("terms"), body.get("maker_sig")
        if not isinstance(terms, dict) or set(terms) != TERMS_KEYS or not isinstance(maker_sig, str):
            continue
        tid = terms["id"]
        if not isinstance(tid, str) or tid in seen or tid in taken or tid in countersigned:
            continue
        seen.add(tid)
        if terms["side"] != THEIR_SIDE or terms["maker"] == did:
            continue
        if terms["taker"] not in ("any", did):
            continue
        px, qty, until = amount(terms["px"]), amount(terms["qty"]), terms["until"]
        if px is None or qty is None or qty < MIN_QTY or type(until) is not int:
            continue
        # one sweep of margin: a post near the boundary can land a sweep late
        if until < mk["lands"] + 1:
            continue
        if not (mk["lo"] <= px <= mk["hi"]) or px < floor:
            continue
        if not signed_ok(terms["maker"], maker_sig, f"{SEASON}|terms|{canonical(terms)}"):
            continue
        bids.append({"terms": terms, "maker_sig": maker_sig, "px": px, "qty": qty,
                     "seq": message.get("seq", 0)})
    bids.sort(key=lambda b: (-b["px"], -b["qty"], b["seq"]))
    return bids


def valid_countersigns(messages: list) -> dict:
    """id -> (seq, taker) of the first countersigned copy whose taker signature verifies."""
    found: dict = {}
    for message in sorted(messages, key=lambda m: m.get("seq", 0)):
        body = parse(message.get("text"))
        if not body or body.get("t") != "trade" or not body.get("taker_sig"):
            continue
        terms = clean_terms(body.get("terms"))
        taker = body.get("taker")
        if terms is None or not isinstance(terms["id"], str) or terms["id"] in found:
            continue
        if not signed_ok(taker, body["taker_sig"], f"{SEASON}|accept|{canonical(terms)}|{taker}"):
            continue
        found[terms["id"]] = (message.get("seq"), taker)
    return found


def someone_else_first(messages: list, tid: str, our_seq: int, did: str) -> bool:
    """True if another key's valid countersigned copy of this id was stamped before ours."""
    earlier = [m for m in messages if isinstance(m.get("seq"), int) and m["seq"] < our_seq]
    hit = valid_countersigns(earlier).get(tid)
    return bool(hit and hit[1] != did)


# -- state -----------------------------------------------------------------------

def load_state() -> dict:
    state = read_json(STATE_PATH, {})
    state.setdefault("fills", {})
    state.setdefault("offers", {})
    return state


HELD = ("likely", "confirmed")


def likely_qty(state: dict) -> Decimal:
    return sum((Decimal(f["qty"]) for f in state["fills"].values()
                if f["status"] in HELD), Decimal(0))


def cost(qty, px) -> Decimal:
    return Decimal(qty) * Decimal(px) * COST_BUFFER


def reconcile(state: dict) -> Decimal:
    """Replay our fills in stamp order against the mint, as the fold's funds check does.
    A likely fill the POLF left could not cover becomes void-funds (and a void-funds
    fill that now fits, after a correction, becomes likely again). Returns POLF left."""
    cash = MINT
    for tid, fill in sorted(state["fills"].items(), key=lambda kv: kv[1].get("seq") or 0):
        if fill["status"] not in HELD + ("void-funds",):
            continue
        need = cost(fill["qty"], fill["px"])
        if fill["status"] == "confirmed" or need <= cash:
            if fill["status"] == "void-funds":
                fill["status"] = "likely"
            cash -= need
        elif fill["status"] == "likely":
            fill["status"] = "void-funds"
            log(f"  {tid}: {fill['qty']} @ {fill['px']} needs {money(need)} POLF, only {money(cash)} left "
                f"-> void (funds), not counted")
    return cash


def confirm_from_flow(state: dict) -> None:
    flow = referee_post(FLOW_ROOM)
    if not flow:
        return
    settled = set(x for x in (flow.get("settled") or []) if isinstance(x, str))
    for tid, fill in state["fills"].items():
        if fill["status"] == "likely" and tid in settled:
            fill["status"] = "confirmed"
            log(f"  confirmed by flow n={flow.get('n')}: {tid} {fill['qty']} @ {fill['px']}")
    for item in flow.get("void") or []:
        tid = item.get("id") if isinstance(item, dict) else item
        if isinstance(tid, str) and tid in state["fills"] and state["fills"][tid]["status"] != "void":
            state["fills"][tid]["status"] = "void"
            log(f"  VOID by flow n={flow.get('n')}: {tid} {item}")


# -- actions -----------------------------------------------------------------------

def post(key, did: str, text: str, kind: str) -> dict:
    response = post_signed_message(key, TRADING_ROOM, text, timeout=TIMEOUT)
    append_signed(record(response["posted"], did, kind))
    return response


def register(key, did: str, state: dict, mk: dict, dry: bool) -> None:
    text = json.dumps({"t": "owner", "season": SEASON, "key": did}, separators=(",", ":"))
    if dry:
        log(f"DRY would register: {text}")
        return
    posted = post(key, did, text, "close1-owner")["posted"]
    state["registered"] = {"seq": posted["seq"], "ts": posted["ts"], "sweep": mk["n"]}
    log(f"registered: close1 seq {posted['seq']} during sweep {mk['n']}; minted by sweep {mk['n'] + 2}")


def note_our_offers(did: str, state: dict, window: list) -> None:
    """Our offers that someone validly countersigned count as likely fills."""
    for tid, (seq, taker) in valid_countersigns(window).items():
        offer = state["offers"].get(tid)
        if offer and tid not in state["fills"]:
            state["fills"][tid] = {"role": "maker", "qty": offer["qty"], "px": offer["px"],
                                   "other": taker, "seq": seq, "sweep": None, "status": "likely"}
            log(f"  offer {tid} countersigned by {short(taker)} ({offer['qty']} @ {offer['px']}) -> likely")


def hit_bids(key, did: str, state: dict, mk: dict, window: list, budget: Decimal, dry: bool) -> Decimal:
    """Sell into good bids we can pay for. Returns the quantity we believe we sold."""
    sold = Decimal(0)
    done = 0
    for bid in open_bids(window, did, mk, set(state["fills"])):
        if done >= MAX_ACCEPTS_PER_CYCLE or budget < cost(MIN_QTY, bid["px"]):
            break
        if cost(bid["qty"], bid["px"]) > budget:
            continue
        terms = bid["terms"]
        done += 1
        if dry:
            log(f"  DRY would sell {terms['qty']} @ {terms['px']} to {short(terms['maker'])} id {terms['id']}")
            sold += bid["qty"]
            budget -= cost(bid["qty"], bid["px"])
            continue
        taker_sig = sign_bytes(key, f"{SEASON}|accept|{canonical(terms)}|{did}".encode("utf-8"))
        text = json.dumps({"t": "trade", "season": SEASON, "terms": terms, "taker": did,
                           "maker_sig": bid["maker_sig"], "taker_sig": taker_sig},
                          separators=(",", ":"))
        try:
            response = post(key, did, text, "close1-trade")
        except NetworkError as error:
            log(f"  post failed for {terms['id']}: {error}")
            continue
        posted = response["posted"]
        lost = someone_else_first(response.get("messages", []) + window, terms["id"], posted["seq"], did)
        status = "lost" if lost else "likely"
        state["fills"][terms["id"]] = {"role": "taker", "qty": terms["qty"], "px": terms["px"],
                                       "other": terms["maker"], "seq": posted["seq"],
                                       "sweep": mk["lands"], "status": status}
        log(f"  sold {terms['qty']} @ {terms['px']} id {terms['id']} seq {posted['seq']} -> {status}")
        if not lost:
            sold += bid["qty"]
            budget -= cost(bid["qty"], bid["px"])
        write_json(STATE_PATH, state)
    return sold


def post_offer(key, did: str, state: dict, mk: dict, qty: Decimal, dry: bool) -> None:
    px = ask_price(mk)
    terms = {"id": f"bm{mk['lands']}-{secrets.token_hex(4)}", "maker": did, "px": money(px),
             "qty": money(qty), "side": OUR_SIDE, "taker": "any",
             "until": mk["lands"] + OFFER_UNTIL_AHEAD}
    if dry:
        log(f"  DRY would offer: {canonical(terms)}")
        return
    maker_sig = sign_bytes(key, f"{SEASON}|terms|{canonical(terms)}".encode("utf-8"))
    text = json.dumps({"t": "trade", "season": SEASON, "terms": terms, "taker": "any",
                       "maker_sig": maker_sig}, separators=(",", ":"))
    posted = post(key, did, text, "close1-offer")["posted"]
    state["offers"][terms["id"]] = {"id": terms["id"], "qty": terms["qty"], "px": terms["px"],
                                    "until": terms["until"], "seq": posted["seq"], "sweep": mk["lands"]}
    log(f"  offered {terms['qty']} @ {terms['px']} (ref {mk['ref']}) until sweep {terms['until']} id {terms['id']}")


def live_offers(state: dict, mk: dict) -> list:
    return [o for o in state["offers"].values()
            if o["until"] >= mk["lands"] and o["id"] not in state["fills"]]


def standing(did: str) -> str:
    notes = []
    for room, label in ((PNL_ROOM, "pnl board"), (POSITIONS_ROOM, "positions board")):
        try:
            board = referee_post(room) or {}
        except (NetworkError, ProtocolError):
            continue
        for rank, row in enumerate(board.get("top") or [], 1):
            if isinstance(row, list) and row and row[0] == did:
                notes.append(f"{label} #{rank}: {row[1:]}")
    return "; ".join(notes) or "not on the published boards (they list only the top few)"


# -- the loop ----------------------------------------------------------------------

def cycle(key, did: str, dry: bool) -> int:
    """One pass. Returns seconds to sleep, or -1 when finished."""
    state = load_state()

    def save() -> None:
        if not dry:
            write_json(STATE_PATH, state)

    mk = market()

    if mk["n"] >= LOCK_SWEEP or datetime.now(timezone.utc) >= LOCK_TIME:
        log("locked - trading is over. S is posted at 10:00 UTC on 4 October.")
        return -1

    if not state.get("registered"):
        register(key, did, state, mk, dry)
        if dry:
            log(f"DRY market: sweep {mk['n']} (next trade lands in {mk['lands']}), ref {mk['ref']}, "
                f"limits {mk['lo']}..{mk['hi']}, our ask would be {money(ask_price(mk))}")
            window = read_room(TRADING_ROOM, limit=200, timeout=TIMEOUT)["messages"]
            bids = open_bids(window, did, mk, set())
            log(f"DRY window: {len(window)} messages, {len(bids)} bid(s) at or above "
                f"{money(mk['ref'] * SELL_FLOOR)}")
            hit_bids(key, did, state, mk, window, MINT, dry)
            post_offer(key, did, state, mk, OFFER_QTY, dry)
            return -1
        save()
        return POLL_SECONDS

    if mk["n"] <= state["registered"]["sweep"]:
        if state.get("_said_wait") != mk["n"]:
            log(f"waiting for the mint: registered in sweep {state['registered']['sweep']}, now {mk['n']}")
            state["_said_wait"] = mk["n"]
            save()
        return POLL_SECONDS

    window = read_room(TRADING_ROOM, limit=200, timeout=TIMEOUT)["messages"]
    note_our_offers(did, state, window)
    if state.get("_flow_n") != mk["n"]:
        confirm_from_flow(state)
        state["_flow_n"] = mk["n"]

    cash = reconcile(state)
    ask = ask_price(mk)
    if cash < cost(MIN_QTY, mk["ref"]):
        save()
        log(f"done: est. position {likely_qty(state)} short, est. POLF left {money(cash)}. {standing(did)}")
        return -1
    sold = hit_bids(key, did, state, mk, window, cash, dry)
    cash = reconcile(state)
    live = live_offers(state, mk)
    free = cash - sum((cost(o["qty"], o["px"]) for o in live), Decimal(0))
    for _ in range(LIVE_OFFERS - len(live)):
        qty = min(OFFER_QTY, (free / (ask * COST_BUFFER)).quantize(CENT, rounding=ROUND_DOWN))
        if qty < MIN_QTY:
            break
        post_offer(key, did, state, mk, qty, dry)
        free -= cost(qty, ask)
    if state.get("_said_n") != mk["n"] or sold:
        log(f"sweep {mk['n']} ref {mk['ref']} ask {money(ask)} | est. position {likely_qty(state)} short, "
            f"POLF left {money(cash)} | live offers {len(live_offers(state, mk))}")
        state["_said_n"] = mk["n"]
    save()
    return POLL_SECONDS


def show_status(did: str) -> None:
    state = load_state()
    print(f"DID         {did}")
    reg = state.get("registered")
    print(f"registered  {reg if reg else 'no'}")
    counts: dict[str, Decimal] = {}
    for fill in state["fills"].values():
        counts[fill["status"]] = counts.get(fill["status"], Decimal(0)) + Decimal(fill["qty"])
    print(f"fills       {', '.join(f'{k} {v}' for k, v in sorted(counts.items())) or 'none'}")
    cash = reconcile(state)
    have = likely_qty(state)
    print(f"position    {have} short (estimate: likely + confirmed, after the funds replay)")
    print(f"POLF left   {money(cash)} (estimate)")
    if have:
        notional = sum((Decimal(f["qty"]) * Decimal(f["px"]) for f in state["fills"].values()
                        if f["status"] in HELD), Decimal(0))
        print(f"avg price   {money(notional / have)}")
    print(f"offers      {len(state['offers'])} posted")
    try:
        mk = market()
        print(f"market      sweep {mk['n']}, reference {mk['ref']}")
        print(f"boards      {standing(did)}")
    except (NetworkError, ProtocolError) as error:
        print(f"market      unreadable: {error}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Play close-1 short with this folder's did:key.")
    parser.add_argument("--dry-run", action="store_true", help="read and decide, post nothing")
    parser.add_argument("--status", action="store_true", help="print progress and exit")
    args = parser.parse_args()

    if not KEY_PATH.exists() or not PASS_PATH.exists():
        print(f"need {KEY_PATH} and {PASS_PATH}")
        return 1
    passphrase = PASS_PATH.read_text(encoding="utf-8").strip().splitlines()[-1].strip()
    try:
        key = load_identity(KEY_PATH, passphrase.encode("utf-8"))
    except IdentityError as error:
        print(f"could not unlock the key: {error}")
        return 1
    del passphrase
    did = did_from_private_key(key)

    if args.status:
        show_status(did)
        return 0

    log(f"close-1 agent | {did} | side {OUR_SIDE.upper()} (short) | sizing by POLF left"
        + (" | DRY RUN" if args.dry_run else ""))
    if args.dry_run and load_state().get("registered"):
        log("DRY: already registered; showing one pass without posting")
    failures = 0
    while True:
        try:
            wait = cycle(key, did, args.dry_run)
            failures = 0
        except KeyboardInterrupt:
            raise
        except Exception as error:  # a bad pass must never kill the loop
            failures += 1
            log(f"error in cycle ({failures} in a row): {type(error).__name__}: {str(error)[:160]}")
            if failures >= 3:
                traceback.print_exc()
            wait = min(POLL_SECONDS * failures, 120)
        if wait < 0 or args.dry_run:
            return 0
        time.sleep(wait)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nstopped.")
