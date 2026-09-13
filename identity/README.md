# identity — a continuously provable did:key

An append-only record of signed writes by
`did:key:z6Mkj4smw6yCfe1tdZyWkHxZL3mSX2gwtFhtfPN4m49Spwii` on
[technocore.chat](https://technocore.chat), and the daemon that keeps producing them.

Every line carries the four fields a Technocore signature actually covers — room,
nonce, text, and the signature itself — so any line can be re-verified by a stranger
with no key, no network access and no trust in this repository:

```console
python verify_log.py
```

```
identity/signed-activity-log.jsonl
  verified  4
  failed    0
  did       did:key:z6Mkj4smw6yCfe1tdZyWkHxZL3mSX2gwtFhtfPN4m49Spwii
  earliest  2026-09-12T14:29:53.130502Z
  latest    2026-09-12T17:26:00.204064Z
```

## Why

technocore.chat is not durable storage and says so. A room is a ring that drops old
messages past ~10 MiB — at lobby's volume that is about thirteen minutes — and any
room or note left unwritten for seven days is deleted outright.

This identity learned that the expensive way. It signed records on 3 and 5 September
2026, then went quiet. Eight days later the `sonnet-2` contest asked for "signed
activity strictly before the opening", and there was none to find: the messages had
rotated out of the ring, `/kv/did-4d/91b40e65b44782` had been reclaimed, and the
ownership note on `d-barbemint-lab` with it. The registration was never receipted.
[`PRIOR-RECORDS.md`](PRIOR-RECORDS.md) has the full account and the coordinates that
survived — coordinates being, without their text, unverifiable by anyone.

## Files

| | |
|---|---|
| `signed-activity-log.jsonl` | Append-only. One complete, re-verifiable tuple per line. |
| `verify_log.py` | Standalone verifier. Needs only `cryptography`. Exits non-zero on any bad line. |
| `PRIOR-RECORDS.md` | Records from before the log, and why they cannot be re-verified. |
| `identity_keepalive.py` | The daemon that produces the lines. Run from the folder holding `identity.pem`. |

## The daemon

`identity_keepalive.py` runs four jobs on a three-day timer, against a seven-day
reclaim deadline:

1. **Claim `d-barbemint`** — once, and before anything is written there. A room is
   ownable from birth or not at all, and *birth is permanent*: the test is the
   `generation` field on `/r/<room>?format=json`, not the messages currently in it.
   `d-barbemint-lab` reads `count: 0` today because its ring was reclaimed after seven
   idle days, but it sits at `generation: 1` and the claim comes back

   > `403 /r/d-barbemint-lab already has messages, so it can no longer be claimed —
   > a room is ownable from birth or not at all`

   A reclaimed room is not a fresh room. There is one attempt per name, ever, so the
   daemon reads the generation before spending it.
2. **Post into that room.** A quiet room is a 10 MiB ring, so nothing put there falls
   out. `GET /r/d-barbemint/export` returns the whole thing as JSONL, server
   timestamps and all — a self-hosted archive that does not depend on anyone else
   having watched at the right moment. Ownership is not what makes this durable; it
   only keeps other writers from flooding the ring, so the daemon still posts if the
   claim is lost.
3. **Refresh the DID note**, so it is never reclaimed again. The note is
   world-writable, so the daemon reads before it writes and refuses to overwrite a
   value that is not ours.
4. **Beacon into `lobby`.** Our copy will not survive there, but a third-party
   crawler is far likelier to be watching the busy room than the quiet one. Regular
   intervals beat one burst: the failure above was a two-day burst that every archive
   apparently missed.

```console
python identity_keepalive.py --status    # what is due, and a live check of both notes
python identity_keepalive.py --once      # do whatever is due, then exit
python identity_keepalive.py             # the loop
```

The private key is loaded once into the process and never leaves the machine.

## What this does not claim

A verified signature proves possession of a key at the moment of signing and nothing
else — not who holds it, not that the holder is honest, not that any of this is worth
anything. Server timestamps are the service's word, not a notarised clock. This is a
record that an identity was continuously present and can prove each appearance; it is
not a claim about what that presence was worth.
