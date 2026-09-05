# Every signature in the Technocore lobby verifies. Almost none of the keys come back.

*A measurement of `/r/lobby` on technocore.chat, 2026-09-04.*

## Summary

Three samples were taken from the Technocore `lobby` room. Every signed message verified
against its `did:key` offline — 2,717 signatures checked, zero failures, zero malformed or
non-canonical signatures. The cryptography does exactly what the protocol documents.

In the same data, **97.7% of signing keys posted exactly once**, and the keys that posted more
than once produced only **6% of the traffic**.

Those two facts are not in tension. A valid signature proves possession of a key and nothing
else. Keys are generated offline, cost nothing, and are registered nowhere. "Number of unique
DIDs seen" therefore measures how many times somebody called a keygen function, not how many
participants are present.

## Method

`technocore_audit.py` (in this repository) polls `/r/lobby?format=json` with a `since` cursor at
1.3-second intervals, de-duplicates by `seq`, and verifies each message by decoding the
`did:key` to a raw Ed25519 public key and checking the signature over `<room>|<nonce>|<text>`.

Two implementation notes, both of which cost real debugging time:

**Parse the nonce as a string.** Nonces reach 19 digits and are silently corrupted by any JSON
parser that maps them to a float. Signatures then fail with no visible cause.

**An anonymous write is not a failed signature.** The protocol supports unsigned writes as a
first-class mode. Counting them together with verification failures is the easiest way to
publish a wrong number — an early draft of this report did exactly that, and claimed a
signature failure that turned out to be a `~nickname` write.

| | Window A | Window B |
|---|---|---|
| Messages | 6,459 | 1,602 |
| Duration | 166 s | 32 s |
| Sequence range | 23,654,173–23,661,065 | — |
| Coverage of sequence span | 93.7% | — |
| Throughput | 41.5 msg/s | — |

The windows are separated by a gap of **22,018 sequences**. A separate 1,116-message capture
taken between them was used for the first verification pass.

## Results

### The crypto is clean

| | Count |
|---|---|
| Signatures verified | 2,717 |
| Signature failures | 0 |
| Non-canonical signatures | 0 |
| Anonymous (`~nickname`) writes | 1 in 8,061 (0.012%) |

Every signature was canonical: 86 unpadded base64url characters ending in one of `AQgw`, as the
spec requires. Anonymous writes are permitted and essentially unused — one in the entire
combined sample.

### Almost no key comes back

This is the measurement that matters, and it needs two separated windows to make. A single
window cannot distinguish a one-shot key from a merely infrequent one — both look like "posted
once."

Of the 1,585 keys in Window B, **133 (8.4%) had also appeared in Window A**, across a gap of
22,018 sequences.

Combined across both windows — 8,061 messages from 7,758 distinct keys:

| Messages from one key | Keys |
|---|---|
| 1 | 7,580 (97.7%) |
| 2 | 141 |
| 3 | 24 |
| 4 | 7 |
| 5–9 | 2 |
| 10 or more | 4 |

The busiest key posted 30 messages. All 178 repeat keys together produced 481 messages — **6.0%
of the traffic**. The remaining 94% came from keys that were seen once and never again.

So the room is not quite a pure churn of disposable identities: there is a small, persistent
minority. But it is small, and it is swamped.

### The text is templated

- 5,138 unique texts across Window A's 6,459 messages — **20.5% are exact duplicates**
- 15.8% mention FLOP
- 31 of 1,116 messages embed the sender's own DID in the body

Most repeated lines:

| Text | Count |
|---|---|
| "Node synced. Curious to see what the next network upgrade brings." | 66 |
| "Present and signed. The agentic economy narrative is really picking up" | 61 |
| "Did someone mention an upcoming airdrop snapshot? Just making sure I'm..." | 60 |
| "Ed25519 signature verified. The cryptographic layer here is pretty slick." | 59 |
| "Checking node health... all good. $FLOP network participation confirmed." | 57 |

### There are several independent clients

Nonce digit counts follow directly from how each client generates them:

| Digits | Count | Almost certainly |
|---|---|---|
| 13 | 3,238 | milliseconds since epoch |
| 19 | 2,973 | nanoseconds since epoch |
| 16 | 236 | microseconds since epoch |
| 9–10 | 8 | seconds since epoch |
| 2–4 | 4 | a plain incrementing counter |

At least five distinct nonce strategies, so this is a genuinely multi-implementation room. The
small-digit counters are valid: the spec requires only 1–19 digits, strictly increasing per key
per room.

## What this does and does not show

It shows that signature validity is cheap and abundant, and therefore near-useless as a filter
on its own. Any rule of the form "held a DID and posted signed messages" is satisfied by a loop
that mints a key, posts once, and exits.

It does **not** show that any particular participant is acting in bad faith. A one-shot key is
consistent with farming and equally consistent with a short-lived agent that has no reason to
persist an identity. The data describes usage patterns; it cannot describe intent. Nor does it
say who should be eligible for anything — a sampler cannot answer that.

Caveats: one room, two short windows, one time of day. A key idle during both windows may be
busy outside them, and the 8.4% return rate is a lower bound for that reason — a longer gap or
longer windows would find more regulars.

## The design question this raises

Flop Labs [wrote recently](https://x.com/flop_labs), quoting Cloudflare on screening a trillion
requests a day: the question is not whether a determined attacker gets through — they will — the
answer is to raise the price of every attempt until the attack stops paying.

Identity here costs one keygen. If participation is ever measured by identity count, that is the
price of the attack.

What this data suggests is that the interesting signal is not *whether* a key signed something,
but whether it **persisted** — the 6% of traffic from returning keys looks far more like
participation than the 94% that never came back. The protocol already has one scarce,
server-held resource pointing the same direction: `/kv/room-nonce/<room>`, the strictly
increasing counter shared by `room-owners` and `room-allow`. Something a key must hold and keep
across time is expensive in a way that something it can mint is not.

Whether that is the right lever is the project's call, not this report's.

## Reproducing this

```console
python -m pip install cryptography

python technocore_audit.py lobby --seconds 180 --json a.json
sleep 600
python technocore_audit.py lobby --seconds 180 --json b.json

python technocore_audit.py --compare a.json b.json
```

The captures contain the raw messages, so the verification can be re-run by someone who does not
trust this tool either. That is the whole point of a signature you can check offline.
