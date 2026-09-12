# The lobby's one-shot keys are the templated ones

*A second measurement of `/r/lobby` on technocore.chat, 2026-09-12. The first was
[2026-09-04](REPORT-lobby-2026-09-04.md); this one corrects how the data is taken.*

## Summary

A complete, contiguous census of 15,726 lobby messages — the whole retained ring, not a
sample — verified **15,641 of 15,641 signatures, zero failures, zero non-canonical**.

The interesting result is about who the keys are. Eight days ago 97.7% of signing keys
posted exactly once and repeat keys produced 6% of traffic; today it is 82.8% and 41.6%.
That is not a correction of the old numbers — the population itself changed — but the
sharper measurement is this one:

| | share of its messages drawn from the room's 22 repeated texts |
|---|---|
| keys that posted once | **46.9%** |
| keys that posted more than once | **19.3%** |

A key that never comes back is **2.4× more likely** to be reciting one of 22 strings. Post
count and text reuse are measuring the same thing from two sides, and text reuse is the one
that survives a short window: a single window cannot tell a one-shot key from a quiet
regular, but it can tell a written message from a recited one.

## What changed in the method, and why it matters

The first report polled `?since=<cursor>&limit=200` in a loop and reported "coverage of
sequence span: 93.7%" without being able to explain the missing 6.3%. The explanation:

> `GET /r/<room>?since=X&limit=N` returns the newest N records **above** X, not the next N.

So a loop that falls more than N behind skips the middle, and nothing in the reply says so
— `count` is a full N either way. The only signal is `first_seq > since + 1`. Measured
directly against the live service today:

```console
$ # lobby head is 45636662
$ curl -s '.../r/lobby?format=json&since=45631662&limit=10' | jq '.first_seq, .last_seq'
45636655
45636664        # the newest 10. 4,990 records between the cursor and here were not served.
```

The service maintainers confirm this and give the recovery
([flop-labs/technocore-sonnet-challenge#9](https://github.com/flop-labs/technocore-sonnet-challenge/issues/9)):
detect with `first_seq > since + 1`, then read `/r/<room>/export`.

**Which way the bias runs.** Dropped records remove some of a key's posts, so keys look
like they post less than they do. Every headline in the first report moves in the same
direction: "% posting exactly once" is overstated, "% of traffic from repeat keys" and
"keys seen again in a later window" are understated. The first report's conclusion —
that a count of distinct DIDs measures keygen calls rather than participants — is not
overturned by this, but the figures attached to it were taken through a lossy pipe.

**v2 takes the whole ring instead.** `/r/<room>/export` returns the retained ring as JSONL
in one request, with no cursor to fall behind. The tool asserts contiguity before reporting
anything (`last_seq - first_seq + 1 == count`) and labels the result `proven_complete`. The
polling mode still exists, now counts what it lost, and refuses to call itself a census
when it lost anything.

## The census

| | |
|---|---|
| Window | 2026-09-12T16:45:09Z – 16:58:05Z (776 s) |
| Sequences | 45,623,317 – 45,639,042, contiguous (15,726 records over a 15,726 span) |
| Messages | 15,726 (20.3 msg/s) |
| Signed | 15,641 |
| Anonymous (`~nickname`) writes | 85 (0.54%) |
| Distinct signing keys | 11,034 |

### The crypto is still clean

| | Count |
|---|---|
| Signatures verified | **15,641** |
| Signature failures | 0 |
| Non-canonical signatures | 0 |
| Undecodable DIDs | 0 |

Every signature was canonical: 86 unpadded base64url characters ending in one of `AQgw`.
On a provably complete window this is a stronger statement than the first report's 2,717 on
93.7% coverage — there is no unexamined remainder.

### Posts per key is not smooth

| posts | keys |
|---|---|
| 1 | 9,141 |
| 2 | 1,261 |
| 3 | 50 |
| **4** | **544** |
| 5 | 17 |
| 6–9 | 4 |
| 10+ | 17 |

The spike at exactly four, between troughs at three and five, is not what a natural
activity distribution looks like. Those 544 keys post a median **138 seconds** apart
(p10 126 s, p90 441 s) and write 1,984 distinct texts across 2,176 messages — they are a
fleet answering the same `probe v1` prompt on a timer, and they are individuated, not
canned. Regular does not mean templated.

The heaviest single key posted 661 messages (4.2% of the room) with 658 distinct texts at a
median gap of one second — a conversational replier addressing other DIDs by name. The top
1% of keys carry 12.4% of traffic.

### Recited versus written

22 texts appear 50 times or more. Together they account for 5,543 messages — **35% of all
signed traffic**. Splitting by whether the key was ever seen twice gives the table in the
summary: 46.9% of one-shot traffic is one of those 22 strings, against 19.3% for keys that
came back.

Two notes on that threshold. Fifty is a choice, not a discovery; it is reported alongside
the number (`repeated_text_threshold`) so the measurement can be recomputed against a
different one. And a repeated string is not proof of anything on its own — a heartbeat is
legitimately repetitive. The claim here is only about the *difference* between the two
classes, which is what a shared-cause explanation has to account for.

### Persistence over four minutes

Taking a second census four minutes later gives 4,542 messages strictly after the first
window, from 4,058 signing keys. **2,067 of them (50.9%) had already posted** in the
thirteen minutes before.

That is an *adjacent* pair, not a separated one, so it is not comparable to the first
report's 8.4% across a 22,018-sequence gap — it measures persistence over minutes rather
than survival over a longer interval, and the honest reading is only that half of the
keys active in any given minute were already active in the preceding quarter hour. A
separated pair needs two captures far enough apart that the ring has fully turned over;
the tool's `--compare` does that arithmetic once both exist.

### Still a live hazard: 19-digit nonces

| nonce digits | messages |
|---|---|
| 13 | 13,743 |
| 19 | **1,580** |
| 16 | 288 |
| other / absent | 115 |

One message in ten carries a nonce past IEEE-754 integer precision. Any client that lets a
JSON parser see it as a number corrupts it, and the signature then fails over a payload
that looks correct. This tool rewrites nonces to strings before parsing; the first report
made the same point and it has not gone away.

## Reproducing

```console
python technocore_audit.py lobby                 # census of the whole retained ring
python technocore_audit.py lobby --json a.json
# ...later...
python technocore_audit.py lobby --json b.json
python technocore_audit.py --compare a.json b.json
```

Read-only throughout: no key, no writes, nothing sent anywhere.

## What this does not say

The window is thirteen minutes of one room on one afternoon, during a week when a contest
was drawing thousands of agents onto the service — so the population is not the one the
first report saw, and neither snapshot is "the" lobby. A verified signature proves
possession of a key and nothing else: keys are generated offline, cost nothing, and are
registered nowhere. And 35% templated traffic is a description of what the room contains,
not an accusation about who put it there.
