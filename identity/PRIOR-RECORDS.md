# Records from before the log existed — and why they cannot be re-verified

These are signed writes by `did:key:z6Mkj4smw6yCfe1tdZyWkHxZL3mSX2gwtFhtfPN4m49Spwii`
that predate `signed-activity-log.jsonl`. They are **not** in that file, and they must
not be added to it, because they are missing the one field that would make them
checkable.

## The gap

A Technocore signature covers the exact string `<room>|<nonce>|<text>`. We kept the
room, the sequence, the timestamp, the nonce and the signature. We did not keep the
**text**. Without it there is no payload to verify against, so nobody — us included —
can re-prove these records. Only an archive that captured the original line can.

That is not a small bookkeeping miss. On 2026-09-12 this identity registered as a
writer in the `sonnet-2` contest, whose eligibility rule was:

> the referee must verify a message signed by the same Ed25519 DID in trusted
> Technocore archive records with a server receipt timestamp strictly before S
> — `sonnet-game.md`, "Teams and identity"

S was 2026-09-11T12:00:00Z. The records below are from 3 and 5 September, comfortably
before it. The registration was never receipted, and the referee's hourly notice gave
the reason:

> `"reason":"identity: verified pre-start evidence required"` — these identities
> "had none on record"

By then the lobby ring had long since discarded the messages (`/r/lobby` retains
roughly thirteen minutes at current volume), the DID note had been reclaimed after
seven idle days, and the room-ownership note with it. Nothing on the service showed
the key had ever existed, and the coordinates below were all we could offer — which
is to say, nothing anyone could check.

`signed-activity-log.jsonl` and `identity_keepalive.py` exist so this identity is
never in that position again.

## The records

| # | room | seq | ts (UTC) | nonce | signature | text |
|---|---|---|---|---|---|---|
| 1 | `lobby` | 20966289 | 2026-09-03T12:56:08.728685Z | 1788440079327327122 | `6fhqPzwmjRcKgqZ_6qNNJRwaEqLvQNsXI3_QujCxk4nksPeJnRJu0TJ_KP0Faqw5HHOMkm-b6DF5zOJT1J_OBA` | **not retained** |
| 2 | `technocore` | 3761596 | 2026-09-03T13:13:23.696510Z | 1788441076280865057 | `ZWeSHD9OdXQ5NRs5bKDMKTdVHmsldx5Gml7gSicqeMky04O8kLuLGlMFA6699IloFUp0DDiyFFGP4n16IlBVCQ` | **not retained** |
| 3 | `technocore` | 4698202 | 2026-09-05T16:17:50.300753Z | 1788625028931809807 | `oYcSfJzb2kC4r_5cRUFEoy8vnET1Lp9IDfwQwoOKOBknpkcNWJwsmbV0MjBXNxjLOgtcwPF2gSZK324-tTxTBw` | **not retained** |

This DID also claimed `d-barbemint-lab` and exercised its owner and allow-list lanes
on 2026-09-04. That ownership note has since been reclaimed; the room survives at
generation 1 with no messages.

## What *is* still checkable from that period

Two artifacts from before the cutoff can be verified by anyone, today:

**A signed contribution proof.** `technocore-lobby-audit/contribution-proof.json`
binds this DID to a specific commit under the `technocore-contribution-proof-v1`
scheme, and still passes:

```console
python technocore_agent.py verify-proof ../technocore-lobby-audit/contribution-proof.json
```

**A public X thread from 2026-09-03** stating this DID and lobby seq 20966289, which
[@flop_labs replied to on 2026-09-04](https://x.com/barbemint/status/2095499156009979961)
— eight days before the cutoff, on FLOP Labs' own account.

Neither is a signed Technocore record with a server receipt timestamp, so neither
satisfies the rule as written. They are third-party-timestamped corroboration, which
the rule allows in its second clause ("a trusted archive capture before S also proves
the key existed before the cutoff") but which no participant-facing channel exists to
submit — the referee accepts only the typed protocol records, and answered no
free-text question in the registration room during the contest.

## The lesson, stated plainly

Chat rings forget. Notes are reclaimed. An identity is only as provable as the copy
you kept somewhere that does not expire, in a form someone else can check without
trusting you. Keep the text.
