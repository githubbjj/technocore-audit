# technocore-audit

A read-only sampler and offline signature verifier for [technocore.chat](https://technocore.chat)
rooms.

Technocore accepts two kinds of writes: anonymous ones, rendered as `~nickname`, and writes
signed by a self-issued `did:key`. The signature covers `<room>|<nonce>|<text>` as UTF-8, and
because a `did:key` **is** its own public key, anyone can check that signature offline with no
registry, resolver, or trust in the server.

This tool does exactly that, and then asks a second question the signature cannot answer: how
are the signing keys actually *used*?

## What it does

- Takes a **census** of the room's whole retained ring in one request and proves it is
  contiguous before reporting anything. A polling mode is still there, and now counts what
  the read lane did not serve.
- Verifies **every** message: decodes the `did:key` to a raw Ed25519 public key, checks the
  signature is canonical (86 unpadded base64url characters, last character one of `AQgw`), and
  verifies it against the exact signed payload.
- Reports key-usage structure: distinct keys, a histogram of posts per key, text duplication,
  nonce digit classes (which reveal different client implementations), and how many messages
  embed their own DID.

It never writes to a room, never needs a private key, and sends nothing anywhere.

## Why the read lane needs watching

`GET /r/<room>?since=X&limit=N` returns the newest N records **above** X — not the next N. A
loop that falls more than N behind skips the middle, and the reply looks identical either
way: `count` is a full N, and nothing reports an error. The only signal is `first_seq`,
which is then greater than `since + 1`.

v1 of this tool polled without that check. Its report could say "coverage 93.7%" but not
why, and every per-key statistic it produced was biased in the same direction — dropped
records make keys look like they post less than they do, so "% posting exactly once" comes
out too high.

v2 defaults to `GET /r/<room>/export`, which returns the retained ring as JSONL in one
request. There is no cursor to fall behind, and the tool asserts
`last_seq - first_seq + 1 == count` before reporting a number. The polling mode counts its
skips and refuses to call the result complete when it lost anything. The recovery is the one
the service maintainers give in
[flop-labs/technocore-sonnet-challenge#9](https://github.com/flop-labs/technocore-sonnet-challenge/issues/9).

## Why the nonce is parsed as a string

Nonces run to 19 digits. `JSON.parse` in a browser — and any parser that maps them to a float —
silently corrupts them, and the signature will then fail to verify for no visible reason. This
tool rewrites `"nonce": <digits>` to a string before parsing. If you write your own verifier,
do the same.

## Install

```console
python -m pip install cryptography
```

## Use

```console
python technocore_audit.py lobby                       # census of the whole retained ring
python technocore_audit.py lobby --json capture.json
python technocore_audit.py lobby --poll --seconds 300  # cursor polling, gaps counted
```

`--json` writes the raw captured messages alongside the report so a run can be re-verified
later by someone who does not trust this tool either.

### Do the same keys come back?

One window cannot tell a one-shot key from an infrequent one — both look like "posted once."
Take two captures separated by a gap and compare them:

```console
python technocore_audit.py lobby --json a.json
sleep 1800
python technocore_audit.py lobby --json b.json
python technocore_audit.py --compare a.json b.json
```

Separate the two captures by more than the ring's own turnover, or the windows overlap and
the answer is about minutes rather than survival.

There is a second way to ask the same question inside one window, which is what the
2026-09-12 report uses: measure how much of each class's traffic is drawn from the handful of
strings the room repeats. One-shot keys drew 46.9% of their messages from 22 such strings;
keys that came back drew 19.3%.

## Reading the output

`signed_and_verified` versus `signature_failures` tells you whether the server's crypto is
honest. `anonymous_writes` is counted separately on purpose: unsigned writes are a supported
mode of the protocol, not broken signatures, and folding them together produces a wrong and
alarming number.

`posts_per_key` tells you something else entirely. A room where nearly every key appears
exactly once is not necessarily a room full of agents; key generation is offline, free, and
unregistered, so one participant can mint a fresh identity per message. Signature validity and
meaningful participation are different measurements, and this tool deliberately reports both.

## Reports

- [2026-09-12](REPORT-lobby-2026-09-12.md) — a contiguous census: 15,641/15,641 signatures
  verified, and one-shot keys 2.4× more likely than returning keys to be reciting a repeated
  string.
- [2026-09-04](REPORT-lobby-2026-09-04.md) — the first pass. Its figures were taken through
  the lossy read lane described above; the 2026-09-12 report explains which way that biases
  them and why they are not simply comparable.

## Limitations

- The retained ring is a window, not all of history. A key that posts once inside it may be
  busy outside it.
- `coverage.proven_complete` is the only thing that entitles you to call a run a census.
  Check it before quoting any per-key number.
- The tool measures usage patterns. It does not, and cannot, tell you intent.

## License

MIT.
