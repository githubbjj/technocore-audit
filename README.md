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

- Polls a room with a `since` cursor and de-duplicates by `seq`, reporting how much of the
  sequence range it actually captured.
- Verifies **every** message: decodes the `did:key` to a raw Ed25519 public key, checks the
  signature is canonical (86 unpadded base64url characters, last character one of `AQgw`), and
  verifies it against the exact signed payload.
- Reports key-usage structure: distinct keys, a histogram of posts per key, text duplication,
  nonce digit classes (which reveal different client implementations), and how many messages
  embed their own DID.

It never writes to a room, never needs a private key, and sends nothing anywhere.

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
python technocore_audit.py lobby --seconds 300
python technocore_audit.py lobby --seconds 60 --json capture.json
```

`--json` writes the raw captured messages alongside the report so a run can be re-verified
later by someone who does not trust this tool either.

### Do the same keys come back?

One window cannot tell a one-shot key from an infrequent one — both look like "posted once."
Take two captures separated by a gap and compare them:

```console
python technocore_audit.py lobby --seconds 180 --json a.json
sleep 600
python technocore_audit.py lobby --seconds 180 --json b.json
python technocore_audit.py --compare a.json b.json
```

This reports how many of the later window's keys were already seen, and what share of traffic
comes from keys that appear more than once. In `lobby` on 2026-09-04 the answers were 8.4% and
6.0% — see the report in this repository.

## Reading the output

`signed_and_verified` versus `signature_failures` tells you whether the server's crypto is
honest. `anonymous_writes` is counted separately on purpose: unsigned writes are a supported
mode of the protocol, not broken signatures, and folding them together produces a wrong and
alarming number.

`posts_per_key` tells you something else entirely. A room where nearly every key appears
exactly once is not necessarily a room full of agents; key generation is offline, free, and
unregistered, so one participant can mint a fresh identity per message. Signature validity and
meaningful participation are different measurements, and this tool deliberately reports both.

## Limitations

- A sample is a window, not a census. A key that posts once in your window may be busy outside
  it.
- Polling can miss sequences under load; `coverage_pct` says how many it got.
- The tool measures usage patterns. It does not, and cannot, tell you intent.

## License

MIT.
