# SchoCo Package

This directory is vendored as a normal folder inside the PACT artifact. It is
not a Git submodule and does not require `git submodule update`.

This module contains the PACT-aware SchoCo implementation used by PACT
`ModeSchoCo`. Within this artifact, SchoCo is not used as a generic application
API; it is used to authenticate PACT prefixes with an explicit slot mapping.

## PACT-Aware API

PACT integrations should use:

- `PACTSlotMessage(slot uint64, prefix []byte) []byte`
- `StdSignPACT(slot uint64, prefix []byte, sk *edwards25519.Scalar)`
- `AggregatePACT(slot uint64, prefix []byte, prev *Signature)`
- `VerifyPACT(rootPK *edwards25519.Point, prefixes [][]byte, partSigs []*edwards25519.Point, lastSig *Signature)`

The generic raw-message APIs remain available for low-level compatibility tests
and non-PACT experiments, but PACT `ModeSchoCo` uses the PACT-aware wrappers.

## Prefix Mapping

PACT prefixes are passed to `VerifyPACT` in natural order:

```text
prefixes[0] = P_0
prefixes[1] = P_1
...
prefixes[k] = P_k
```

`VerifyPACT` maps `P_i` to SchoCo slot `i+1` internally. Callers do not manually
construct raw SchoCo messages for normal PACT validation.

## Slot Message Encoding

`PACTSlotMessage` includes:

- a domain separator: `PACT-SCHOCO-SLOT-V1`;
- the one-based slot/index;
- the PACT prefix bytes.

Variable-length fields are length-prefixed, and the slot is fixed-width
big-endian. This makes the signed message encoding unambiguous and prevents a
PACT integration from accidentally signing only raw prefix bytes.

## Challenge Scalars

SchoCo challenge derivation uses a domain-separated transcript and canonical
scalar reduction via the `filippo.io/edwards25519` APIs. Nonce/key generation is
kept separate from challenge scalar derivation.

## Test Coverage

Tests cover:

- slot 1 versus slot 2 for the same prefix;
- different prefixes in the same slot;
- ambiguous raw-concatenation cases;
- deterministic slot-message construction;
- `P_0 -> slot 1`, `P_1 -> slot 2`, and so on;
- reorder, reindex, missing-prefix, and same-length replacement rejection;
- rejection of PACT validation for signatures produced over raw messages that
  omit the slot/index.

## Tests

```bash
cd ./schoco
env GOCACHE=/tmp/go-build-schoco go test -count=1 ./...
```

Benchmarks local to this module can be run with:

```bash
cd ./schoco
env GOCACHE=/tmp/go-build-schoco go test -run '^$' -bench . -benchmem ./...
```
