# PACT Package

This module implements the core PACT proof of concept. PACT tokens represent an
issuer-rooted chain of authorization-state prefixes. A verifier can validate the
chain locally, recompute authenticated field commitments from external evidence
or selective disclosures, evaluate an application verifier relation, and check
bounded-staleness revocation through issuer-signed checkpoints.

## Modes

Implemented main modes:

- `ModeID`: each prefix is authenticated by a signature. The root prefix `P_0`
  is signed by the issuer. Each extension prefix `P_i`, for `i > 0`, is signed
  by the bearer key authorized by `P_{i-1}`. The current implementation uses an
  ECDSA backend for this mode. Target `ValidatePACT` validation requires an
  `IDKeyResolver` for extension-bearing ID-mode tokens so the extension signer
  is resolved from predecessor-authorized bearer material.
- `ModeSchoCo`: prefixes are authenticated through the PACT-aware SchoCo API.
  PACT prefix `P_i` maps to SchoCo message slot `i+1`.

## Token Lifecycle

Issue:

- Build a root `Payload`.
- Attach a salted commitment root with `AttachCommitmentRootToPayload`.
- Sign the root prefix with `CreateJWS`.

Extend:

- Build the next `LDNode` payload and attach its commitment root.
- In `ModeID`, sign the new prefix with the predecessor-authorized bearer key.
- In `ModeSchoCo`, aggregate using the PACT-aware SchoCo API.
- Store intermediate authentication material in backward links; the current
  token signature authenticates the final prefix.

Validate:

- Reconstruct each prefix exactly as it was signed.
- Validate the chain signatures or SchoCo aggregate signature.
- Validate full evidence `E` or selective disclosure objects `D_{i,J}` against
  authenticated commitment roots.
- Evaluate the optional verifier relation `R_V`.
- Validate the optional or required revocation checkpoint `RC_e`.

## Evidence And Presentations

Full evidence `E` is represented by:

```go
type Evidence struct {
    NodeOpenings map[int][]sd.FieldOpening `json:"node_openings"`
}
```

It carries complete salted field openings for each evidenced node. It does not
carry Merkle paths. During validation, PACT recomputes each field commitment
from the opening, rebuilds the complete node Merkle root, and compares that
root to the value authenticated in the token payload.

Selective presentations use `sd.Disclosure`. A disclosure contains the
authenticated root, selected indices, selected salted openings, and Merkle paths
for those selected fields. This is the path-bearing object used when only part
of a node is presented.

## Prefix Reconstruction

A token with `k` extensions contains `k+1` authenticated prefixes:

- `P_0`: the root payload without extensions.
- `P_i`: the root plus the first `i` extension nodes.
- `P_k`: the current token payload.

For `ModeID`, intermediate signatures are stored as backward links on extension
nodes, and the final signature is the token signature. For `ModeSchoCo`, the
package reconstructs prefixes in natural PACT order and passes them to
`schoco.VerifyPACT`, which maps `P_i` to slot `i+1`.

## Validation Pipeline

`ValidatePACT` has explicit stages:

1. Chain signature validation.
2. Commitment/evidence or disclosure validation.
3. Verifier relation `R_V`.
4. Revocation checkpoint validation.

`ValidationOptions` carries the external inputs used by these stages:

- `TrustedIssuerPK`
- `IDKeyResolver`
- `Evidence`
- `Presentations`
- `VerifierRelation`
- `RevocationCheckpoint`
- `RequireRevocation`
- `Tau`
- `ClockSkew`
- `Now`

Revocation checkpoints are verified against the configured trusted issuer key,
not against a public key embedded in the checkpoint.

For ID-mode tokens with extensions, `ValidatePACT` rejects if `IDKeyResolver` is
nil. Root-only ID-mode tokens still validate with `TrustedIssuerPK` alone.

## Tests

```bash
cd pact
env GOCACHE=/tmp/go-build-pact go test -count=1 ./...
```
