# Selective Disclosure Layer

This module implements the salted field commitment and Merkle disclosure layer
used by the PACT artifact. The same commitment layer is used for full-chain
evidence and selective presentations.

## Field Commitments

Each disclosed or evidenced field is represented by a `FieldOpening`:

- `tid_0`
- `node_index`
- `field_index`
- `tag`
- `salt`
- canonical field value encoding

The commitment is:

```text
H(dom_SD || tid_0 || node_index || field_index || tag || salt || canonical_field_encoding)
```

The implementation uses an injective length-prefix encoding for variable-length
components before hashing. This avoids ambiguous raw concatenation.

## Merkle Roots and Disclosures

For each PACT node:

1. Field openings are converted to field commitments.
2. Commitments are placed in canonical field order.
3. A Merkle root is computed and stored in the authenticated PACT payload.

Selective disclosure object `D_{i,J}` contains:

- the authenticated root;
- selected field openings;
- selected field indices;
- Merkle paths for those fields.

`VerifyDisclosure` recomputes the selected commitments and checks that their
paths reconstruct the authenticated root. Signature validation is performed by
the PACT layer, not by this module.

Target `ValidatePACT` validation accepts disclosure objects that contain salted
field `Openings`. Legacy leaf-only disclosures may still be understood by
legacy helpers, but they are not part of the target PACT validation path.

## Full Evidence and Selective Disclosure

Full-chain evidence `E` is external to the token and carries all openings needed
for the nodes evaluated by the verifier relation. It does not carry Merkle
paths; PACT recomputes the complete node root from the complete opening set.
Selective disclosure `D_{i,J}` carries only selected openings and Merkle paths.
Both use the same field commitment construction.

A compact complete-presentation format can be layered on this construction
without changing token semantics: for a complete node presentation, values,
tags, and salts are sufficient when `tid_0`, node index, and canonical field
indices are derived from the validated token and node position. The current
artifact still serializes full evidence as `FieldOpening` objects for clarity
and compatibility.

## Salt Behavior

Production constructors use `crypto/rand` to generate fresh salts. Salts should
not be reused across fields, nodes, or tokens.

Deterministic salts exist only in explicit test helpers, such as
`NewDeterministicFieldOpeningForTest`, to support stable fixtures and test
vectors.

## Test Coverage

The package and PACT integration tests cover:

- deterministic canonical encoding;
- fresh salts changing commitments;
- tampering with value, salt, tag, `tid_0`, node index, or field index;
- recomputing the same Merkle root from the same openings;
- using the same commitment layer for full evidence and selective disclosure.

## Tests

```bash
cd ./sd
env GOCACHE=/tmp/go-build-sd go test -count=1 ./...
```

Benchmarks local to this module can be run with:

```bash
cd ./sd
env GOCACHE=/tmp/go-build-sd go test -run '^$' -bench . -benchmem ./...
```
