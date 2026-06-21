# Benchmark Suite

This directory contains the benchmark suite for the current PACT paper model.
The goal is to quantify PACT operation costs and artifact sizes, compare
against minimal JWS baselines, and compare `PACT-ID/ECDSA` and `PACT-SchoCo`
under deterministic workflow scenarios and synthetic scaling workloads.

The code-maintenance scenario models issue #184 as the branch-based local
bug-fix workflow used by the PoC: one root grant, a context branch, a patch
branch, and a repository-management branch. It stresses evidence accumulation
and artifact dependency checks over context, patch, diff, test-log, and
final-release hashes. Benchmark rows are named `CodeMaintenanceBranch` and
measure joint validation over the branch presentation.

The data-processing scenario is a deterministic five-node workflow:
dataset retrieval, field filtering, aggregation/summary, and report release
after the root grant. It stresses authority narrowing, data-scope constraints,
and selective presentation: audiences and retention windows narrow over the
chain, released fields must be allowed and non-sensitive, summary/report hashes
bind the processing stages, and selected disclosures expose verifier-relevant
release fields without revealing all internal processing fields. Scenario
parameters are recorded in `scenario_parameters.csv`.

The CSV helper used for the paper runs the operation, CodeMaintenance, depth,
parameter-scaling, and disclosure-layer groups. `BenchmarkPACTScenario` is kept
as a direct Go benchmark for the DataProcessing scenario and is included by
manual `go test -bench '^BenchmarkPACT'` runs, but it is not part of the
default `run_bench_csv.sh` paper group.

`TransparentPayload` is an engineering presentation profile used as a size and
validation ablation. It is not a separate PACT cryptographic mode. PACT prefix
authentication remains active, but verifier-relevant fields are embedded
directly in each signed PACT payload instead of being represented by commitment
roots plus external evidence or disclosure objects. This makes it similar to a
JWT-style self-contained presentation for deployments that do not need selective
disclosure. The presentation profile is treated as fixed and issuer-defined for
a benchmark chain; profile mixing within one chain is not evaluated.

## Benchmark Groups

- `BenchmarkJWSStatic`: `jws-static` one-token issue/validate operations plus
  the CodeMaintenance final-artifact lower-bound baseline.
- `BenchmarkJWSReissued`: `jws-reissued` independent JWS tokens for a linear
  six-state workflow and for all CodeMaintenance branch states.
- `BenchmarkPACTOperation`: `pact-operation` root issuance, one-step extension
  from the root, and RC_e checkpoint validation.
- `BenchmarkPACTCodeMaintenance`: `pact-code-maintenance` integrated
  CodeMaintenanceBranch validation for transparent, complete, and selective
  presentations in both PACT modes.
- `BenchmarkPACTScenario`: direct Go benchmark for the five-node
  DataProcessing workflow with complete, transparent, and selective
  presentations. It is not collected by the CSV helper's default paper group.
- `BenchmarkPACTDepthScaling`: `pact-depth-scaling` synthetic linear chains at
  depths `k = 1, 2, 5, 10, 20, 50, 100`; this is where ValidateChain,
  Token+Evidence, Token+Disclosure, ExtendOneAtDepthK, and size rows are
  interpreted as functions of `k`.
- `BenchmarkPACTParameterScaling`: included in the `pact-depth-scaling` CSV
  group. It adds synthetic chain-length rows for `k = 0, 1, 2, 4, 8, 16`,
  fields-per-node rows for `4, 8, 16`, and complete-versus-selective
  presentation-kind rows for the linear six-state fixture.
- `BenchmarkPACTDisclosureLayer`: `pact-disclosure-layer`
  presentation-evidence-only benchmark for `k = 10`, 8 committed fields per
  node, and opened-field counts `1, 2, 4, 8`.
- `BenchmarkSD`: optional standalone selective-disclosure microbenchmarks for
  the current salted field commitment and Merkle disclosure layer.

Falcon is not implemented in this artifact and is not benchmarked.

## Feature Support

| Mechanism | Extensible chain | Offline extension | Local chain validation | Selective presentation | RC_e revocation |
| --- | --- | --- | --- | --- | --- |
| JWS-static | No | No | No | No | No |
| JWS-reissued | No local chain | No | Per-token only | No | No |
| PACT-ID/ECDSA | Yes | Yes | Yes | Yes | Yes |
| PACT-SchoCo | Yes | Yes | Yes | Yes | Yes |

`JWS-static` is one conventional signed bearer token. It has no authenticated
transition history, no selective disclosure, no local derivation, and no RC_e
revocation in this suite. Unsupported operations should be reported as N/A, not
as zero cost.

`JWS-reissued` approximates a centralized workflow design. For a workflow of
`n` logical steps, the authorization server issues `n` independent JWS tokens.
Each token carries the reduced claims for that step, and every transition
requires issuer reissuance. Network latency is not included; issuer interactions
are reported separately as an architectural metric. This approximates the local
cryptographic cost of token-exchange-style reissuance, not authorization-server
latency, availability, policy evaluation, or deployment behavior.

## What Is Measured

- JWS issue, validate, serialized size, and CodeMaintenance lower-bound
  final-artifact validation.
- JWS-reissued total linear workflow issue/validate time and CodeMaintenance
  branch-state validation over independently signed claims.
- PACT root issue, one-step extension from root, and revocation checkpoint
  verification as operation benchmarks.
- Integrated CodeMaintenanceBranch validation with transparent, complete, and
  selective presentations. These rows report branch counts, nodes per branch,
  unique logical nodes, authenticated nodes including repeated roots, issuer
  interactions, token bytes, presentation bytes, checkpoint bytes, and total
  serialized bytes validated.
- Synthetic linear scaling by chain length `k = 0, 1, 2, 4, 8, 16` with 8
  fields per node and 50% disclosure.
- Synthetic linear scaling by fields per node `4, 8, 16` with chain length
  `k = 4` and 50% disclosure.
- Full evidence versus selective disclosure validation and size for the
  workflow-sized chain.
- Scenario validation for the linear DataProcessing workflow is available as
  `BenchmarkPACTScenario` in direct Go benchmark runs. CodeMaintenance is
  reported separately as the integrated reference workflow in the default CSV
  paper groups.
- Synthetic linear depth scaling for chain-only validation, Token+Evidence
  validation, Token+Disclosure validation, depth-dependent extend-one cost, and
  explicit size-only measurements for token, token plus full evidence, and token
  plus selective disclosure.
- Focused selective-disclosure layer cost for synthetic committed nodes. It
  reports `evidence_bytes`, validation latency, `B/op`, and `allocs/op` as the
  verifier opens `1, 2, 4, 8` of 8 committed fields per node. It does not
  validate PACT chain authentication, transition profiles, or revocation.
- Standalone SD field commitment/Merkle-root creation, disclosure creation,
  disclosure verification, and serialized disclosure size for field counts
  `4, 8, 16, 32, 64` and valid reveal counts `1, 2, 4, 8`.

Scenario setup is outside timed validation loops. Production constructors still
use fresh random salts; deterministic salts are not used in benchmarked PACT
paths.

Token+E and Token+D are presentation-package sizes, not bearer-token-only
header sizes. In those profiles, the signed token carries commitments/Merkle
roots and the presentation package additionally carries evidence or disclosure
objects.

Full evidence `E` carries complete salted field openings and no Merkle paths.
It is larger than TransparentPayload, but it uses the same commitment layer that
also enables selective disclosure. Selective disclosure objects carry selected
salted openings plus Merkle paths; they reduce semantic exposure, not
necessarily bytes.
DataProcessing uses a scenario-specific selective disclosure set for report
verification. The semantic DataProcessing relation is measured on full evidence;
the selective workflow rows measure cryptographic validation and size for the
reduced presentation shape.

TransparentPayload rows measure a JWT-style self-contained presentation: the
token contains the verifier-relevant fields directly, no complete evidence `E`
is counted, no selective disclosure `D` is counted, and no presentation salts or
Merkle paths are counted.

`BenchmarkSD` isolates the disclosure layer. It uses salted `FieldOpening`
objects and target disclosure objects directly; it does not perform PACT token
signature validation, verifier-relation evaluation, or revocation checking.

`BenchmarkPACTDepthScaling` is synthetic linear core-chain scaling and
separates timing and size rows. `ValidateChain`, `ValidateTokenPlusEvidence`,
`ValidateTokenPlusDisclosure`, and `ExtendOneAtDepthK` are depth-dependent rows,
not unit operation costs. `SizeToken`, `SizeTokenPlusEvidence`, and
`SizeTokenPlusDisclosure` report the byte metrics used for depth-scaling plots.

`BenchmarkPACTDisclosureLayer` keeps opening/root/disclosure construction
outside the timed loop and times only the presentation-layer checks: disclosed
values, salts, field identifiers, node indexes, Merkle authentication material,
commitment roots, and required-field presence. The `complete` baseline opens all
8 fields once. `selective-current` rows use the current standalone
`sd.Disclosure` JSON format and open `1, 2, 4, 8` fields. `selective-multiproof`
rows use the experimental token-bound per-node multiproof format from `sd` and
open the same field counts; the authenticated root is supplied by the fixture
rather than serialized in each disclosure object. Selective disclosure may be
smaller for few opened fields and may approach or exceed complete evidence when
most fields are opened because it carries salts, field metadata, and Merkle
authentication paths.

## What Is Excluded

- Network latency to the authorization server or Git providers.
- Live MCP/A2A traffic or production MCP/A2A throughput.
- Live Git or GitHub operations.
- Live LLM calls.

The evaluation is deterministic and construction-level: it measures local token
construction, extension, validation, disclosure, evidence, and checkpoint costs.
It does not benchmark live LLMs, live Git providers, network latency, or
production MCP/A2A throughput.

## Reference Results

The CSV files used as paper reference results are included in
`paper-results/`:

- `benchmark_raw.csv`
- `benchmark_summary.csv`

The same directory also includes the raw Go benchmark output for each default
paper group:

- `jws-static.txt`
- `jws-reissued.txt`
- `pact-operation.txt`
- `pact-code-maintenance.txt`
- `pact-depth-scaling.txt`
- `pact-disclosure-layer.txt`

They are included for auditability. Reviewers can regenerate fresh local
outputs with `run_bench_csv.sh`; regenerated `bench-results-*` directories are
ignored by version control.

## Commands

Smoke:

```bash
cd benchmark
env GOCACHE=/tmp/go-build-benchmark go test -timeout=30m -run '^$' -bench '^(BenchmarkJWS|BenchmarkPACT)' -benchmem -count=1 ./...
```

Paper run:

```bash
cd benchmark
COUNT=100 TIMEOUT=120m ./run_bench_csv.sh
```

PACT-only:

```bash
cd benchmark
env GOCACHE=/tmp/go-build-benchmark go test -timeout=30m -run '^$' -bench '^BenchmarkPACT' -benchmem -count=1 ./...
```

SD-only:

```bash
cd benchmark
env GOCACHE=/tmp/go-build-benchmark go test -run '^$' -bench '^BenchmarkSD' -benchmem -count=1 ./...
```

Use a shorter benchtime for development or CI smoke runs:

```bash
cd benchmark
COUNT=1 BENCHTIME=200ms TIMEOUT=30m ./run_bench_csv.sh
```

The CSV helper writes files under a timestamped `bench-results-*` directory
unless `OUTDIR` is provided:

- `jws-static.txt`, `jws-reissued.txt`, `pact-operation.txt`,
  `pact-code-maintenance.txt`, `pact-depth-scaling.txt`, and
  `pact-disclosure-layer.txt`: raw Go benchmark output for each default paper
  group.
- `benchmark_raw.csv`: one row per Go benchmark run, including `ns/op`,
  `B/op`, `allocs/op`, metadata columns (`benchmark_class`, `strategy`, `mode`,
  `presentation_profile`, `workflow`, `branch_count`, `nodes_per_branch`,
  `unique_logical_nodes`, `authenticated_nodes`, `k`, `issuer_interactions`,
  and `timed_scope`), and custom `b.ReportMetric` values such as `token_bytes`,
  `workflow_bytes`, `serialized_token_bytes`,
  `serialized_presentation_bytes`, `total_serialized_bytes_validated`,
  `full_evidence_bytes`, `selective_disclosure_bytes`, `evidence_bytes`,
  `token_plus_evidence_bytes`, `token_plus_disclosure_bytes`,
  per-branch token/evidence/disclosure byte columns, and `checkpoint_bytes`.
  Disclosure-layer rows also include parseable `depth_k`, `fields_per_node`,
  `opened_fields_per_node`, and `profile` columns.
- `benchmark_summary.csv`: one row per benchmark and metric with `count`,
  `mean`, `median`, `stdev`, `p95`, `min`, and `max`.

Run only one or more CSV groups with `BENCH_GROUPS`. Supported groups are
`jws-static`, `jws-reissued`, `pact-operation`, `pact-code-maintenance`,
`pact-depth-scaling`, `pact-disclosure-layer`, and `sd`. The default
`BENCH_GROUPS=paper` runs all groups except optional standalone `sd`.
`BENCH_GROUPS=all` runs every supported CSV group, including `sd`.

```bash
cd benchmark
BENCH_GROUPS=sd COUNT=1 TIMEOUT=30m ./run_bench_csv.sh
BENCH_GROUPS=pact-disclosure-layer COUNT=1 BENCHTIME=200ms TIMEOUT=30m ./run_bench_csv.sh
BENCH_GROUPS=jws-static,jws-reissued,pact-code-maintenance COUNT=1 BENCHTIME=200ms TIMEOUT=30m ./run_bench_csv.sh
```
