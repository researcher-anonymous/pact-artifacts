# PACT Artifact

This repository contains the proof-of-concept implementation and benchmark
artifacts for PACT, Prefix-Authenticated Chain Tokens. PACT is evaluated here
as a token construction for issuer-rooted authorization-state continuity,
offline extension, local validation, selective presentation, and
bounded-staleness revocation.

The code is a research artifact. It is intended to make the implementation and
evaluation reproducible, not to provide a production authorization system.

The artifact is self-contained. It does not require Git submodules; `schoco/`
is vendored as a normal directory and is referenced by local Go module
`replace` directives.

## Repository Layout

- `pact/`: core PACT token implementation, including issue, extension,
  validation, ID-mode signatures, SchoCo-mode integration, evidence,
  disclosures, verifier relations, and revocation checkpoints.
- `sd/`: salted field commitment and Merkle disclosure layer used by PACT full
  evidence and selective presentations.
- `schoco/`: SchoCo implementation with PACT-aware slot-message APIs.
- `poc/`: local reproducible agentic code-maintenance workflow over
  `poc/fixture-repo`, using HTTP/MCP/A2A-style components.
- `benchmark/`: construction-level benchmark suite with JWS-static,
  JWS-reissued, PACT-ID/ECDSA, PACT-SchoCo, deterministic workflow scenarios,
  explicit ID-versus-SchoCo crossover scaling, and CSV summary tooling.
- `benchmark/paper-results/`: paper reference benchmark CSVs included for
  auditability.

## Artifact Scope

Implemented:

- PACT `ModeID` with ECDSA as the ID-mode signature backend.
- PACT `ModeSchoCo` using the PACT-aware SchoCo APIs.
- Salted field commitments and Merkle disclosure objects.
- Full-chain external evidence `E` and selective disclosure objects `D_{i,J}`.
- Issuer-signed revocation checkpoints `RC_e` with local freshness checks.
- A local issue-investigation, deterministic patch-proposal, patch-application,
  test-execution, and final-artifact-release PoC for issue #184.
- JWS-static, JWS-reissued, PACT-ID/ECDSA, PACT-SchoCo, workflow scenario,
  crossover/scaling, and selective-disclosure benchmarks.
- Deterministic code-maintenance and data-processing benchmark scenarios with
  parameters recorded in `benchmark/scenario_parameters.csv`.
- CSV benchmark reporting with raw rows and summary statistics: count, mean,
  median, standard deviation, p95, min, and max.

Not implemented as main artifact features:

- Production GitHub integration.
- Live LLM integration.
- MCP/A2A protocol-security claims.
- Non-deterministic patch-agent behavior; the PoC uses a deterministic patch
  agent by default.
- Network-latency benchmarks for AS, MCP, or A2A communication.

Legacy/internal code paths may remain for compatibility tests or contextual
experiments.

## Go Modules

This repository is organized as several Go modules. Most modules use Go
`1.23.3`; `poc/` uses Go `1.24.4` with `toolchain go1.24.11` because of its
MCP/A2A dependencies. Run commands from the module directory shown below so
each module uses its own `go.mod` and local `replace` directives.

## Quick Start

Run the core package tests:

```bash
cd pact
env GOCACHE=/tmp/go-build-pact go test -count=1 ./...

cd ../sd
env GOCACHE=/tmp/go-build-sd go test -count=1 ./...

cd ../schoco
env GOCACHE=/tmp/go-build-schoco go test -count=1 ./...
```

Run the PoC tests:

```bash
cd ./poc
env GOCACHE=/tmp/go-build-poc go test -count=1 ./...
```

Run the fixture API regression test:

```bash
cd ./poc/fixture-repo
env GOCACHE=/tmp/go-build-fixture go test -count=1 ./...
```

Run the benchmark smoke suite:

```bash
cd ./benchmark
env GOCACHE=/tmp/go-build-benchmark go test -timeout=30m -run '^$' -bench '^(BenchmarkJWS|BenchmarkPACT)' -benchmem -count=1 ./...
```

## Selective Disclosure And Benchmark Tests

```bash
cd ./sd
env GOCACHE=/tmp/go-build-sd go test -run '^$' -bench . -benchmem -benchtime=1x ./...

cd ./benchmark
env GOCACHE=/tmp/go-build-benchmark go test -run '^$' -bench '^BenchmarkPACTDisclosureLayer' -benchmem -benchtime=1x -count=1 ./...
```

## PoC

The PoC models the task:

> Investigate issue #184: the API returns 500 when `project_id` is empty. If
> the fix is safe, open a PR.

It runs a local, reproducible branch-based bug-fix workflow over
`poc/fixture-repo`:

- root grant `T0 = [n0]`
- context branch `T_ctx = [n0, n1_ctx_scope, n2_ctx_result]`
- patch branch `T_patch = [n0, n1_patch_scope, n2_patch_result]`
- repository branch `T_repo = [n0, n1_repo_scope, n2_apply, n3_test, n4_release]`
- final validation over the joint branch presentation

The context MCP tool reads the real fixture issue, source, and test files and
computes `context_hash`. The A2A patch agent returns a deterministic applicable
unified diff. The repository-management tool copies `poc/fixture-repo` to a
temporary worktree, applies the patch with `git apply`, runs `go test ./...`,
and returns `diff_hash`, `test_result`, `test_log_hash`, and final artifact
metadata. The host validates the joint branch presentation with branch-keyed
evidence and issuer-signed `RC_e` checkpoints.

After root issuance, the services do not contact the authorization server. The
host sends each service a scoped branch prefix plus the checkpoint issued with
`T0`; the service locally extends only that branch and returns the extended
branch to the host.

Useful one-line commands from the repository root:

```bash
cd poc && env GOCACHE=/tmp/go-build-poc go test -count=1 ./...
cd poc/fixture-repo && env GOCACHE=/tmp/go-build-fixture go test -count=1 ./...
```

Containerized demo:

```bash
cd poc && docker compose up --build --abort-on-container-exit --exit-code-from mcp-host mcp-host
cd poc && docker compose down
```

The base Compose startup command is:

```bash
cd poc && docker compose up --build
```

Expected successful host output includes the branch shape:

- `Root grant T0 = [n0]`
- `Context branch T_ctx = [n0, n1_ctx_scope, n2_ctx_result]`
- `Patch branch T_patch = [n0, n1_patch_scope, n2_patch_result]`
- `Repository branch T_repo = [n0, n1_repo_scope, n2_apply, n3_test, n4_release]`
- `Final validation = joint branch validation`

Expected final summary fields include `task_id`, `issue_id`, `repo`,
`allowed_paths`, `context_hash`, `patch_hash`, `diff_hash`,
`test_result: passed`, `test_log_hash`, `artifact_hash`, `modified_paths`,
`final_status: ok`, and `joint_branch_validation: accepted`.

The fixture repository includes the regression test for issue #184 and should
pass when run directly. The Docker Compose flow copies that fixture to a
temporary worktree, applies or recognizes the deterministic patch there, runs
the fixture tests there, and leaves the original `poc/fixture-repo` unmodified.

The PoC proves a local bug-fix workflow: PACT evidence binds the root grant,
repository context, deterministic patch, temporary application, passing test
log, and final artifact release.

## Benchmarks

Target benchmark groups:

- `BenchmarkJWSStatic`
- `BenchmarkJWSReissued`
- `BenchmarkPACTOperation`
- `BenchmarkPACTCodeMaintenance`
- `BenchmarkPACTDepthScaling`
- `BenchmarkPACTParameterScaling`
- `BenchmarkPACTScenario`
- `BenchmarkPACTDisclosureLayer`
- `BenchmarkSD`

Benchmark smoke run:

```bash
cd benchmark
COUNT=1 BENCHTIME=200ms TIMEOUT=30m ./run_bench_csv.sh
```

Paper-style run:

```bash
cd benchmark
COUNT=100 TIMEOUT=120m ./run_bench_csv.sh
```

Use `BENCHTIME` for quicker smoke runs:

```bash
cd benchmark
COUNT=1 BENCHTIME=200ms TIMEOUT=30m ./run_bench_csv.sh
```

The helper writes raw Go benchmark output plus `benchmark_raw.csv` and
`benchmark_summary.csv`.

Reference CSVs used for the paper are included under
`benchmark/paper-results/`:

- `paper_benchmark_raw.csv`
- `paper_benchmark_summary.csv`

They are provided for auditability. Fresh local benchmark runs write to ignored
`bench-results-*` directories.

## Reproducibility Notes

- Benchmark inputs are deterministic at the scenario level, but PACT
  production paths still use fresh random salts.
- Benchmark setup is outside timed validation loops unless setup is the measured
  operation.
- Full evidence `E` carries complete salted field openings; selective
  disclosure objects carry selected openings plus Merkle paths.
- Network latency, live MCP/A2A traffic, production GitHub operations, and live
  LLM calls are excluded from the benchmark suite.
- Docker is needed only for the live PoC demo, not for unit tests or local
  benchmarks.
- The PoC container includes `git` because `server2` uses `git apply` in a
  temporary fixture worktree.