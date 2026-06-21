# PACT Agentic Code-Maintenance PoC

This module contains the local proof of concept for the PACT paper artifact. It
models one reproducible agentic code-maintenance workflow over
`poc/fixture-repo`:

> Investigate issue #184: the API returns 500 when `project_id` is empty. If
> the fix is safe, open a PR.

The workflow is local and deterministic by default. It does not call GitHub and
does not call a live LLM.

## Components

- Authorization server, `as/`, port `8080`: issues the root PACT token and
  exposes the latest issuer-signed revocation checkpoint `RC_e`.
- MCP host, `mcp-host/`: orchestrates the workflow.
- Context MCP tool, `server1/`, port `8081`: reads the fixture issue, source,
  and test files and computes `issue_hash`, `files_hash`, and `context_hash`.
- A2A patch agent, `agent/`, port `8082`: returns a deterministic applicable
  unified diff, `patch_hash`, `rationale_hash`, model ID, and risk level.
- Repository-management MCP tool, `server2/`, port `8083`: copies the fixture
  repo to a temporary worktree, applies the patch with `git apply`, runs
  `go test ./...`, computes `diff_hash` and `test_log_hash`, and returns final
  artifact evidence.
- Shared workflow package, `internal/workflow/`: claim builders,
  linear compatibility relation, branch claim builders, and strict PACT
  validation helpers.

## Workflow

0. The authorization server issues root grant `T0 = [n0]`, bound to `task_id`,
   `repo`, `issue_id`, `branch_prefix`, `allowed_paths`, and workflow
   permissions.
1. The host derives context scope from retained `T0`:
   `T_ctx = [n0, n1_ctx_scope]`. The context tool extends only that branch to
   `T_ctx = [n0, n1_ctx_scope, n2_ctx_result]`.
2. The host derives patch scope from retained `T0`, with dependency on
   `context_hash`: `T_patch = [n0, n1_patch_scope]`. The A2A patch agent extends
   only that branch to `T_patch = [n0, n1_patch_scope, n2_patch_result]`.
3. The host derives repository scope from retained `T0`, with dependencies on
   `context_hash` and `patch_hash`: `T_repo = [n0, n1_repo_scope]`.
4. Repository management extends only the repository branch with
   `n2_apply`, `n3_test`, and `n4_release`.
5. The host validates a joint branch presentation containing the context, patch,
   and repository branches plus branch-keyed evidence and `RC_e`.

After `T0` issuance, downstream components do not contact the authorization
server. The host passes the scoped branch token, disclosures/evidence, and the
issuer-signed `RC_e` checkpoint to each component; each component then extends
only its assigned branch locally.

## Validation

PoC services use `ValidatePACT`, not `ValidateJWSWithPresentations`. Validation
uses target PACT APIs with salted openings, full-chain evidence or selective
disclosure objects, and issuer-signed revocation checkpoints.

Before validation, services obtain `RC_e` from a small local cache. A cached
checkpoint is used while fresh under `tau`; otherwise the service fetches the
latest checkpoint from the authorization server. With `RequireRevocation=true`,
validation rejects if no fresh checkpoint is available.

Strict validation options include:

- trusted issuer public key;
- `RequireRevocation=true`;
- freshness bound `Tau`;
- allowed clock skew;
- fetched or cached `RevocationCheckpoint`;
- full evidence or selective disclosure inputs as required by the service.

Revocation checkpoints are verified against the configured trusted issuer key,
not against a key embedded in the checkpoint.

## Branch Validation

The final host validation uses `ValidateBranchedCodeMaintenance`. It validates
each branch independently and then checks the joint presentation:

- all branches share `tid_0`, `task_id`, `repo`, and `issue_id`;
- `task_id`, `repo`, and `issue_id` are present on every evaluated node and
  equal the root values;
- enabled permissions are drawn from the closed workflow vocabulary;
- each node's permissions are a subset of the root permissions and match the
  node's workflow role;
- context branch evidence contains `issue_hash`, `files_hash`, and
  `context_hash`;
- patch scope and result bind `patch_hash` and `rationale_hash` to
  `context_hash`;
- repository scope binds to `context_hash` and `patch_hash`;
- application evidence binds `diff_hash` to `patch_hash`;
- modified paths stay within root `allowed_paths`;
- test evidence binds `test_log_hash` to `diff_hash` and requires
  `test_result=passed`;
- final artifact evidence binds `diff_hash`, `test_log_hash`, and `branch`;
- final `branch` starts with `branch_prefix`;
- `RC_e` is fresh and `tid_0` is not revoked.

## Automated Tests

The PoC tests cover the valid workflow and negative paths for permission
escalation, unexpected permission fields, repo/issue/task mismatches, omitted
bindings, path-policy enforcement, patch/diff/test/final binding failures,
branch-prefix enforcement, stale or missing revocation checkpoints, revoked
`tid_0`, and tampered evidence.

```bash
cd poc && env GOCACHE=/tmp/go-build-poc go test -count=1 ./...
cd poc/fixture-repo && env GOCACHE=/tmp/go-build-fixture go test -count=1 ./...
```

The fixture repository includes the issue #184 regression test and should pass
when run directly.

## Notes

The branch workflow represents the local bug-fix task that PACT validates:
root grant, repository context branch, patch branch, and repository-management
branch with application, test, and release evidence. The PoC copies
`poc/fixture-repo` to a temporary worktree, applies or recognizes the
deterministic patch there with `git apply`, runs `go test ./...` there, and
discards the temporary copy. The original fixture repo remains unmodified.
Final validation proves that the PACT evidence binds the context, patch,
applied diff, passing test log, and final artifact metadata for this local
workflow.

## Containerized Demo

The live demo runs the same conceptual workflow as the tests, but the
components communicate over HTTP/MCP/A2A-style service boundaries.

```bash
cd poc && docker compose up --build --abort-on-container-exit --exit-code-from mcp-host mcp-host
```

The base Compose startup command is:

```bash
cd poc && docker compose up --build
```

Expected successful host output includes:

- `User task: Investigate issue #184...`
- `Branch-based local bug-fix workflow:`
- `Root grant T0 = [n0]`
- `Context branch T_ctx = [n0, n1_ctx_scope, n2_ctx_result]`
- `Patch branch T_patch = [n0, n1_patch_scope, n2_patch_result]`
- `Repository branch T_repo = [n0, n1_repo_scope, n2_apply, n3_test, n4_release]`
- `Final validation = joint branch validation`
- `Fixture regression test is present in poc/fixture-repo.`
- `Original fixture repo is not modified.`
- `Patch workflow runs only in a temporary worktree.`
- `Fixture tests pass in the temporary worktree.`
- `Context hash: context:...`
- `Patch hash: patch:...`
- `Joint branch validation: accepted`
- `PACT branch summary:`
- `Dependency summary:`
- `Final summary: ... test_result:passed ... final_status:ok ...`
- `PoC flow completed successfully`

Expected final summary fields include:

- `task_id`
- `issue_id`
- `repo`
- `allowed_paths`
- `context_hash`
- `patch_hash`
- `diff_hash`
- `test_result: passed`
- `test_log_hash`
- `artifact_hash`
- `modified_paths`
- `final_status: ok`
- `joint_branch_validation: accepted`

Clean up containers after the demo:

```bash
cd poc && docker compose down
```

If Docker is unavailable, the automated Go tests remain the primary
reproducible execution mode.

## Limitations

- No production GitHub integration is included.
- The patch agent is deterministic by default; this PoC does not evaluate LLM
  coding quality.
- No live LLM is used.
- The PoC does not make claims about MCP/A2A protocol security.
- The container image includes `git` because `server2` uses `git apply`.
- PR URLs are local/demo metadata, not production GitHub operations.
- The PoC demonstrates local validation semantics; it is not a production
  authorization service.
