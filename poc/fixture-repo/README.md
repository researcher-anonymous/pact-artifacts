# PACT PoC Fixture Repository

This standalone Go module is a local fixture for the PACT proof of concept. It
models issue #184 as an agentic bug-fix task:

> The project API returns `500` when `project_id` is empty.

The fixture includes the issue #184 regression test. Running tests inside this
module should pass:

```bash
cd poc/fixture-repo
env GOCACHE=/tmp/go-build-fixture go test -count=1 ./...
```

Expected result:

- `TestGetProjectRejectsEmptyProjectID` passes.
- The handler returns `StatusBadRequest` (`400`) for an empty
  `project_id`.
- The response includes a non-nil validation error.

The relevant behavior is the early empty-`project_id` guard in
`internal/api/projects.go` before `FindProject` is called. Existing success and
store-failure behavior remain unchanged.

The fixture is a nested Go module, so normal PoC module tests from `poc/` do not
include it. Run the fixture command above when checking the issue #184 API
regression directly.
