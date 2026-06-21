package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anonymous-artifact/schoco"
	"flow-poc/internal/pocconfig"
	"flow-poc/internal/workflow"
	pact "flow-poc/pact"
	sd "flow-poc/sd"
)

func TestExecuteLocalRepositoryWorkflowAppliesPatchAndPassesTests(t *testing.T) {
	fixtureRoot, err := findFixtureRepo()
	if err != nil {
		t.Fatal(err)
	}
	originalPath := filepath.Join(fixtureRoot, "internal", "api", "projects.go")
	before, err := os.ReadFile(originalPath)
	if err != nil {
		t.Fatal(err)
	}

	patchText := deterministicAgentPatchText()
	result, err := executeLocalRepositoryWorkflow(context.Background(), patchText, workflow.ComputePatchHash(patchText))
	if err != nil {
		t.Fatal(err)
	}

	if result.TestResult != "passed" {
		t.Fatalf("test_result = %q, want passed\noutput:\n%s", result.TestResult, result.TestOutput)
	}
	if result.PatchHash != workflow.ComputePatchHash(patchText) {
		t.Fatalf("patch_hash = %q, want computed patch hash", result.PatchHash)
	}
	if result.DiffHash == "" || !strings.HasPrefix(result.DiffHash, "diff:") {
		t.Fatalf("diff_hash = %q, want diff: hash", result.DiffHash)
	}
	if result.TestLogHash == "" || !strings.HasPrefix(result.TestLogHash, "test-log:") {
		t.Fatalf("test_log_hash = %q, want test-log: hash", result.TestLogHash)
	}
	if len(result.ModifiedPaths) != 1 || result.ModifiedPaths[0] != "internal/api/projects.go" {
		t.Fatalf("modified_paths = %#v, want internal/api/projects.go", result.ModifiedPaths)
	}

	after, err := os.ReadFile(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("original fixture repository was mutated")
	}
}

func TestExecuteLocalRepositoryWorkflowRejectsPatchHashMismatch(t *testing.T) {
	if _, err := executeLocalRepositoryWorkflow(context.Background(), deterministicAgentPatchText(), "patch:wrong"); err == nil {
		t.Fatal("patch_hash mismatch was accepted")
	}
}

func TestExtendLocalArtifactTokenProducesValidRepositoryBranch(t *testing.T) {
	token, evidence, rc := buildPatchPrefix(t)
	result := validLocalRepositoryResult()

	artifacts, err := extendLocalArtifactToken(token, "context:fixture", result)
	if err != nil {
		t.Fatal(err)
	}
	evidence.NodeOpenings[2] = artifacts.ApplicationOpenings
	evidence.NodeOpenings[3] = artifacts.TestOpenings
	evidence.NodeOpenings[4] = artifacts.FinalOpenings

	if err := workflow.ValidateWithRevocation(artifacts.Token, evidence, nil, nil, rc, time.Unix(1000, 0)); err != nil {
		t.Fatalf("repository branch rejected: %v", err)
	}
}

func TestExtendLocalArtifactTokenMissingFinalNodeFails(t *testing.T) {
	token, evidence, rc := buildPatchPrefix(t)
	artifacts, err := extendLocalArtifactToken(token, "context:fixture", validLocalRepositoryResult())
	if err != nil {
		t.Fatal(err)
	}
	evidence.NodeOpenings[2] = artifacts.ApplicationOpenings
	evidence.NodeOpenings[3] = artifacts.TestOpenings

	if err := workflow.ValidateWithRevocation(artifacts.Token, evidence, nil, nil, rc, time.Unix(1000, 0)); err == nil {
		t.Fatal("missing final artifact node was accepted")
	}
}

func TestExtendLocalArtifactTokenFailedTestResultFails(t *testing.T) {
	token, evidence, rc := buildPatchPrefix(t)
	result := validLocalRepositoryResult()
	result.TestResult = "failed"
	artifacts, err := extendLocalArtifactToken(token, "context:fixture", result)
	if err != nil {
		t.Fatal(err)
	}
	evidence.NodeOpenings[2] = artifacts.ApplicationOpenings
	evidence.NodeOpenings[3] = artifacts.TestOpenings
	evidence.NodeOpenings[4] = artifacts.FinalOpenings

	if err := workflow.ValidateWithRevocation(artifacts.Token, evidence, nil, workflow.CodeMaintenanceRelation{}, rc, time.Unix(1000, 0)); err == nil {
		t.Fatal("failed test_result was accepted")
	}
}

func TestExtendLocalArtifactTokenBranchPrefixViolationFails(t *testing.T) {
	token, evidence, rc := buildPatchPrefix(t)
	result := validLocalRepositoryResult()
	result.Branch = "feature/unrelated"
	artifacts, err := extendLocalArtifactToken(token, "context:fixture", result)
	if err != nil {
		t.Fatal(err)
	}
	evidence.NodeOpenings[2] = artifacts.ApplicationOpenings
	evidence.NodeOpenings[3] = artifacts.TestOpenings
	evidence.NodeOpenings[4] = artifacts.FinalOpenings

	if err := workflow.ValidateWithRevocation(artifacts.Token, evidence, nil, workflow.CodeMaintenanceRelation{}, rc, time.Unix(1000, 0)); err == nil {
		t.Fatal("branch prefix violation was accepted")
	}
}

func deterministicAgentPatchText() string {
	return `diff --git a/internal/api/projects.go b/internal/api/projects.go
index 0000000..0000000 100644
--- a/internal/api/projects.go
+++ b/internal/api/projects.go
@@ -34,6 +34,13 @@ func NewHandler(store ProjectStore) *Handler {
 }
 
 func (h *Handler) GetProject(projectID string) Response {
+	if projectID == "" {
+		return Response{
+			StatusCode: StatusBadRequest,
+			Err:        errors.New("project_id is required"),
+		}
+	}
+
 	project, err := h.store.FindProject(projectID)
 	if err != nil {
 		return Response{
`
}

func validLocalRepositoryResult() *localRepositoryResult {
	return &localRepositoryResult{
		Branch:        workflow.BranchPrefix + "-empty-project-id",
		ModifiedPaths: []string{"internal/api/projects.go"},
		DiffHash:      "diff:fixture",
		TestResult:    "passed",
		TestLogHash:   "test-log:fixture",
		PatchHash:     "patch:fixture",
		ArtifactHash:  "artifact:fixture",
	}
}

func buildPatchPrefix(t *testing.T) (string, *pact.Evidence, *pact.RevocationCheckpoint) {
	t.Helper()
	now := time.Unix(1000, 0)
	sk, pk, err := schoco.KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	root := &pact.Payload{Ver: pact.ModeSchoCo, TID0: workflow.TaskID, NodeIndex: 0, Iat: now.Unix(), Iss: &pact.IDClaim{PK: pk.Bytes(), CN: "issuer"}}
	_, rootOpenings, err := pact.AttachCommitmentRootToPayload(root, root.TID0, 0, workflow.RootClaims(workflow.LocalWorkflowPermissions))
	if err != nil {
		t.Fatal(err)
	}
	token, err := pact.CreateJWS(root, pact.ModeSchoCo, sk)
	if err != nil {
		t.Fatal(err)
	}
	evidence := &pact.Evidence{NodeOpenings: map[int][]sd.FieldOpening{0: rootOpenings}}

	token = appendTestNode(t, token, evidence, 1, "repo-scope", workflow.RepositoryScopeClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, "context:fixture", "patch:fixture"))

	rc, err := pact.CreateRevocationCheckpoint(pocconfig.RevocationIssuerKey(), 1, now.Unix(), nil)
	if err != nil {
		t.Fatal(err)
	}
	rc.IssuerID = pocconfig.RevocationIssuerID
	if err := pact.SignRevocationCheckpoint(pocconfig.RevocationIssuerKey(), rc); err != nil {
		t.Fatal(err)
	}
	return token, evidence, rc
}

func appendTestNode(t *testing.T, token string, evidence *pact.Evidence, nodeIndex int, cn string, claims map[string]interface{}) string {
	t.Helper()
	payload := &pact.Payload{
		Ver:       pact.ModeSchoCo,
		TID0:      workflow.TaskID,
		NodeIndex: nodeIndex,
		Iat:       time.Unix(1000, 0).Unix(),
		Iss:       &pact.IDClaim{CN: cn},
	}
	_, openings, err := pact.AttachCommitmentRootToPayload(payload, payload.TID0, nodeIndex, claims)
	if err != nil {
		t.Fatal(err)
	}
	evidence.NodeOpenings[nodeIndex] = openings
	next, err := pact.ExtendJWS(token, &pact.LDNode{Payload: payload}, pact.ModeSchoCo)
	if err != nil {
		t.Fatal(err)
	}
	return next
}
