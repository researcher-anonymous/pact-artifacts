package workflow_test

import (
	"strings"
	"testing"

	"flow-poc/internal/workflow"
)

func TestHashArtifactDeterministic(t *testing.T) {
	a := workflow.HashArtifact("issue", []byte("empty project_id returns 500"))
	b := workflow.HashArtifact("issue", []byte("empty project_id returns 500"))

	if a != b {
		t.Fatalf("HashArtifact changed for same input: %q != %q", a, b)
	}
	if !strings.HasPrefix(a, "issue:") {
		t.Fatalf("HashArtifact prefix = %q, want issue:", a)
	}
}

func TestHashArtifactChangesWhenInputChanges(t *testing.T) {
	a := workflow.HashArtifact("issue", []byte("empty project_id returns 500"))
	b := workflow.HashArtifact("issue", []byte("empty project_id returns 400"))

	if a == b {
		t.Fatal("HashArtifact did not change when input changed")
	}
}

func TestComputeContextHashChangesWhenIssueHashChanges(t *testing.T) {
	filesHash := workflow.ComputeFilesHash(map[string][]byte{
		"internal/api/projects.go": []byte("package api\n"),
	})
	a := workflow.ComputeContextHash("184", []string{"internal/api/projects.go"}, workflow.ComputeIssueHash([]byte("before")), filesHash)
	b := workflow.ComputeContextHash("184", []string{"internal/api/projects.go"}, workflow.ComputeIssueHash([]byte("after")), filesHash)

	if a == b {
		t.Fatal("context_hash did not change when issue_hash changed")
	}
}

func TestComputeContextHashChangesWhenFilesHashChanges(t *testing.T) {
	issueHash := workflow.ComputeIssueHash([]byte("empty project_id returns 500"))
	a := workflow.ComputeContextHash("184", []string{"internal/api/projects.go"}, issueHash, workflow.ComputeFilesHash(map[string][]byte{
		"internal/api/projects.go": []byte("package api\n"),
	}))
	b := workflow.ComputeContextHash("184", []string{"internal/api/projects.go"}, issueHash, workflow.ComputeFilesHash(map[string][]byte{
		"internal/api/projects.go": []byte("package api\nfunc fixed() {}\n"),
	}))

	if a == b {
		t.Fatal("context_hash did not change when files_hash changed")
	}
}

func TestComputePatchHashChangesWhenPatchTextChanges(t *testing.T) {
	a := workflow.ComputePatchHash("--- a/projects.go\n+++ b/projects.go\n@@\n-return 500\n")
	b := workflow.ComputePatchHash("--- a/projects.go\n+++ b/projects.go\n@@\n-return 400\n")

	if a == b {
		t.Fatal("patch_hash did not change when patch text changed")
	}
}

func TestComputeTestLogHashChangesWhenOutputChanges(t *testing.T) {
	a := workflow.ComputeTestLogHash("FAIL TestGetProjectRejectsEmptyProjectID\n")
	b := workflow.ComputeTestLogHash("ok pact-fixture-repo/internal/api\n")

	if a == b {
		t.Fatal("test_log_hash did not change when test output changed")
	}
}
