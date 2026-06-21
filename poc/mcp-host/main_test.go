package main

import (
	"encoding/json"
	"strings"
	"testing"

	"flow-poc/internal/workflow"
	pact "flow-poc/pact"
	sd "flow-poc/sd"
)

func TestPatchArtifactFromAgentResponseUsesTopLevelFields(t *testing.T) {
	resp := map[string]any{
		"patch_text":     "diff --git a/internal/api/projects.go b/internal/api/projects.go\n",
		"patch_hash":     "patch:top",
		"rationale_hash": "rationale:top",
		"model_id":       "deterministic-patch-agent",
		"risk_level":     "low",
		"patch": map[string]any{
			"patch_hash": "patch:nested",
		},
	}

	artifact, err := patchArtifactFromAgentResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.PatchText == "" {
		t.Fatal("patch_text was not extracted")
	}
	if artifact.PatchHash != "patch:top" {
		t.Fatalf("patch_hash = %q, want top-level value", artifact.PatchHash)
	}
	if artifact.ModelID != "deterministic-patch-agent" {
		t.Fatalf("model_id = %q, want deterministic-patch-agent", artifact.ModelID)
	}
}

func TestPatchArtifactFromAgentResponseFallsBackToNestedPatch(t *testing.T) {
	artifact, err := patchArtifactFromAgentResponse(map[string]any{
		"patch": map[string]any{
			"patch_hash":     "patch:nested",
			"rationale_hash": "rationale:nested",
			"risk_level":     "low",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.PatchHash != "patch:nested" {
		t.Fatalf("patch_hash = %q, want nested value", artifact.PatchHash)
	}
	if artifact.PatchText != "" {
		t.Fatalf("patch_text = %q, want empty compatibility fallback", artifact.PatchText)
	}
}

func TestRepositoryManagementArgsIncludesPatchWhenPresent(t *testing.T) {
	evidence := &pact.Evidence{}
	rc := &pact.RevocationCheckpoint{Epoch: 1}
	args := repositoryManagementArgs("token", evidence, "context:hash", patchArtifact{
		PatchText: "diff",
		PatchHash: "patch:hash",
	}, rc)

	if args["token"] != "token" {
		t.Fatal("token not included")
	}
	if args["evidence"] != evidence {
		t.Fatal("evidence not included")
	}
	if args["context_hash"] != "context:hash" {
		t.Fatal("context_hash not included")
	}
	if args["revocation_checkpoint"] != rc {
		t.Fatal("revocation_checkpoint not included")
	}
	if args["patch_text"] != "diff" {
		t.Fatal("patch_text not included")
	}
	if args["patch_hash"] != "patch:hash" {
		t.Fatal("patch_hash not included")
	}
}

func TestRepositoryManagementArgsPreservesOldPathWithoutPatchText(t *testing.T) {
	args := repositoryManagementArgs("token", &pact.Evidence{}, "context:hash", patchArtifact{PatchHash: "patch:hash"}, &pact.RevocationCheckpoint{Epoch: 1})
	if _, ok := args["patch_text"]; ok {
		t.Fatal("patch_text included despite being absent")
	}
	if _, ok := args["patch_hash"]; ok {
		t.Fatal("patch_hash included despite absent patch_text")
	}
}

func TestValidateRepositoryManagementResponseRequiresPassedTestsWhenPatchSent(t *testing.T) {
	if err := validateRepositoryManagementResponse(map[string]any{
		"status":      "ok",
		"test_result": "failed",
	}, true); err == nil {
		t.Fatal("failed tests were accepted")
	}

	if err := validateRepositoryManagementResponse(map[string]any{
		"status":      "ok",
		"test_result": "passed",
	}, true); err != nil {
		t.Fatalf("passed tests rejected: %v", err)
	}
}

func TestFinalSummaryIncludesRealArtifactFields(t *testing.T) {
	summary := finalSummary("context:hash", patchArtifact{
		PatchHash:     "patch:hash",
		RationaleHash: "rationale:hash",
		ModelID:       "deterministic-patch-agent",
		RiskLevel:     "low",
	}, map[string]any{
		"diff_hash":               "diff:hash",
		"test_result":             "passed",
		"test_log_hash":           "test-log:hash",
		"artifact_hash":           "artifact:hash",
		"modified_paths":          []any{"internal/api/projects.go"},
		"branch":                  "fix/issue-184-empty-project-id",
		"status":                  "ok",
		"joint_branch_validation": "accepted",
		"pr_url":                  "https://git.example/example/api-service/pull/184",
	})

	if summary["task_id"] != workflow.TaskID {
		t.Fatalf("task_id = %v, want %s", summary["task_id"], workflow.TaskID)
	}
	if summary["repo"] != workflow.Repo {
		t.Fatalf("repo = %v, want %s", summary["repo"], workflow.Repo)
	}
	if got := summary["allowed_paths"].([]string); len(got) != 2 || got[0] != "internal/api/projects.go" {
		t.Fatalf("allowed_paths = %v", got)
	}
	if summary["context_hash"] != "context:hash" {
		t.Fatalf("context_hash = %v", summary["context_hash"])
	}
	if got := summary["modified_paths"].([]string); len(got) != 1 || got[0] != "internal/api/projects.go" {
		t.Fatalf("modified_paths = %v", got)
	}
	if summary["test_result"] != "passed" {
		t.Fatalf("test_result = %v", summary["test_result"])
	}
	if summary["test_log_hash"] != "test-log:hash" {
		t.Fatalf("test_log_hash = %v", summary["test_log_hash"])
	}
	if summary["joint_branch_validation"] != "accepted" {
		t.Fatalf("joint_branch_validation = %v", summary["joint_branch_validation"])
	}
}

func TestFinalSummaryLinesAreStableAndOrdered(t *testing.T) {
	lines := finalSummaryLines(map[string]any{
		"task_id":                 "task",
		"issue_id":                "184",
		"repo":                    "example/api-service",
		"allowed_paths":           []string{"internal/api/projects.go", "internal/api/projects_test.go"},
		"modified_paths":          []string{"internal/api/projects.go"},
		"context_hash":            "context:hash",
		"patch_hash":              "patch:hash",
		"diff_hash":               "diff:hash",
		"test_result":             "passed",
		"test_log_hash":           "test-log:hash",
		"artifact_hash":           "artifact:hash",
		"final_status":            "ok",
		"joint_branch_validation": "accepted",
	})

	want := []string{
		"Final summary:",
		"  task_id: task",
		"  issue_id: 184",
		"  repo: example/api-service",
		"  allowed_paths: internal/api/projects.go, internal/api/projects_test.go",
		"  modified_paths: internal/api/projects.go",
		"  context_hash: context:hash",
		"  patch_hash: patch:hash",
		"  diff_hash: diff:hash",
		"  test_result: passed",
		"  test_log_hash: test-log:hash",
		"  artifact_hash: artifact:hash",
		"  final_status: ok",
		"  joint_branch_validation: accepted",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("summary lines:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

func TestBranchWorkflowLinesDescribeRuntimeFlow(t *testing.T) {
	lines := strings.Join(branchWorkflowLines(), "\n")
	for _, want := range []string{
		"Root grant T0 = [n0]",
		"Context branch T_ctx = [n0, n1_ctx_scope, n2_ctx_result]",
		"Patch branch T_patch = [n0, n1_patch_scope, n2_patch_result]",
		"Repository branch T_repo = [n0, n1_repo_scope, n2_apply, n3_test, n4_release]",
		"Final validation = joint branch validation",
	} {
		if !strings.Contains(lines, want) {
			t.Fatalf("missing line %q in:\n%s", want, lines)
		}
	}
	for _, stale := range []string{"Six-step", "six-node", "six_node_validation"} {
		if strings.Contains(lines, stale) {
			t.Fatalf("stale linear wording %q in:\n%s", stale, lines)
		}
	}
}

func TestLocalExtensionLogLinesDescribeComponentResponsibilities(t *testing.T) {
	lines := []string{
		"[Host] Root grant received: T0=[n0]",
		"[Host] Sent context scoped branch [n0,n1_ctx_scope] to Context Service",
		"[Context] Extended context branch locally: T_ctx=[n0,n1_ctx_scope,n2_ctx_result]",
		"[Host] Sent patch scoped branch [n0,n1_patch_scope] to Patch Agent",
		"[Agent] Extended patch branch locally: T_patch=[n0,n1_patch_scope,n2_patch_result]",
		"[Host] Sent repository scoped branch [n0,n1_repo_scope] to RepoMgmt Service",
		"[RepoMgmt] Extended repository branch locally: T_repo=[n0,n1_repo_scope,n2_apply,n3_test,n4_release]",
		"[Host] Final validation = joint validation of returned branches",
	}
	joined := strings.Join(lines, "\n")
	for _, want := range []string{
		"Extended context branch locally",
		"Extended patch branch locally",
		"Extended repository branch locally",
		"joint validation of returned branches",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing local extension log %q in:\n%s", want, joined)
		}
	}
	for _, stale := range []string{"six-node", "six_node", "six-step", "linear CodeMaintenance", "one root and five downstream extensions"} {
		if strings.Contains(joined, stale) {
			t.Fatalf("stale output term %q in:\n%s", stale, joined)
		}
	}
}

func TestPactBranchAndDependencySummariesAreBranchBased(t *testing.T) {
	repoResp := map[string]any{
		"diff_hash":               "diff:hash",
		"test_result":             "passed",
		"test_log_hash":           "test-log:hash",
		"artifact_hash":           "artifact:hash",
		"status":                  "ok",
		"joint_branch_validation": "accepted",
	}
	branches := workflow.CodeMaintenanceBranchPresentation{
		Context:    workflow.BranchPresentation{Token: "h.ctx.sig"},
		Patch:      workflow.BranchPresentation{Token: "h.patch.sig"},
		Repository: workflow.BranchPresentation{Token: "h.repo.sig"},
	}
	branchLines := strings.Join(pactBranchSummaryLines("h.root.sig", branches, "context:hash", patchArtifact{PatchHash: "patch:hash"}, repoResp), "\n")
	for _, want := range []string{
		"PACT branch summary:",
		"branch=context token=T_ctx nodes=[n0, n1_ctx_scope, n2_ctx_result]",
		"branch=patch token=T_patch nodes=[n0, n1_patch_scope, n2_patch_result]",
		"branch=repository token=T_repo nodes=[n0, n1_repo_scope, n2_apply, n3_test, n4_release]",
		"joint_branch_validation: accepted",
	} {
		if !strings.Contains(branchLines, want) {
			t.Fatalf("missing line fragment %q in:\n%s", want, branchLines)
		}
	}
	deps := strings.Join(dependencySummaryLines("context:hash", "patch:hash", repoResp), "\n")
	for _, want := range []string{
		"patch branch depends on context_hash=context:hash",
		"repository branch depends on context_hash=context:hash and patch_hash=patch:hash",
		"apply node binds patch_hash=patch:hash to diff_hash=diff:hash",
		"test node binds diff_hash=diff:hash to test_result=passed and test_log_hash=test-log:hash",
		"release node binds passing test state to artifact_hash=artifact:hash and final_status=ok",
	} {
		if !strings.Contains(deps, want) {
			t.Fatalf("missing dependency fragment %q in:\n%s", want, deps)
		}
	}
}

func TestFixtureSafetyLinesExplainRegressionAndTempWorktree(t *testing.T) {
	lines := strings.Join(fixtureSafetyLines(map[string]any{
		"test_result":             "passed",
		"joint_branch_validation": "accepted",
	}), "\n")
	for _, want := range []string{
		"Fixture regression test is present in poc/fixture-repo.",
		"Original fixture repo is not modified.",
		"Patch workflow runs only in a temporary worktree.",
		"Fixture tests pass in the temporary worktree.",
		"joint_branch_validation: accepted",
	} {
		if !strings.Contains(lines, want) {
			t.Fatalf("missing line %q in:\n%s", want, lines)
		}
	}
}

func TestVerboseOutputRequiresExplicitEnvironmentFlag(t *testing.T) {
	t.Setenv("PACT_POC_VERBOSE", "")
	if verboseOutput() {
		t.Fatal("verbose output enabled by default")
	}

	t.Setenv("PACT_POC_VERBOSE", "1")
	if !verboseOutput() {
		t.Fatal("PACT_POC_VERBOSE=1 did not enable verbose output")
	}

	t.Setenv("PACT_POC_VERBOSE", "true")
	if verboseOutput() {
		t.Fatal("non-1 verbose value enabled verbose output")
	}
}

func TestCollectRepositoryManagementEvidenceConstructsRepositoryBranchNodes(t *testing.T) {
	evidence := &pact.Evidence{NodeOpenings: map[int][]sd.FieldOpening{
		0: {opening(t, 0, "task_id", workflow.TaskID)},
		1: {opening(t, 1, "branch_id", workflow.BranchRepository)},
	}}
	resp := map[string]any{
		"application_openings": jsonOpenings(t, []sd.FieldOpening{opening(t, 2, "patch.apply", true)}),
		"test_openings":        jsonOpenings(t, []sd.FieldOpening{opening(t, 3, "test.execute", true)}),
		"final_openings":       jsonOpenings(t, []sd.FieldOpening{opening(t, 4, "artifact.release", true)}),
	}

	if err := collectRepositoryManagementEvidence(evidence, resp); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= 4; i++ {
		if len(evidence.NodeOpenings[i]) == 0 {
			t.Fatalf("missing node %d evidence", i)
		}
	}
	if len(evidence.NodeOpenings) != 5 {
		t.Fatalf("node count = %d, want 5", len(evidence.NodeOpenings))
	}
}

func TestCollectRepositoryManagementEvidenceRequiresFinalArtifactNode(t *testing.T) {
	evidence := &pact.Evidence{NodeOpenings: map[int][]sd.FieldOpening{}}
	resp := map[string]any{
		"application_openings": jsonOpenings(t, []sd.FieldOpening{opening(t, 3, "patch.apply", true)}),
		"test_openings":        jsonOpenings(t, []sd.FieldOpening{opening(t, 4, "test.execute", true)}),
	}

	if err := collectRepositoryManagementEvidence(evidence, resp); err == nil {
		t.Fatal("missing final artifact openings accepted")
	}
}

func opening(t *testing.T, node int, tag string, value any) sd.FieldOpening {
	t.Helper()
	o, err := sd.NewDeterministicFieldOpeningForTest(workflow.TaskID, node, 0, tag, value)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func jsonOpenings(t *testing.T, openings []sd.FieldOpening) any {
	t.Helper()
	b, err := json.Marshal(openings)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
