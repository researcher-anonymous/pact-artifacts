package workflow_test

import (
	"testing"
	"time"

	"anonymous-artifact/schoco"
	"flow-poc/internal/pocconfig"
	"flow-poc/internal/workflow"
	pact "flow-poc/pact"
	sd "flow-poc/sd"
)

type scenarioOptions struct {
	rootPerms         []string
	rootClaims        map[string]interface{}
	contextClaims     map[string]interface{}
	patchClaims       map[string]interface{}
	reviewClaims      map[string]interface{}
	prClaims          map[string]interface{}
	tamperEvidence    func(*pact.Evidence)
	revoked           []string
	rcIssuedAt        int64
	omitRC            bool
	requireValidation bool
}

type localScenarioOptions struct {
	rootPerms      []string
	rootClaims     map[string]interface{}
	contextClaims  map[string]interface{}
	patchClaims    map[string]interface{}
	applyClaims    map[string]interface{}
	testClaims     map[string]interface{}
	finalClaims    map[string]interface{}
	tamperEvidence func(*pact.Evidence)
}

type branchedScenarioOptions struct {
	patchScopeClaims map[string]interface{}
	repoScopeClaims  map[string]interface{}
	applyClaims      map[string]interface{}
	derivePatchFrom  string
}

func TestCodeMaintenanceWorkflowValidates(t *testing.T) {
	token, evidence, rc := buildScenario(t, scenarioOptions{})
	if err := workflow.ValidateWithRevocation(token, evidence, nil, workflow.CodeMaintenanceRelation{}, rc, time.Unix(1000, 0)); err != nil {
		t.Fatalf("valid workflow rejected: %v", err)
	}
}

func TestCodeMaintenanceWorkflowNegativePaths(t *testing.T) {
	tests := map[string]scenarioOptions{
		"permission escalation rejects": {
			rootPerms: []string{"issue.read", "repo.read", "patch.propose", "analysis.execute"},
		},
		"repo mismatch rejects": {
			contextClaims: withClaim(workflow.ContextClaims(), "repo", "example/other-repo"),
		},
		"issue_id mismatch rejects": {
			contextClaims: withClaim(workflow.ContextClaims(), "issue_id", "999"),
		},
		"later node missing task_id rejects": {
			patchClaims: withoutClaim(workflow.PatchClaims(workflow.ContextHash), "task_id"),
		},
		"later node missing repo rejects": {
			patchClaims: withoutClaim(workflow.PatchClaims(workflow.ContextHash), "repo"),
		},
		"later node missing issue_id rejects": {
			patchClaims: withoutClaim(workflow.PatchClaims(workflow.ContextHash), "issue_id"),
		},
		"unexpected permission field rejects": {
			patchClaims: withClaim(workflow.PatchClaims(workflow.ContextHash), "admin.override", true),
		},
		"permission outside node scope rejects": {
			patchClaims: withClaim(workflow.PatchClaims(workflow.ContextHash), "pr.create", true),
		},
		"missing patch_hash rejects": {
			patchClaims: withoutClaim(workflow.PatchClaims(workflow.ContextHash), "patch_hash"),
		},
		"missing review_result_hash rejects": {
			reviewClaims: withoutClaim(workflow.ReviewClaims(workflow.PatchHash, true), "review_result_hash"),
		},
		"decision rejected denies PR creation": {
			reviewClaims: workflow.ReviewClaims(workflow.PatchHash, false),
		},
		"final branch not matching branch_prefix rejects": {
			prClaims: withClaim(workflow.PRClaims(workflow.PatchHash, workflow.ReviewResultHash), "branch", "feature/unrelated"),
		},
		"missing branch_prefix rejects": {
			rootClaims: withoutClaim(workflow.RootClaims(nil), "branch_prefix"),
		},
		"missing final branch rejects": {
			prClaims: withoutClaim(workflow.PRClaims(workflow.PatchHash, workflow.ReviewResultHash), "branch"),
		},
		"stale RC_e rejects": {
			rcIssuedAt: time.Unix(1000, 0).Add(-2 * time.Minute).Unix(),
		},
		"missing RC_e rejects": {
			omitRC: true,
		},
		"revoked tid_0 rejects": {
			revoked: []string{workflow.TaskID},
		},
		"tampered evidence rejects": {
			tamperEvidence: func(e *pact.Evidence) {
				e.NodeOpenings[2][0].Value = []byte(`"tampered"`)
			},
		},
	}
	for name, opts := range tests {
		t.Run(name, func(t *testing.T) {
			token, evidence, rc := buildScenario(t, opts)
			if opts.tamperEvidence != nil {
				opts.tamperEvidence(evidence)
			}
			if opts.omitRC {
				rc = nil
			}
			if err := workflow.ValidateWithRevocation(token, evidence, nil, workflow.CodeMaintenanceRelation{}, rc, time.Unix(1000, 0)); err == nil {
				t.Fatal("invalid workflow accepted")
			}
		})
	}
}

func TestCodeMaintenanceLocalWorkflowValidates(t *testing.T) {
	token, evidence, rc := buildLocalScenario(t, localScenarioOptions{})
	if err := workflow.ValidateWithRevocation(token, evidence, nil, workflow.CodeMaintenanceRelation{}, rc, time.Unix(1000, 0)); err != nil {
		t.Fatalf("valid local workflow rejected: %v", err)
	}
}

func TestCodeMaintenanceLocalWorkflowNegativePaths(t *testing.T) {
	tests := map[string]localScenarioOptions{
		"modified path outside allowed_paths rejects": {
			applyClaims: withClaim(localApplyClaims(), "modified_paths", []string{"internal/secret.go"}),
		},
		"patch_hash mismatch between proposal and application rejects": {
			applyClaims: withClaim(localApplyClaims(), "patch_hash", "patch:other"),
		},
		"diff_hash mismatch between application and test execution rejects": {
			testClaims: withClaim(localTestClaims(), "diff_hash", "diff:other"),
		},
		"final release when test_result failed rejects": {
			finalClaims: withClaim(localFinalClaims(), "test_result", "failed"),
		},
		"final release missing test_log_hash rejects": {
			finalClaims: withoutClaim(localFinalClaims(), "test_log_hash"),
		},
		"branch not respecting branch_prefix rejects": {
			finalClaims: withClaim(localFinalClaims(), "branch", "feature/unrelated"),
		},
		"permission escalation rejects": {
			rootPerms: []string{"issue.read", "repo.read", "patch.propose", "analysis.execute", "patch.apply", "test.execute"},
		},
		"repo mismatch rejects": {
			contextClaims: withClaim(localContextClaims(), "repo", "example/other-repo"),
		},
		"issue_id mismatch rejects": {
			patchClaims: withClaim(localPatchClaims(), "issue_id", "999"),
		},
		"missing model_id rejects": {
			patchClaims: withoutClaim(localPatchClaims(), "model_id"),
		},
		"failed test execution rejects": {
			testClaims: withClaim(localTestClaims(), "test_result", "failed"),
		},
	}
	for name, opts := range tests {
		t.Run(name, func(t *testing.T) {
			token, evidence, rc := buildLocalScenario(t, opts)
			if opts.tamperEvidence != nil {
				opts.tamperEvidence(evidence)
			}
			if err := workflow.ValidateWithRevocation(token, evidence, nil, workflow.CodeMaintenanceRelation{}, rc, time.Unix(1000, 0)); err == nil {
				t.Fatal("invalid local workflow accepted")
			}
		})
	}
}

func TestBranchedCodeMaintenanceWorkflowValidates(t *testing.T) {
	presentation, rc := buildBranchedScenario(t, branchedScenarioOptions{})
	if err := workflow.ValidateBranchedCodeMaintenance(presentation, rc, time.Unix(1000, 0)); err != nil {
		t.Fatalf("valid branched workflow rejected: %v", err)
	}
}

func TestBranchedCodeMaintenanceNegativePaths(t *testing.T) {
	tests := map[string]branchedScenarioOptions{
		"downstream context token cannot derive sibling patch branch": {
			derivePatchFrom: "context_scope",
		},
		"patch branch missing context dependency rejects": {
			patchScopeClaims: withoutClaim(workflow.PatchScopeClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, "context:fixture"), "context_hash"),
		},
		"patch branch wrong context dependency rejects": {
			patchScopeClaims: withClaim(workflow.PatchScopeClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, "context:fixture"), "context_hash", "context:wrong"),
		},
		"repo branch missing patch dependency rejects": {
			repoScopeClaims: withoutClaim(workflow.RepositoryScopeClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, "context:fixture", "patch:fixture"), "patch_hash"),
		},
		"repo branch wrong patch dependency rejects": {
			repoScopeClaims: withClaim(workflow.RepositoryScopeClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, "context:fixture", "patch:fixture"), "patch_hash", "patch:wrong"),
		},
		"modified path outside allowed_paths rejects": {
			applyClaims: withClaim(localApplyClaims(), "modified_paths", []string{"internal/secret.go"}),
		},
	}
	for name, opts := range tests {
		t.Run(name, func(t *testing.T) {
			presentation, rc := buildBranchedScenario(t, opts)
			if err := workflow.ValidateBranchedCodeMaintenance(presentation, rc, time.Unix(1000, 0)); err == nil {
				t.Fatal("invalid branched workflow accepted")
			}
		})
	}
}

func buildScenario(t *testing.T, opts scenarioOptions) (string, *pact.Evidence, *pact.RevocationCheckpoint) {
	t.Helper()
	now := time.Unix(1000, 0)
	sk, pk, err := schoco.KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	rootClaims := opts.rootClaims
	if rootClaims == nil {
		rootClaims = workflow.RootClaims(opts.rootPerms)
	}
	root := &pact.Payload{Ver: pact.ModeSchoCo, TID0: workflow.TaskID, NodeIndex: 0, Iat: now.Unix(), Iss: &pact.IDClaim{PK: pk.Bytes(), CN: "issuer"}}
	_, rootOpenings, err := pact.AttachCommitmentRootToPayload(root, root.TID0, 0, rootClaims)
	if err != nil {
		t.Fatal(err)
	}
	token, err := pact.CreateJWS(root, pact.ModeSchoCo, sk)
	if err != nil {
		t.Fatal(err)
	}
	evidence := &pact.Evidence{NodeOpenings: map[int][]sd.FieldOpening{0: rootOpenings}}

	token = appendNode(t, token, 1, "context", claimsOr(opts.contextClaims, workflow.ContextClaims()), evidence)
	token = appendNode(t, token, 2, "patch-agent", claimsOr(opts.patchClaims, workflow.PatchClaims(workflow.ContextHash)), evidence)
	token = appendNode(t, token, 3, "review", claimsOr(opts.reviewClaims, workflow.ReviewClaims(workflow.PatchHash, true)), evidence)
	token = appendNode(t, token, 4, "repo-management", claimsOr(opts.prClaims, workflow.PRClaims(workflow.PatchHash, workflow.ReviewResultHash)), evidence)

	issuedAt := opts.rcIssuedAt
	if issuedAt == 0 {
		issuedAt = now.Unix()
	}
	rc, err := pact.CreateRevocationCheckpoint(pocconfig.RevocationIssuerKey(), 1, issuedAt, opts.revoked)
	if err != nil {
		t.Fatal(err)
	}
	rc.IssuerID = pocconfig.RevocationIssuerID
	if err := pact.SignRevocationCheckpoint(pocconfig.RevocationIssuerKey(), rc); err != nil {
		t.Fatal(err)
	}
	return token, evidence, rc
}

func buildBranchedScenario(t *testing.T, opts branchedScenarioOptions) (workflow.CodeMaintenanceBranchPresentation, *pact.RevocationCheckpoint) {
	t.Helper()
	now := time.Unix(1000, 0)
	sk, pk, err := schoco.KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	rootClaims := workflow.RootClaims(workflow.LocalWorkflowPermissions)
	rootClaims["allowed_paths"] = []string{"internal/api/projects.go", "internal/api/projects_test.go"}
	root := &pact.Payload{Ver: pact.ModeSchoCo, TID0: workflow.TaskID, NodeIndex: 0, Iat: now.Unix(), Iss: &pact.IDClaim{PK: pk.Bytes(), CN: "issuer"}}
	_, rootOpenings, err := pact.AttachCommitmentRootToPayload(root, root.TID0, 0, rootClaims)
	if err != nil {
		t.Fatal(err)
	}
	rootToken, err := pact.CreateJWS(root, pact.ModeSchoCo, sk)
	if err != nil {
		t.Fatal(err)
	}

	contextEvidence := &pact.Evidence{NodeOpenings: map[int][]sd.FieldOpening{0: rootOpenings}}
	contextScopeToken := appendNode(t, rootToken, 1, "context-scope", workflow.ContextScopeClaims(workflow.TaskID, workflow.Repo, workflow.IssueID), contextEvidence)
	contextToken := appendNode(t, contextScopeToken, 2, "context-result", workflow.ContextResultClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, workflow.ContextResult{
		IssueID:      workflow.IssueID,
		RelevantFile: []string{"internal/api/projects.go", "internal/api/projects_test.go"},
		IssueHash:    "issue:fixture",
		FilesHash:    "files:fixture",
		ContextHash:  "context:fixture",
	}), contextEvidence)

	patchEvidence := &pact.Evidence{NodeOpenings: map[int][]sd.FieldOpening{0: rootOpenings}}
	patchScopeClaims := claimsOr(opts.patchScopeClaims, workflow.PatchScopeClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, "context:fixture"))
	patchParent := rootToken
	if opts.derivePatchFrom == "context_scope" {
		patchParent = contextScopeToken
	}
	patchScopeToken := appendNode(t, patchParent, 1, "patch-scope", patchScopeClaims, patchEvidence)
	patchToken := appendNode(t, patchScopeToken, 2, "patch-result", workflow.PatchResultClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, "context:fixture", workflow.PatchResult{
		PatchHash:     "patch:fixture",
		RationaleHash: "rationale:fixture",
		ModelID:       "deterministic-patch-agent",
		RiskLevel:     "low",
	}), patchEvidence)

	repoEvidence := &pact.Evidence{NodeOpenings: map[int][]sd.FieldOpening{0: rootOpenings}}
	repoScopeToken := appendNode(t, rootToken, 1, "repo-scope", claimsOr(opts.repoScopeClaims, workflow.RepositoryScopeClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, "context:fixture", "patch:fixture")), repoEvidence)
	repoToken := appendNode(t, repoScopeToken, 2, "repo-apply", claimsOr(opts.applyClaims, localApplyClaims()), repoEvidence)
	repoToken = appendNode(t, repoToken, 3, "repo-test", localTestClaims(), repoEvidence)
	repoToken = appendNode(t, repoToken, 4, "repo-release", localFinalClaims(), repoEvidence)

	rc, err := pact.CreateRevocationCheckpoint(pocconfig.RevocationIssuerKey(), 1, now.Unix(), nil)
	if err != nil {
		t.Fatal(err)
	}
	rc.IssuerID = pocconfig.RevocationIssuerID
	if err := pact.SignRevocationCheckpoint(pocconfig.RevocationIssuerKey(), rc); err != nil {
		t.Fatal(err)
	}
	return workflow.CodeMaintenanceBranchPresentation{
		Context: workflow.BranchPresentation{Token: contextToken, Evidence: contextEvidence},
		Patch:   workflow.BranchPresentation{Token: patchToken, Evidence: patchEvidence},
		Repository: workflow.BranchPresentation{
			Token:    repoToken,
			Evidence: repoEvidence,
		},
	}, rc
}

func buildLocalScenario(t *testing.T, opts localScenarioOptions) (string, *pact.Evidence, *pact.RevocationCheckpoint) {
	t.Helper()
	now := time.Unix(1000, 0)
	sk, pk, err := schoco.KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	rootClaims := opts.rootClaims
	if rootClaims == nil {
		perms := opts.rootPerms
		if len(perms) == 0 {
			perms = workflow.LocalWorkflowPermissions
		}
		rootClaims = workflow.RootClaims(perms)
		rootClaims["allowed_paths"] = []string{"internal/api/projects.go", "internal/api/projects_test.go"}
	}
	root := &pact.Payload{Ver: pact.ModeSchoCo, TID0: workflow.TaskID, NodeIndex: 0, Iat: now.Unix(), Iss: &pact.IDClaim{PK: pk.Bytes(), CN: "issuer"}}
	_, rootOpenings, err := pact.AttachCommitmentRootToPayload(root, root.TID0, 0, rootClaims)
	if err != nil {
		t.Fatal(err)
	}
	token, err := pact.CreateJWS(root, pact.ModeSchoCo, sk)
	if err != nil {
		t.Fatal(err)
	}
	evidence := &pact.Evidence{NodeOpenings: map[int][]sd.FieldOpening{0: rootOpenings}}

	token = appendNode(t, token, 1, "context", claimsOr(opts.contextClaims, localContextClaims()), evidence)
	token = appendNode(t, token, 2, "patch-agent", claimsOr(opts.patchClaims, localPatchClaims()), evidence)
	token = appendNode(t, token, 3, "repo-management-apply", claimsOr(opts.applyClaims, localApplyClaims()), evidence)
	token = appendNode(t, token, 4, "repo-management-test", claimsOr(opts.testClaims, localTestClaims()), evidence)
	token = appendNode(t, token, 5, "repo-management-release", claimsOr(opts.finalClaims, localFinalClaims()), evidence)

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

func localContextClaims() map[string]interface{} {
	return workflow.RepositoryContextClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, workflow.ContextResult{
		IssueID:      workflow.IssueID,
		RelevantFile: []string{"internal/api/projects.go", "internal/api/projects_test.go"},
		IssueHash:    "issue:fixture",
		FilesHash:    "files:fixture",
		ContextHash:  "context:fixture",
	})
}

func localPatchClaims() map[string]interface{} {
	return workflow.PatchProposalClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, "context:fixture", workflow.PatchResult{
		PatchHash:     "patch:fixture",
		RationaleHash: "rationale:fixture",
		ModelID:       "deterministic-patch-agent",
		RiskLevel:     "low",
	})
}

func localApplyClaims() map[string]interface{} {
	return workflow.PatchApplicationClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, workflow.ApplyResult{
		PatchHash:    "patch:fixture",
		DiffHash:     "diff:fixture",
		Applied:      true,
		ModifiedPath: []string{"internal/api/projects.go"},
	})
}

func localTestClaims() map[string]interface{} {
	return workflow.TestExecutionClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, workflow.TestResult{
		DiffHash:    "diff:fixture",
		TestLogHash: "test-log:fixture",
		Passed:      true,
		TestResult:  "passed",
		Command:     "go test ./...",
	})
}

func localFinalClaims() map[string]interface{} {
	return workflow.FinalArtifactClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, workflow.FinalArtifactResult{
		DiffHash:    "diff:fixture",
		TestLogHash: "test-log:fixture",
		Branch:      workflow.BranchPrefix + "-empty-project-id",
		TestResult:  "passed",
		Status:      "ok",
	})
}

func appendNode(t *testing.T, token string, nodeIndex int, cn string, claims map[string]interface{}, evidence *pact.Evidence) string {
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

func claimsOr(got map[string]interface{}, fallback map[string]interface{}) map[string]interface{} {
	if got != nil {
		return got
	}
	return fallback
}

func withClaim(claims map[string]interface{}, key string, value interface{}) map[string]interface{} {
	cp := map[string]interface{}{}
	for k, v := range claims {
		cp[k] = v
	}
	cp[key] = value
	return cp
}

func withoutClaim(claims map[string]interface{}, key string) map[string]interface{} {
	cp := map[string]interface{}{}
	for k, v := range claims {
		if k != key {
			cp[k] = v
		}
	}
	return cp
}
