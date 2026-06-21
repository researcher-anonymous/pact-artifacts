package main

import (
	"strings"
	"testing"
	"time"

	"anonymous-artifact/schoco"
	"flow-poc/internal/pocconfig"
	"flow-poc/internal/workflow"
	pact "flow-poc/pact"
	sd "flow-poc/sd"
)

func TestDeterministicPatchArtifact(t *testing.T) {
	patchText := deterministicPatchText()

	if !strings.Contains(patchText, "diff --git a/internal/api/projects.go b/internal/api/projects.go") {
		t.Fatalf("patch does not target projects.go:\n%s", patchText)
	}
	if !strings.Contains(patchText, `if projectID == ""`) {
		t.Fatalf("patch does not add empty project_id guard:\n%s", patchText)
	}
	if !strings.Contains(patchText, "StatusCode: StatusBadRequest") {
		t.Fatalf("patch does not return bad request:\n%s", patchText)
	}
	if !strings.Contains(patchText, `errors.New("project_id is required")`) {
		t.Fatalf("patch does not return validation error:\n%s", patchText)
	}

	patchHash := workflow.ComputePatchHash(patchText)
	if patchHash != workflow.ComputePatchHash(deterministicPatchText()) {
		t.Fatal("deterministic patch hash changed across calls")
	}
	if !strings.HasPrefix(patchHash, "patch:") {
		t.Fatalf("patch_hash = %q, want patch: prefix", patchHash)
	}
}

func TestDeterministicRationaleHash(t *testing.T) {
	rationale := deterministicRationaleText()
	if rationale == "" {
		t.Fatal("rationale text is empty")
	}

	rationaleHash := workflow.ComputeRationaleHash(rationale)
	if rationaleHash != workflow.ComputeRationaleHash(deterministicRationaleText()) {
		t.Fatal("deterministic rationale hash changed across calls")
	}
	if !strings.HasPrefix(rationaleHash, "rationale:") {
		t.Fatalf("rationale_hash = %q, want rationale: prefix", rationaleHash)
	}
}

func TestDeterministicModelID(t *testing.T) {
	if deterministicModelID != "deterministic-patch-agent" {
		t.Fatalf("model_id = %q, want deterministic-patch-agent", deterministicModelID)
	}
}

func TestPatchAgentExtendsPatchBranchLocally(t *testing.T) {
	token, evidence, rc := buildPatchScopeForTest(t)
	patchText := deterministicPatchText()
	artifacts, err := extendPatchBranch(token, "context:fixture", workflow.PatchResult{
		ContextHash:   "context:fixture",
		PatchHash:     workflow.ComputePatchHash(patchText),
		RationaleHash: workflow.ComputeRationaleHash(deterministicRationaleText()),
		ModelID:       deterministicModelID,
		RiskLevel:     "low",
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence.NodeOpenings[2] = artifacts.Openings
	if err := workflow.ValidateWithRevocation(artifacts.Token, evidence, nil, nil, rc, time.Now()); err != nil {
		t.Fatalf("patch branch rejected: %v", err)
	}
}

func buildPatchScopeForTest(t *testing.T) (string, *pact.Evidence, *pact.RevocationCheckpoint) {
	t.Helper()
	now := time.Now()
	sk, pk, err := schoco.KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	root := &pact.Payload{Ver: pact.ModeSchoCo, TID0: workflow.TaskID, NodeIndex: 0, Iat: now.Unix(), Iss: &pact.IDClaim{PK: pk.Bytes(), CN: "issuer"}}
	_, rootOpenings, err := pact.AttachCommitmentRootToPayload(root, root.TID0, 0, workflow.RootClaims(workflow.LocalWorkflowPermissions))
	if err != nil {
		t.Fatal(err)
	}
	rootToken, err := pact.CreateJWS(root, pact.ModeSchoCo, sk)
	if err != nil {
		t.Fatal(err)
	}
	scope := &pact.Payload{Ver: pact.ModeSchoCo, TID0: workflow.TaskID, NodeIndex: 1, Iat: now.Unix(), Iss: &pact.IDClaim{CN: "patch-scope"}}
	_, scopeOpenings, err := pact.AttachCommitmentRootToPayload(scope, scope.TID0, 1, workflow.PatchScopeClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, "context:fixture"))
	if err != nil {
		t.Fatal(err)
	}
	scopeToken, err := pact.ExtendJWS(rootToken, &pact.LDNode{Payload: scope}, pact.ModeSchoCo)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := pact.CreateRevocationCheckpoint(pocconfig.RevocationIssuerKey(), 1, now.Unix(), nil)
	if err != nil {
		t.Fatal(err)
	}
	rc.IssuerID = pocconfig.RevocationIssuerID
	rc.ExpiresAt = now.Add(2 * time.Minute).Unix()
	if err := pact.SignRevocationCheckpoint(pocconfig.RevocationIssuerKey(), rc); err != nil {
		t.Fatal(err)
	}
	return scopeToken, &pact.Evidence{NodeOpenings: map[int][]sd.FieldOpening{0: rootOpenings, 1: scopeOpenings}}, rc
}
