package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"anonymous-artifact/schoco"
	"flow-poc/internal/pocconfig"
	"flow-poc/internal/workflow"
	pact "flow-poc/pact"
	sd "flow-poc/sd"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestLoadFixtureContextUsesRealFixtureArtifacts(t *testing.T) {
	result, err := loadFixtureContext()
	if err != nil {
		t.Fatal(err)
	}

	if result.IssueID != workflow.IssueID {
		t.Fatalf("issue_id = %q, want %q", result.IssueID, workflow.IssueID)
	}
	if len(result.RelevantFile) != len(fixtureRelevantFiles) {
		t.Fatalf("relevant file count = %d, want %d", len(result.RelevantFile), len(fixtureRelevantFiles))
	}
	for _, got := range []string{result.IssueHash, result.FilesHash, result.ContextHash} {
		if got == "" {
			t.Fatal("expected non-empty artifact hashes")
		}
	}
	if !strings.HasPrefix(result.IssueHash, "issue:") {
		t.Fatalf("issue_hash = %q, want issue: prefix", result.IssueHash)
	}
	if !strings.HasPrefix(result.FilesHash, "files:") {
		t.Fatalf("files_hash = %q, want files: prefix", result.FilesHash)
	}
	if !strings.HasPrefix(result.ContextHash, "context:") {
		t.Fatalf("context_hash = %q, want context: prefix", result.ContextHash)
	}
}

func TestContextToolExtendsContextBranchLocally(t *testing.T) {
	token, rootDisc, scopeDisc, evidence, rc := buildContextScopeForTest(t)
	result, _, err := contextTool(context.Background(), token, []string{
		string(jsonMustMarshal(rootDisc)),
		string(jsonMustMarshal(scopeDisc)),
	}, rc)
	if err != nil {
		t.Fatal(err)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	var resp map[string]any
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatal(err)
	}
	evidence.NodeOpenings[2] = decodeOpeningsForTest(t, resp["openings"])
	extended := resp["extended_token"].(string)
	if err := workflow.ValidateWithRevocation(extended, evidence, nil, nil, rc, time.Now()); err != nil {
		t.Fatalf("context branch rejected: %v", err)
	}
}

func buildContextScopeForTest(t *testing.T) (string, *sd.Disclosure, *sd.Disclosure, *pact.Evidence, *pact.RevocationCheckpoint) {
	t.Helper()
	now := time.Now()
	sk, pk, err := schoco.KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	root := &pact.Payload{Ver: pact.ModeSchoCo, TID0: workflow.TaskID, NodeIndex: 0, Iat: now.Unix(), Iss: &pact.IDClaim{PK: pk.Bytes(), CN: "issuer"}}
	rootKeys, rootOpenings, err := pact.AttachCommitmentRootToPayload(root, root.TID0, 0, workflow.RootClaims(workflow.LocalWorkflowPermissions))
	if err != nil {
		t.Fatal(err)
	}
	rootToken, err := pact.CreateJWS(root, pact.ModeSchoCo, sk)
	if err != nil {
		t.Fatal(err)
	}
	rootSelected, err := workflow.Indexes(rootKeys, "task_id", "repo", "issue_id", "branch_prefix", "allowed_paths")
	if err != nil {
		t.Fatal(err)
	}
	rootDisc, err := sd.CreateDisclosureFromOpenings(rootOpenings, rootSelected)
	if err != nil {
		t.Fatal(err)
	}

	scope := &pact.Payload{Ver: pact.ModeSchoCo, TID0: workflow.TaskID, NodeIndex: 1, Iat: now.Unix(), Iss: &pact.IDClaim{CN: "context-scope"}}
	scopeKeys, scopeOpenings, err := pact.AttachCommitmentRootToPayload(scope, scope.TID0, 1, workflow.ContextScopeClaims(workflow.TaskID, workflow.Repo, workflow.IssueID))
	if err != nil {
		t.Fatal(err)
	}
	scopeSelected, err := workflow.Indexes(scopeKeys, "task_id", "repo", "issue_id", "branch_id", "issue.read", "repo.read")
	if err != nil {
		t.Fatal(err)
	}
	scopeDisc, err := sd.CreateDisclosureFromOpenings(scopeOpenings, scopeSelected)
	if err != nil {
		t.Fatal(err)
	}
	scopeToken, err := pact.ExtendJWS(rootToken, &pact.LDNode{Payload: scope}, pact.ModeSchoCo)
	if err != nil {
		t.Fatal(err)
	}
	evidence := &pact.Evidence{NodeOpenings: map[int][]sd.FieldOpening{0: rootOpenings, 1: scopeOpenings}}
	rc, err := pact.CreateRevocationCheckpoint(pocconfig.RevocationIssuerKey(), 1, now.Unix(), nil)
	if err != nil {
		t.Fatal(err)
	}
	rc.IssuerID = pocconfig.RevocationIssuerID
	rc.ExpiresAt = now.Add(2 * time.Minute).Unix()
	if err := pact.SignRevocationCheckpoint(pocconfig.RevocationIssuerKey(), rc); err != nil {
		t.Fatal(err)
	}
	return scopeToken, rootDisc, scopeDisc, evidence, rc
}

func decodeOpeningsForTest(t *testing.T, value any) []sd.FieldOpening {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var openings []sd.FieldOpening
	if err := json.Unmarshal(data, &openings); err != nil {
		t.Fatal(err)
	}
	return openings
}
