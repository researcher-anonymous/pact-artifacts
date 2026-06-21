package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"flow-poc/internal/workflow"
	pact "flow-poc/pact"
	sd "flow-poc/sd"
	"github.com/a2aproject/a2a-go/a2a"
	"github.com/a2aproject/a2a-go/a2aclient"
	"github.com/a2aproject/a2a-go/a2aclient/agentcard"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	asURL        = envOr("POC_AS_URL", "http://localhost:8080/issueToken")
	server1URL   = envOr("POC_SERVER1_URL", "http://localhost:8081")
	agentCardURL = envOr("POC_AGENT_CARD_URL", "http://localhost:8082")
	server2URL   = envOr("POC_SERVER2_URL", "http://localhost:8083")
)

func main() {
	ctx := context.Background()
	log.Println("[Host] User task: Investigate issue #184: the API returns 500 when project_id is empty. If the fix is safe, open a PR.")

	tokenResp, err := requestTokenFromAS(workflow.RootPermissions)
	if err != nil {
		log.Fatal(err)
	}
	if tokenResp.RevocationCheckpoint == nil {
		log.Fatal("[Host] AS response missing revocation checkpoint")
	}
	log.Println("[Host] Root grant received: T0=[n0]")
	rootEvidence := func() map[int][]sd.FieldOpening {
		return map[int][]sd.FieldOpening{0: tokenResp.Openings}
	}

	rootCommonDisc := mustDisclosure(tokenResp.Keys, tokenResp.Openings, "task_id", "repo", "issue_id", "branch_prefix", "allowed_paths")
	contextScope, err := deriveBranchScope(tokenResp.JWS, "context-scope", workflow.ContextScopeClaims(workflow.TaskID, workflow.Repo, workflow.IssueID), "task_id", "repo", "issue_id", "branch_id", "issue.read", "repo.read")
	if err != nil {
		log.Fatal("[Host] Context branch derivation failed:", err)
	}
	log.Println("[Host] Sent context scoped branch [n0,n1_ctx_scope] to Context Service")
	contextEvidence := &pact.Evidence{NodeOpenings: rootEvidence()}
	contextEvidence.NodeOpenings[1] = contextScope.Openings
	contextResp := callMCP(ctx, server1URL, "context", map[string]any{
		"token": contextScope.Token,
		"presentations": []string{
			string(mustJSON(rootCommonDisc)),
			string(mustJSON(contextScope.Disclosure)),
		},
		"revocation_checkpoint": tokenResp.RevocationCheckpoint,
	})
	contextOpenings := openingsField(contextResp, "openings")
	contextResult := mapField(contextResp, "context")
	contextHash, _ := contextResult["context_hash"].(string)
	contextEvidence.NodeOpenings[2] = contextOpenings
	log.Println("[Host] Context hash:", contextHash)

	patchScope, err := deriveBranchScope(tokenResp.JWS, "patch-scope", workflow.PatchScopeClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, contextHash), "task_id", "repo", "issue_id", "branch_id", "patch.propose", "analysis.execute", "context_hash")
	if err != nil {
		log.Fatal("[Host] Patch branch derivation failed:", err)
	}
	log.Println("[Host] Sent patch scoped branch [n0,n1_patch_scope] to Patch Agent")
	patchEvidence := &pact.Evidence{NodeOpenings: rootEvidence()}
	patchEvidence.NodeOpenings[1] = patchScope.Openings
	agentResp, err := callPatchAgent(ctx, patchScope.Token, map[string]*sd.Disclosure{
		"0": rootCommonDisc,
		"1": patchScope.Disclosure,
	}, contextHash, tokenResp.RevocationCheckpoint)
	if err != nil {
		log.Fatal("[Host] Agent failed:", err)
	}
	patchOpenings := openingsField(agentResp, "openings")
	patchArtifact, err := patchArtifactFromAgentResponse(agentResp)
	if err != nil {
		log.Fatal("[Host] Agent response missing patch artifact:", err)
	}
	patchHash := patchArtifact.PatchHash
	patchEvidence.NodeOpenings[2] = patchOpenings
	log.Println("[Host] Patch hash:", patchHash)
	if patchArtifact.PatchText != "" {
		log.Println("[Host] Patch model:", patchArtifact.ModelID, "risk:", patchArtifact.RiskLevel)
	}

	repositoryScope, err := deriveBranchScope(tokenResp.JWS, "repository-scope", workflow.RepositoryScopeClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, contextHash, patchHash), "task_id", "repo", "issue_id", "branch_id", "context_hash", "patch_hash", "allowed_paths", "branch_prefix", "patch.apply", "test.execute", "artifact.release")
	if err != nil {
		log.Fatal("[Host] Repository branch derivation failed:", err)
	}
	log.Println("[Host] Sent repository scoped branch [n0,n1_repo_scope] to RepoMgmt Service")
	repositoryEvidence := &pact.Evidence{NodeOpenings: rootEvidence()}
	repositoryEvidence.NodeOpenings[1] = repositoryScope.Openings
	prResp := callMCP(ctx, server2URL, "openPR", repositoryManagementArgs(repositoryScope.Token, repositoryEvidence, contextHash, patchArtifact, tokenResp.RevocationCheckpoint))
	if err := validateRepositoryManagementResponse(prResp, patchArtifact.PatchText != ""); err != nil {
		log.Fatal("[Host] Repository management failed:", err)
	}
	if err := collectRepositoryManagementEvidence(repositoryEvidence, prResp); err != nil {
		log.Fatal("[Host] Repository management evidence missing:", err)
	}
	repositoryFinalToken := stringField(prResp, "extended_token")
	now := time.Now()
	rc := tokenResp.RevocationCheckpoint
	branches := workflow.CodeMaintenanceBranchPresentation{
		Context: workflow.BranchPresentation{
			Token:    stringField(contextResp, "extended_token"),
			Evidence: contextEvidence,
		},
		Patch: workflow.BranchPresentation{
			Token:    stringField(agentResp, "extended_token"),
			Evidence: patchEvidence,
		},
		Repository: workflow.BranchPresentation{
			Token:    repositoryFinalToken,
			Evidence: repositoryEvidence,
		},
	}
	if err := workflow.ValidateBranchedCodeMaintenance(branches, rc, now); err != nil {
		log.Fatal("[Host] Branch validation failed:", err)
	}
	log.Println("[Host] Final validation = joint validation of returned branches")
	prResp["joint_branch_validation"] = "accepted"
	logHostLines(branchWorkflowLines())
	logHostLines(fixtureSafetyLines(prResp))
	log.Println("[Host] Joint branch validation: accepted")
	if verboseOutput() {
		log.Println("[Host] Repository management raw response:", prResp)
	}
	logHostLines(pactBranchSummaryLines(tokenResp.JWS, branches, contextHash, patchArtifact, prResp))
	logHostLines(dependencySummaryLines(contextHash, patchArtifact.PatchHash, prResp))
	logHostLines(finalSummaryLines(finalSummary(contextHash, patchArtifact, prResp)))
	log.Println("[Host] PoC flow completed successfully")
}

type patchArtifact struct {
	PatchText     string
	PatchHash     string
	RationaleHash string
	ModelID       string
	RiskLevel     string
}

type ASTokenResponse struct {
	JWS                  string
	Keys                 []string
	Openings             []sd.FieldOpening
	RevocationCheckpoint *pact.RevocationCheckpoint `json:"revocation_checkpoint"`
}

type branchScope struct {
	Token      string
	Disclosure *sd.Disclosure
	Openings   []sd.FieldOpening
}

func deriveBranchScope(rootToken, cn string, claims map[string]interface{}, selectedKeys ...string) (*branchScope, error) {
	payload := &pact.Payload{
		Ver:       pact.ModeSchoCo,
		TID0:      workflow.TaskID,
		NodeIndex: 1,
		Iat:       time.Now().Unix(),
		Iss:       &pact.IDClaim{CN: "spiffe://example.org/" + cn},
	}
	keys, openings, err := pact.AttachCommitmentRootToPayload(payload, payload.TID0, 1, claims)
	if err != nil {
		return nil, err
	}
	selected, err := workflow.Indexes(keys, selectedKeys...)
	if err != nil {
		return nil, err
	}
	disclosure, err := sd.CreateDisclosureFromOpenings(openings, selected)
	if err != nil {
		return nil, err
	}
	token, err := pact.ExtendJWS(rootToken, &pact.LDNode{Payload: payload}, pact.ModeSchoCo)
	if err != nil {
		return nil, err
	}
	return &branchScope{
		Token:      token,
		Disclosure: disclosure,
		Openings:   openings,
	}, nil
}

func requestTokenFromAS(perms []string) (*ASTokenResponse, error) {
	b, _ := json.Marshal(map[string]interface{}{"permissions": perms})
	var resp *http.Response
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		resp, err = http.Post(asURL, "application/json", bytes.NewReader(b))
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var data ASTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return &data, nil
}

func callMCP(ctx context.Context, endpoint, tool string, args map[string]any) map[string]any {
	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-host"}, nil)
	var session *mcp.ClientSession
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		session, err = client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint}, nil)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		log.Fatal(err)
	}
	if len(result.Content) == 0 {
		log.Fatal("empty MCP response")
	}
	for _, c := range result.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			if len(t.Text) >= 6 && t.Text[:6] == "ERROR:" {
				log.Fatal(t.Text)
			}
			var out map[string]any
			if err := json.Unmarshal([]byte(t.Text), &out); err != nil {
				log.Fatal(err)
			}
			return out
		}
	}
	log.Fatal("MCP response did not contain text")
	return nil
}

func callPatchAgent(ctx context.Context, token string, presentations map[string]*sd.Disclosure, contextHash string, rc *pact.RevocationCheckpoint) (map[string]any, error) {
	var card *a2a.AgentCard
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		card, err = agentcard.DefaultResolver.Resolve(ctx, agentCardURL)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		return nil, err
	}
	client, err := a2aclient.NewFromCard(ctx, card)
	if err != nil {
		return nil, err
	}
	msgPayload := map[string]any{
		"jws":                   token,
		"presentations":         presentations,
		"context_hash":          contextHash,
		"revocation_checkpoint": rc,
	}
	resp, err := client.SendMessage(ctx, &a2a.MessageSendParams{
		Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.TextPart{Text: string(mustJSON(msgPayload))}),
	})
	if err != nil {
		return nil, err
	}
	msg, ok := resp.(*a2a.Message)
	if !ok {
		return nil, errUnexpectedAgentResult{resp}
	}
	if len(msg.Parts) == 0 {
		return nil, errUnexpectedAgentResult{resp}
	}
	var text string
	switch part := msg.Parts[0].(type) {
	case a2a.TextPart:
		text = part.Text
	case *a2a.TextPart:
		text = part.Text
	default:
		return nil, errUnexpectedAgentResult{resp}
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		return nil, err
	}
	if msg, ok := out["error"].(string); ok && msg != "" {
		return nil, errAgent(msg)
	}
	return out, nil
}

func patchArtifactFromAgentResponse(resp map[string]any) (patchArtifact, error) {
	nested, _ := resp["patch"].(map[string]any)
	artifact := patchArtifact{
		PatchText:     stringFromResponse(resp, nested, "patch_text"),
		PatchHash:     stringFromResponse(resp, nested, "patch_hash"),
		RationaleHash: stringFromResponse(resp, nested, "rationale_hash"),
		ModelID:       stringFromResponse(resp, nested, "model_id"),
		RiskLevel:     stringFromResponse(resp, nested, "risk_level"),
	}
	if artifact.PatchHash == "" {
		return patchArtifact{}, fmt.Errorf("patch_hash is required")
	}
	return artifact, nil
}

func repositoryManagementArgs(token string, evidence *pact.Evidence, contextHash string, artifact patchArtifact, rc *pact.RevocationCheckpoint) map[string]any {
	args := map[string]any{
		"token":                 token,
		"extended_token":        token,
		"evidence":              evidence,
		"context_hash":          contextHash,
		"revocation_checkpoint": rc,
	}
	if artifact.PatchText != "" {
		args["patch_text"] = artifact.PatchText
		args["patch_hash"] = artifact.PatchHash
	}
	return args
}

func collectRepositoryManagementEvidence(evidence *pact.Evidence, resp map[string]any) error {
	if evidence == nil {
		return fmt.Errorf("nil evidence")
	}
	if evidence.NodeOpenings == nil {
		evidence.NodeOpenings = map[int][]sd.FieldOpening{}
	}
	fields := []struct {
		node int
		key  string
	}{
		{node: 2, key: "application_openings"},
		{node: 3, key: "test_openings"},
		{node: 4, key: "final_openings"},
	}
	for _, field := range fields {
		openings, err := decodeOpeningsField(resp, field.key)
		if err != nil {
			return err
		}
		evidence.NodeOpenings[field.node] = openings
	}
	return nil
}

func validateRepositoryManagementResponse(resp map[string]any, patchTextSent bool) error {
	status := stringValue(resp, "status")
	if status != "ok" {
		return fmt.Errorf("status=%q", status)
	}
	if patchTextSent {
		testResult := stringValue(resp, "test_result")
		if testResult != "passed" {
			return fmt.Errorf("test_result=%q", testResult)
		}
	}
	return nil
}

func finalSummary(contextHash string, artifact patchArtifact, repoResp map[string]any) map[string]any {
	return map[string]any{
		"task_id":                 workflow.TaskID,
		"issue_id":                workflow.IssueID,
		"repo":                    workflow.Repo,
		"allowed_paths":           rootAllowedPaths(),
		"context_hash":            contextHash,
		"patch_hash":              artifact.PatchHash,
		"rationale_hash":          artifact.RationaleHash,
		"model_id":                artifact.ModelID,
		"risk_level":              artifact.RiskLevel,
		"diff_hash":               stringValue(repoResp, "diff_hash"),
		"test_result":             stringValue(repoResp, "test_result"),
		"test_log_hash":           stringValue(repoResp, "test_log_hash"),
		"artifact_hash":           stringValue(repoResp, "artifact_hash"),
		"modified_paths":          stringSliceValue(repoResp, "modified_paths"),
		"branch":                  stringValue(repoResp, "branch"),
		"final_status":            stringValue(repoResp, "status"),
		"joint_branch_validation": stringValue(repoResp, "joint_branch_validation"),
		"pr_url":                  stringValue(repoResp, "pr_url"),
	}
}

func branchWorkflowLines() []string {
	return []string{
		"Branch-based local bug-fix workflow:",
		"Root grant T0 = [n0]",
		"Context branch T_ctx = [n0, n1_ctx_scope, n2_ctx_result]",
		"Patch branch T_patch = [n0, n1_patch_scope, n2_patch_result]",
		"Repository branch T_repo = [n0, n1_repo_scope, n2_apply, n3_test, n4_release]",
		"Final validation = joint branch validation",
	}
}

func pactBranchSummaryLines(rootToken string, branches workflow.CodeMaintenanceBranchPresentation, contextHash string, artifact patchArtifact, repoResp map[string]any) []string {
	validation := stringValue(repoResp, "joint_branch_validation")
	if validation == "" {
		validation = "pending"
	}
	lines := []string{
		"PACT branch summary:",
		"  tid_0: " + workflow.TaskID,
		"  root_token: T0",
		"  root_token_fingerprint: " + safeFingerprint(rootToken),
		"  chain_authentication_mode: SchoCo",
	}
	lines = append(lines, branchSummaryLine("context", "T_ctx", "[n0, n1_ctx_scope, n2_ctx_result]", 2, branches.Context.Token, map[string]string{
		"context_hash": contextHash,
	}, "accepted"))
	lines = append(lines, branchSummaryLine("patch", "T_patch", "[n0, n1_patch_scope, n2_patch_result]", 2, branches.Patch.Token, map[string]string{
		"context_hash": contextHash,
		"patch_hash":   artifact.PatchHash,
	}, "accepted"))
	lines = append(lines, branchSummaryLine("repository", "T_repo", "[n0, n1_repo_scope, n2_apply, n3_test, n4_release]", 4, branches.Repository.Token, map[string]string{
		"context_hash":  contextHash,
		"patch_hash":    artifact.PatchHash,
		"diff_hash":     stringValue(repoResp, "diff_hash"),
		"test_log_hash": stringValue(repoResp, "test_log_hash"),
		"artifact_hash": stringValue(repoResp, "artifact_hash"),
	}, "accepted"))
	lines = append(lines, "  joint_branch_validation: "+validation)
	return lines
}

func branchSummaryLine(name, tokenLabel, nodes string, terminalIndex int, token string, deps map[string]string, validation string) string {
	parts := []string{
		"  branch=" + name,
		"token=" + tokenLabel,
		"nodes=" + nodes,
		fmt.Sprintf("terminal_prefix_index=%d", terminalIndex),
		"terminal_signature_fingerprint=" + terminalSignatureFingerprint(token),
	}
	for _, key := range []string{"context_hash", "patch_hash", "diff_hash", "test_log_hash", "artifact_hash"} {
		if value := deps[key]; value != "" {
			parts = append(parts, key+"="+value)
		}
	}
	parts = append(parts, "branch_validation="+validation)
	return strings.Join(parts, " ")
}

func dependencySummaryLines(contextHash, patchHash string, repoResp map[string]any) []string {
	diffHash := stringValue(repoResp, "diff_hash")
	testResult := stringValue(repoResp, "test_result")
	testLogHash := stringValue(repoResp, "test_log_hash")
	artifact := stringValue(repoResp, "artifact_hash")
	status := stringValue(repoResp, "status")
	return []string{
		"Dependency summary:",
		"  patch branch depends on context_hash=" + contextHash,
		"  repository branch depends on context_hash=" + contextHash + " and patch_hash=" + patchHash,
		"  apply node binds patch_hash=" + patchHash + " to diff_hash=" + diffHash,
		"  test node binds diff_hash=" + diffHash + " to test_result=" + testResult + " and test_log_hash=" + testLogHash,
		"  release node binds passing test state to artifact_hash=" + artifact + " and final_status=" + status,
	}
}

func fixtureSafetyLines(repoResp map[string]any) []string {
	testResult := stringValue(repoResp, "test_result")
	testLine := "Fixture tests in temporary worktree: " + testResult
	if testResult == "passed" {
		testLine = "Fixture tests pass in the temporary worktree."
	}
	validation := stringValue(repoResp, "joint_branch_validation")
	if validation == "" {
		validation = "pending"
	}
	return []string{
		"Fixture regression test is present in poc/fixture-repo.",
		"Original fixture repo is not modified.",
		"Patch workflow runs only in a temporary worktree.",
		testLine,
		"joint_branch_validation: " + validation,
	}
}

func finalSummaryLines(summary map[string]any) []string {
	lines := []string{"Final summary:"}
	for _, key := range []string{
		"task_id",
		"issue_id",
		"repo",
		"allowed_paths",
		"modified_paths",
		"context_hash",
		"patch_hash",
		"diff_hash",
		"test_result",
		"test_log_hash",
		"artifact_hash",
		"final_status",
		"joint_branch_validation",
	} {
		lines = append(lines, fmt.Sprintf("  %s: %s", key, summaryValue(summary[key])))
	}
	return lines
}

func safeFingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func terminalSignatureFingerprint(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "invalid-token"
	}
	return safeFingerprint(parts[2])
}

func summaryValue(value any) string {
	switch v := value.(type) {
	case []string:
		return strings.Join(v, ", ")
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			parts = append(parts, fmt.Sprint(item))
		}
		return strings.Join(parts, ", ")
	case string:
		return v
	default:
		return fmt.Sprint(v)
	}
}

func logHostLines(lines []string) {
	for _, line := range lines {
		log.Println("[Host]", line)
	}
}

func verboseOutput() bool {
	return os.Getenv("PACT_POC_VERBOSE") == "1"
}

func rootAllowedPaths() []string {
	rootClaims := workflow.RootClaims(workflow.RootPermissions)
	allowed := workflow.StringClaim(rootClaims, "allowed_paths")
	if allowed == "" {
		return nil
	}
	parts := strings.Split(allowed, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func stringSliceValue(m map[string]any, key string) []string {
	if m == nil {
		return nil
	}
	switch v := m[key].(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil
			}
			out = append(out, s)
		}
		return out
	default:
		return nil
	}
}

func stringFromResponse(top, nested map[string]any, key string) string {
	if v := stringValue(top, key); v != "" {
		return v
	}
	return stringValue(nested, key)
}

func stringValue(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, _ := m[key].(string)
	return v
}

func decodeOpeningsField(m map[string]any, key string) ([]sd.FieldOpening, error) {
	b, err := json.Marshal(m[key])
	if err != nil {
		return nil, err
	}
	var openings []sd.FieldOpening
	if err := json.Unmarshal(b, &openings); err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	if len(openings) == 0 {
		return nil, fmt.Errorf("%s is empty", key)
	}
	return openings, nil
}

type errAgent string

func (e errAgent) Error() string { return string(e) }

type errUnexpectedAgentResult struct{ got any }

func (e errUnexpectedAgentResult) Error() string { return "unexpected A2A result shape" }

func mustDisclosure(keys []string, openings []sd.FieldOpening, selected ...string) *sd.Disclosure {
	idx, err := workflow.Indexes(keys, selected...)
	if err != nil {
		log.Fatal(err)
	}
	disc, err := sd.CreateDisclosureFromOpenings(openings, idx)
	if err != nil {
		log.Fatal(err)
	}
	return disc
}

func disclosureField(m map[string]any, key string) *sd.Disclosure {
	b := mustJSON(m[key])
	d, err := sd.FromJSON(b)
	if err != nil {
		log.Fatal(err)
	}
	return d
}

func openingsField(m map[string]any, key string) []sd.FieldOpening {
	b := mustJSON(m[key])
	var openings []sd.FieldOpening
	if err := json.Unmarshal(b, &openings); err != nil {
		log.Fatal(err)
	}
	return openings
}

func mapField(m map[string]any, key string) map[string]any {
	v, ok := m[key].(map[string]any)
	if !ok {
		log.Fatal("missing map field: ", key)
	}
	return v
}

func stringField(m map[string]any, key string) string {
	v, ok := m[key].(string)
	if !ok || v == "" {
		log.Fatal("missing string field: ", key)
	}
	return v
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
