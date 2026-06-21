package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"flow-poc/internal/workflow"
	pact "flow-poc/pact"
	sd "flow-poc/sd"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var fixtureRelevantFiles = []string{
	"internal/api/projects.go",
	"internal/api/projects_test.go",
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "code-maintenance-tools",
		Version: "1.0.0",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "context",
		Description: "Validate issue/repo access and return issue context for issue #184",
	}, func(ctx context.Context, req *mcp.CallToolRequest, rawArgs map[string]any) (*mcp.CallToolResult, any, error) {
		var args tokenArgs
		if err := decodeArgs(rawArgs, &args); err != nil {
			return errorResult("failed to parse arguments: " + err.Error()), nil, nil
		}
		return contextTool(ctx, args.Token, args.Presentations, args.RevocationCheckpoint)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "review",
		Description: "Validate patch evidence and return policy review decision",
	}, func(ctx context.Context, req *mcp.CallToolRequest, rawArgs map[string]any) (*mcp.CallToolResult, any, error) {
		var args tokenArgs
		if err := decodeArgs(rawArgs, &args); err != nil {
			return errorResult("failed to parse arguments: " + err.Error()), nil, nil
		}
		return reviewTool(ctx, args.Token, args.Presentations, args.RevocationCheckpoint)
	})

	handler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return server
	}, nil)

	log.Println("[Context/Review] Listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", handler))
}

type tokenArgs struct {
	Token                string                     `json:"token"`
	Presentations        []string                   `json:"presentations"`
	RevocationCheckpoint *pact.RevocationCheckpoint `json:"revocation_checkpoint"`
}

func contextTool(ctx context.Context, token string, presentations []string, rc *pact.RevocationCheckpoint) (*mcp.CallToolResult, any, error) {
	log.Println("[Context] context request received")
	presMap, err := parsePresentations(presentations)
	if err != nil {
		return errorResult(err.Error()), nil, nil
	}
	if err := validatePresentations(ctx, token, presMap, rc); err != nil {
		return errorResult("token validation failed: " + err.Error()), nil, nil
	}
	rootClaims, err := workflow.ClaimsFromDisclosure(presMap[0])
	if err != nil {
		return errorResult("invalid root disclosure: " + err.Error()), nil, nil
	}
	if workflow.StringClaim(rootClaims, "repo") != workflow.Repo || workflow.StringClaim(rootClaims, "issue_id") != workflow.IssueID {
		return errorResult("access denied: token is not bound to requested repo/issue"), nil, nil
	}
	scopeClaims, err := workflow.ClaimsFromDisclosure(presMap[1])
	if err != nil {
		return errorResult("invalid context-scope disclosure: " + err.Error()), nil, nil
	}
	if workflow.StringClaim(scopeClaims, "branch_id") != workflow.BranchContext {
		return errorResult("access denied: context branch scope required"), nil, nil
	}
	if !workflow.BoolClaim(scopeClaims, "issue.read") || !workflow.BoolClaim(scopeClaims, "repo.read") {
		return errorResult("access denied: issue.read and repo.read required"), nil, nil
	}
	if workflow.StringClaim(scopeClaims, "repo") != workflow.Repo || workflow.StringClaim(scopeClaims, "issue_id") != workflow.IssueID {
		return errorResult("access denied: context scope is not bound to requested repo/issue"), nil, nil
	}

	payload := &pact.Payload{
		Ver:       pact.ModeSchoCo,
		TID0:      workflow.TaskID,
		NodeIndex: 2,
		Iat:       time.Now().Unix(),
		Iss:       &pact.IDClaim{CN: "spiffe://example.org/context-tool"},
	}
	result, err := loadFixtureContext()
	if err != nil {
		return errorResult("load fixture context failed: " + err.Error()), nil, nil
	}
	contextClaims := workflow.ContextResultClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, result)
	keys, openings, err := pact.AttachCommitmentRootToPayload(payload, payload.TID0, 2, contextClaims)
	if err != nil {
		return errorResult("attach commitment root failed: " + err.Error()), nil, nil
	}
	selected, err := workflow.Indexes(keys, "task_id", "repo", "issue_id", "branch_id", "issue_hash", "files_hash", "context_hash", "relevant_files")
	if err != nil {
		return errorResult(err.Error()), nil, nil
	}
	disc, err := sd.CreateDisclosureFromOpenings(openings, selected)
	if err != nil {
		return errorResult("create disclosure failed: " + err.Error()), nil, nil
	}
	extended, err := pact.ExtendJWS(token, &pact.LDNode{Payload: payload}, pact.ModeSchoCo)
	if err != nil {
		return errorResult("extend token failed: " + err.Error()), nil, nil
	}
	log.Println("[Context] Extended context branch locally: T_ctx=[n0,n1_ctx_scope,n2_ctx_result]")

	return jsonResult(map[string]any{
		"extended_token": extended,
		"disclosure":     disc,
		"openings":       openings,
		"context":        result,
	}), nil, nil
}

func reviewTool(ctx context.Context, token string, presentations []string, rc *pact.RevocationCheckpoint) (*mcp.CallToolResult, any, error) {
	presMap, err := parsePresentations(presentations)
	if err != nil {
		return errorResult(err.Error()), nil, nil
	}
	if err := validatePresentations(ctx, token, presMap, rc); err != nil {
		return errorResult("token validation failed: " + err.Error()), nil, nil
	}
	patchClaims, err := workflow.ClaimsFromDisclosure(presMap[2])
	if err != nil {
		return errorResult("invalid patch disclosure: " + err.Error()), nil, nil
	}
	contextClaims, err := workflow.ClaimsFromDisclosure(presMap[1])
	if err != nil {
		return errorResult("invalid context disclosure: " + err.Error()), nil, nil
	}
	contextHash := workflow.StringClaim(contextClaims, "context_hash")
	if workflow.StringClaim(patchClaims, "context_hash") != contextHash || contextHash == "" || workflow.StringClaim(patchClaims, "patch_hash") == "" {
		return errorResult("patch is not bound to expected context"), nil, nil
	}
	approved := workflow.StringClaim(patchClaims, "risk_level") == "low"
	patchHash := workflow.StringClaim(patchClaims, "patch_hash")

	payload := &pact.Payload{
		Ver:       pact.ModeSchoCo,
		TID0:      workflow.TaskID,
		NodeIndex: 3,
		Iat:       time.Now().Unix(),
		Iss:       &pact.IDClaim{CN: "spiffe://example.org/review-policy-tool"},
	}
	reviewClaims := workflow.ReviewClaims(patchHash, approved)
	reviewClaims["context_hash"] = contextHash
	keys, openings, err := pact.AttachCommitmentRootToPayload(payload, payload.TID0, 3, reviewClaims)
	if err != nil {
		return errorResult("attach commitment root failed: " + err.Error()), nil, nil
	}
	selected, err := workflow.Indexes(keys, "task_id", "repo", "issue_id", "context_hash", "patch_hash", "review_result_hash", "decision")
	if err != nil {
		return errorResult(err.Error()), nil, nil
	}
	disc, err := sd.CreateDisclosureFromOpenings(openings, selected)
	if err != nil {
		return errorResult("create disclosure failed: " + err.Error()), nil, nil
	}
	extended, err := pact.ExtendJWS(token, &pact.LDNode{Payload: payload}, pact.ModeSchoCo)
	if err != nil {
		return errorResult("extend token failed: " + err.Error()), nil, nil
	}

	return jsonResult(map[string]any{
		"extended_token": extended,
		"disclosure":     disc,
		"openings":       openings,
		"review": workflow.ReviewResult{
			ReviewResultHash: workflow.ReviewResultHash,
			Decision:         workflow.StringClaim(reviewClaims, "decision"),
		},
	}), nil, nil
}

func loadFixtureContext() (workflow.ContextResult, error) {
	fixtureRoot, err := findFixtureRepo()
	if err != nil {
		return workflow.ContextResult{}, err
	}

	issueContent, err := os.ReadFile(filepath.Join(fixtureRoot, "issues", workflow.IssueID+".md"))
	if err != nil {
		return workflow.ContextResult{}, fmt.Errorf("read issue: %w", err)
	}
	log.Printf("[Context] issue file loaded: issues/%s.md", workflow.IssueID)

	fileContents := make(map[string][]byte, len(fixtureRelevantFiles))
	for _, rel := range fixtureRelevantFiles {
		content, err := os.ReadFile(filepath.Join(fixtureRoot, rel))
		if err != nil {
			return workflow.ContextResult{}, fmt.Errorf("read %s: %w", rel, err)
		}
		fileContents[rel] = content
		log.Printf("[Context] relevant file loaded: %s", rel)
	}

	issueHash := workflow.ComputeIssueHash(issueContent)
	filesHash := workflow.ComputeFilesHash(fileContents)
	contextHash := workflow.ComputeContextHash(workflow.IssueID, fixtureRelevantFiles, issueHash, filesHash)
	log.Println("[Context] context_hash computed:", contextHash)

	return workflow.ContextResult{
		IssueID:      workflow.IssueID,
		Title:        "API returns 500 when project_id is empty",
		RelevantFile: append([]string(nil), fixtureRelevantFiles...),
		IssueHash:    issueHash,
		FilesHash:    filesHash,
		ContextHash:  contextHash,
	}, nil
}

func findFixtureRepo() (string, error) {
	candidates := []string{
		"../fixture-repo",
		"fixture-repo",
		"poc/fixture-repo",
	}
	for _, candidate := range candidates {
		if isFixtureRepo(candidate) {
			return candidate, nil
		}
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for dir := cwd; ; dir = filepath.Dir(dir) {
		candidate := filepath.Join(dir, "fixture-repo")
		if isFixtureRepo(candidate) {
			return candidate, nil
		}
		candidate = filepath.Join(dir, "poc", "fixture-repo")
		if isFixtureRepo(candidate) {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
	}
	return "", fmt.Errorf("fixture-repo not found from %s", cwd)
}

func isFixtureRepo(path string) bool {
	info, err := os.Stat(filepath.Join(path, "go.mod"))
	return err == nil && !info.IsDir()
}

func validatePresentations(ctx context.Context, token string, presMap map[int]*sd.Disclosure, rc *pact.RevocationCheckpoint) error {
	now := time.Now()
	if rc == nil {
		return fmt.Errorf("missing revocation checkpoint")
	}
	return workflow.ValidateWithRevocation(token, nil, presMap, nil, rc, now)
}

func parsePresentations(presentations []string) (map[int]*sd.Disclosure, error) {
	presMap := map[int]*sd.Disclosure{}
	for i, pStr := range presentations {
		d, err := sd.FromJSON([]byte(pStr))
		if err != nil {
			return nil, err
		}
		presMap[i] = d
	}
	return presMap, nil
}

func decodeArgs(raw map[string]any, dst any) error {
	b, _ := json.Marshal(raw)
	return json.Unmarshal(b, dst)
}

func errorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ERROR: " + msg}}}
}

func jsonResult(v any) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(jsonMustMarshal(v))}}}
}

func jsonMustMarshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
