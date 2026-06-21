package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"flow-poc/internal/workflow"
	pact "flow-poc/pact"
	sd "flow-poc/sd"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "repository-management",
		Version: "1.0.0",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "openPR",
		Description: "Validate final PACT evidence and create a mocked pull request",
	}, func(ctx context.Context, req *mcp.CallToolRequest, rawArgs map[string]any) (*mcp.CallToolResult, any, error) {
		var args struct {
			Token                string                     `json:"token"`
			Evidence             *pact.Evidence             `json:"evidence"`
			PatchText            string                     `json:"patch_text"`
			PatchHash            string                     `json:"patch_hash"`
			ContextHash          string                     `json:"context_hash"`
			RevocationCheckpoint *pact.RevocationCheckpoint `json:"revocation_checkpoint"`
		}
		b, _ := json.Marshal(rawArgs)
		if err := json.Unmarshal(b, &args); err != nil {
			return errorResult("failed to parse arguments: " + err.Error()), nil, nil
		}
		return openPR(ctx, args.Token, args.Evidence, args.PatchText, args.PatchHash, args.ContextHash, args.RevocationCheckpoint)
	})

	handler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return server
	}, nil)

	log.Println("[RepoMgmt] Listening on :8083")
	log.Fatal(http.ListenAndServe(":8083", handler))
}

func openPR(ctx context.Context, token string, evidence *pact.Evidence, patchText, suppliedPatchHash, suppliedContextHash string, rc *pact.RevocationCheckpoint) (*mcp.CallToolResult, any, error) {
	log.Println("[RepoMgmt] repository-management/finalization request received")
	now := time.Now()
	if rc == nil {
		return errorResult("missing revocation checkpoint"), nil, nil
	}
	if err := workflow.ValidateWithRevocation(token, evidence, nil, nil, rc, now); err != nil {
		return errorResult("repository branch prefix denied: " + err.Error()), nil, nil
	}
	scopeClaims, err := workflow.ClaimsFromOpenings(evidence.NodeOpenings[1])
	if err != nil {
		return errorResult("invalid repository-scope evidence: " + err.Error()), nil, nil
	}
	if workflow.StringClaim(scopeClaims, "branch_id") != workflow.BranchRepository {
		return errorResult("repository branch scope required"), nil, nil
	}
	evidencePatchHash := workflow.StringClaim(scopeClaims, "patch_hash")
	evidenceContextHash := workflow.StringClaim(scopeClaims, "context_hash")
	if suppliedContextHash != "" && suppliedContextHash != evidenceContextHash {
		return errorResult("context_hash does not match repository scope"), nil, nil
	}
	if suppliedPatchHash != "" && suppliedPatchHash != evidencePatchHash {
		return errorResult("patch_hash does not match repository scope"), nil, nil
	}

	resp := map[string]any{
		"status":         "ok",
		"pr_url":         "https://git.example/" + workflow.Repo + "/pull/184",
		"branch":         workflow.BranchPrefix + "-empty-project-id",
		"context_hash":   evidenceContextHash,
		"patch_hash":     evidencePatchHash,
		"token":          token,
		"extended_token": token,
	}

	if patchText == "" {
		reviewClaims, err := workflow.ClaimsFromOpenings(evidence.NodeOpenings[3])
		if err != nil {
			return errorResult("invalid review evidence: " + err.Error()), nil, nil
		}
		resp["review_result_hash"] = workflow.StringClaim(reviewClaims, "review_result_hash")
		return jsonResult(resp), nil, nil
	}

	localResult, err := executeLocalRepositoryWorkflow(ctx, patchText, evidencePatchHash)
	if err != nil {
		return errorResult("local repository workflow failed: " + err.Error()), nil, nil
	}
	resp["modified_paths"] = localResult.ModifiedPaths
	resp["diff_hash"] = localResult.DiffHash
	resp["test_result"] = localResult.TestResult
	resp["test_log_hash"] = localResult.TestLogHash
	resp["artifact_hash"] = localResult.ArtifactHash

	tokenArtifacts, err := extendLocalArtifactToken(token, evidenceContextHash, localResult)
	if err != nil {
		return errorResult("extend local artifact token failed: " + err.Error()), nil, nil
	}
	log.Println("[RepoMgmt] Extended repository branch locally: T_repo=[n0,n1_repo_scope,n2_apply,n3_test,n4_release]")
	resp["extended_token"] = tokenArtifacts.Token
	resp["application_disclosure"] = tokenArtifacts.ApplicationDisclosure
	resp["application_openings"] = tokenArtifacts.ApplicationOpenings
	resp["test_disclosure"] = tokenArtifacts.TestDisclosure
	resp["test_openings"] = tokenArtifacts.TestOpenings
	resp["final_disclosure"] = tokenArtifacts.FinalDisclosure
	resp["final_openings"] = tokenArtifacts.FinalOpenings
	resp["disclosure"] = tokenArtifacts.FinalDisclosure
	resp["openings"] = tokenArtifacts.FinalOpenings

	if localResult.TestResult != "passed" {
		resp["status"] = "tests_failed"
		delete(resp, "pr_url")
	}
	log.Println("[RepoMgmt] final_status:", resp["status"])
	return jsonResult(resp), nil, nil
}

type localRepositoryResult struct {
	Branch        string
	ModifiedPaths []string
	DiffHash      string
	TestResult    string
	TestLogHash   string
	TestOutput    string
	PatchHash     string
	ArtifactHash  string
}

type localTokenArtifacts struct {
	Token                 string
	ApplicationDisclosure *sd.Disclosure
	ApplicationOpenings   []sd.FieldOpening
	TestDisclosure        *sd.Disclosure
	TestOpenings          []sd.FieldOpening
	FinalDisclosure       *sd.Disclosure
	FinalOpenings         []sd.FieldOpening
}

func executeLocalRepositoryWorkflow(ctx context.Context, patchText, patchHash string) (*localRepositoryResult, error) {
	if patchText == "" {
		return nil, fmt.Errorf("patch_text is required")
	}
	computedPatchHash := workflow.ComputePatchHash(patchText)
	if patchHash != "" && patchHash != computedPatchHash {
		return nil, fmt.Errorf("patch_hash does not match patch_text")
	}
	if patchHash == "" {
		patchHash = computedPatchHash
	}

	fixtureRoot, err := findFixtureRepo()
	if err != nil {
		return nil, err
	}
	tempRoot, err := os.MkdirTemp("", "pact-fixture-worktree-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempRoot)

	worktree := filepath.Join(tempRoot, "fixture-repo")
	if err := copyDir(fixtureRoot, worktree); err != nil {
		return nil, err
	}
	log.Println("[RepoMgmt] fixture repo copied to temp worktree")
	if err := applyUnifiedDiff(ctx, worktree, patchText); err != nil {
		return nil, err
	}
	log.Println("[RepoMgmt] git apply executed")

	modifiedPaths, err := changedFiles(fixtureRoot, worktree)
	if err != nil {
		return nil, err
	}
	if len(modifiedPaths) == 0 {
		modifiedPaths = modifiedPathsFromPatch(patchText)
	}
	log.Println("[RepoMgmt] modified_paths:", modifiedPaths)
	diffHash, err := computePatchedArtifactHash(worktree, modifiedPaths)
	if err != nil {
		return nil, err
	}
	log.Println("[RepoMgmt] diff_hash:", diffHash)
	testOutput, passed := runFixtureTests(ctx, tempRoot, worktree)
	log.Println("[RepoMgmt] go test ./... executed")
	testResult := "failed"
	if passed {
		testResult = "passed"
	}
	testLogHash := workflow.ComputeTestLogHash(testOutput)
	log.Println("[RepoMgmt] test_result:", testResult)
	log.Println("[RepoMgmt] test_log_hash:", testLogHash)

	return &localRepositoryResult{
		Branch:        workflow.BranchPrefix + "-empty-project-id",
		ModifiedPaths: modifiedPaths,
		DiffHash:      diffHash,
		TestResult:    testResult,
		TestLogHash:   testLogHash,
		TestOutput:    testOutput,
		PatchHash:     patchHash,
		ArtifactHash:  workflow.HashArtifact("artifact", []byte(diffHash+"\n"+testResult+"\n"+testLogHash)),
	}, nil
}

func extendLocalArtifactToken(token, contextHash string, result *localRepositoryResult) (*localTokenArtifacts, error) {
	applicationPayload := &pact.Payload{
		Ver:       pact.ModeSchoCo,
		TID0:      workflow.TaskID,
		NodeIndex: 2,
		Iat:       time.Now().Unix(),
		Iss:       &pact.IDClaim{CN: "spiffe://example.org/repository-management"},
	}
	applicationResult := workflow.ApplyResult{
		PatchHash:    result.PatchHash,
		DiffHash:     result.DiffHash,
		Applied:      true,
		ModifiedPath: result.ModifiedPaths,
		FilesChanged: result.ModifiedPaths,
	}
	appClaims := workflow.PatchApplicationClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, applicationResult)
	appKeys, appOpenings, err := pact.AttachCommitmentRootToPayload(applicationPayload, applicationPayload.TID0, 2, appClaims)
	if err != nil {
		return nil, err
	}
	appSelected, err := workflow.Indexes(appKeys, "task_id", "repo", "issue_id", "patch.apply", "patch_hash", "diff_hash", "applied", "modified_paths")
	if err != nil {
		return nil, err
	}
	appDisclosure, err := sd.CreateDisclosureFromOpenings(appOpenings, appSelected)
	if err != nil {
		return nil, err
	}
	appToken, err := pact.ExtendJWS(token, &pact.LDNode{Payload: applicationPayload}, pact.ModeSchoCo)
	if err != nil {
		return nil, err
	}

	testPayload := &pact.Payload{
		Ver:       pact.ModeSchoCo,
		TID0:      workflow.TaskID,
		NodeIndex: 3,
		Iat:       time.Now().Unix(),
		Iss:       &pact.IDClaim{CN: "spiffe://example.org/repository-management"},
	}
	testResult := workflow.TestResult{
		DiffHash:    result.DiffHash,
		TestLogHash: result.TestLogHash,
		Passed:      result.TestResult == "passed",
		TestResult:  result.TestResult,
		Command:     "go test ./...",
	}
	testClaims := workflow.TestExecutionClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, testResult)
	testKeys, testOpenings, err := pact.AttachCommitmentRootToPayload(testPayload, testPayload.TID0, 3, testClaims)
	if err != nil {
		return nil, err
	}
	testSelected, err := workflow.Indexes(testKeys, "task_id", "repo", "issue_id", "test.execute", "diff_hash", "test_log_hash", "passed", "test_result", "command")
	if err != nil {
		return nil, err
	}
	testDisclosure, err := sd.CreateDisclosureFromOpenings(testOpenings, testSelected)
	if err != nil {
		return nil, err
	}
	testToken, err := pact.ExtendJWS(appToken, &pact.LDNode{Payload: testPayload}, pact.ModeSchoCo)
	if err != nil {
		return nil, err
	}

	finalPayload := &pact.Payload{
		Ver:       pact.ModeSchoCo,
		TID0:      workflow.TaskID,
		NodeIndex: 4,
		Iat:       time.Now().Unix(),
		Iss:       &pact.IDClaim{CN: "spiffe://example.org/repository-management"},
	}
	finalResult := workflow.FinalArtifactResult{
		ContextHash:  contextHash,
		PatchHash:    result.PatchHash,
		DiffHash:     result.DiffHash,
		TestLogHash:  result.TestLogHash,
		ArtifactHash: result.ArtifactHash,
		Branch:       result.Branch,
		TestResult:   result.TestResult,
		Status:       "ok",
	}
	if result.TestResult != "passed" {
		finalResult.Status = "tests_failed"
	}
	finalClaims := workflow.FinalArtifactClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, finalResult)
	finalKeys, finalOpenings, err := pact.AttachCommitmentRootToPayload(finalPayload, finalPayload.TID0, 4, finalClaims)
	if err != nil {
		return nil, err
	}
	finalSelected, err := workflow.Indexes(finalKeys, "task_id", "repo", "issue_id", "artifact.release", "context_hash", "patch_hash", "diff_hash", "test_log_hash", "artifact_hash", "branch", "test_result", "status")
	if err != nil {
		return nil, err
	}
	finalDisclosure, err := sd.CreateDisclosureFromOpenings(finalOpenings, finalSelected)
	if err != nil {
		return nil, err
	}
	finalToken, err := pact.ExtendJWS(testToken, &pact.LDNode{Payload: finalPayload}, pact.ModeSchoCo)
	if err != nil {
		return nil, err
	}

	return &localTokenArtifacts{
		Token:                 finalToken,
		ApplicationDisclosure: appDisclosure,
		ApplicationOpenings:   appOpenings,
		TestDisclosure:        testDisclosure,
		TestOpenings:          testOpenings,
		FinalDisclosure:       finalDisclosure,
		FinalOpenings:         finalOpenings,
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

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode())
	})
}

func applyUnifiedDiff(ctx context.Context, worktree, patchText string) error {
	cmd := exec.CommandContext(ctx, "git", "apply", "--whitespace=nowarn", "-")
	cmd.Dir = worktree
	cmd.Stdin = strings.NewReader(patchText)
	output, err := cmd.CombinedOutput()
	if err != nil {
		check := exec.CommandContext(ctx, "git", "apply", "--reverse", "--check", "-")
		check.Dir = worktree
		check.Stdin = strings.NewReader(patchText)
		if checkOutput, checkErr := check.CombinedOutput(); checkErr == nil {
			return nil
		} else if len(checkOutput) > 0 {
			output = append(output, '\n')
			output = append(output, checkOutput...)
		}
		return fmt.Errorf("git apply: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func changedFiles(original, worktree string) ([]string, error) {
	var paths []string
	if err := filepath.WalkDir(worktree, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(worktree, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		originalContent, originalErr := os.ReadFile(filepath.Join(original, filepath.FromSlash(rel)))
		worktreeContent, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if originalErr != nil || !bytes.Equal(originalContent, worktreeContent) {
			paths = append(paths, rel)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Strings(paths)
	return paths, nil
}

func modifiedPathsFromPatch(patchText string) []string {
	seen := make(map[string]bool)
	var paths []string
	for _, line := range strings.Split(patchText, "\n") {
		if !strings.HasPrefix(line, "+++ b/") {
			continue
		}
		path := strings.TrimPrefix(line, "+++ b/")
		if path == "" || path == "/dev/null" || seen[path] {
			continue
		}
		seen[path] = true
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func computePatchedArtifactHash(worktree string, modifiedPaths []string) (string, error) {
	var b strings.Builder
	for _, rel := range modifiedPaths {
		content, err := os.ReadFile(filepath.Join(worktree, filepath.FromSlash(rel)))
		if err != nil {
			return "", err
		}
		b.WriteString("path:")
		b.WriteString(rel)
		b.WriteByte('\n')
		b.Write(content)
		if len(content) == 0 || content[len(content)-1] != '\n' {
			b.WriteByte('\n')
		}
	}
	return workflow.ComputeDiffHash(b.String()), nil
}

func runFixtureTests(ctx context.Context, tempRoot, worktree string) (string, bool) {
	cacheDir := filepath.Join(tempRoot, ".gocache")
	_ = os.MkdirAll(cacheDir, 0o755)

	cmd := exec.CommandContext(ctx, "go", "test", "./...")
	cmd.Dir = worktree
	cmd.Env = append(os.Environ(), "GOCACHE="+cacheDir, "GOTOOLCHAIN=local")
	output, err := cmd.CombinedOutput()
	return string(output), err == nil
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
