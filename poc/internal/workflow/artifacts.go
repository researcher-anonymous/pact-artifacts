package workflow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

var LocalWorkflowPermissions = []string{
	"issue.read",
	"repo.read",
	"patch.propose",
	"analysis.execute",
	"patch.apply",
	"test.execute",
	"artifact.release",
}

const (
	BranchContext    = "context"
	BranchPatch      = "patch"
	BranchRepository = "repository"
)

type ApplyResult struct {
	PatchHash    string   `json:"patch_hash"`
	DiffHash     string   `json:"diff_hash"`
	Applied      bool     `json:"applied"`
	ModifiedPath []string `json:"modified_paths,omitempty"`
	FilesChanged []string `json:"files_changed,omitempty"`
}

type TestResult struct {
	DiffHash    string `json:"diff_hash"`
	TestLogHash string `json:"test_log_hash"`
	Passed      bool   `json:"passed"`
	TestResult  string `json:"test_result,omitempty"`
	Command     string `json:"command,omitempty"`
}

type FinalArtifactResult struct {
	ContextHash  string `json:"context_hash,omitempty"`
	PatchHash    string `json:"patch_hash,omitempty"`
	DiffHash     string `json:"diff_hash"`
	TestLogHash  string `json:"test_log_hash"`
	ArtifactHash string `json:"artifact_hash,omitempty"`
	Branch       string `json:"branch,omitempty"`
	TestResult   string `json:"test_result,omitempty"`
	Status       string `json:"status,omitempty"`
}

func HashArtifact(label string, data []byte) string {
	sum := sha256.Sum256(data)
	return label + ":" + hex.EncodeToString(sum[:])
}

func ComputeIssueHash(issueContent []byte) string {
	return HashArtifact("issue", issueContent)
}

func ComputeFilesHash(files map[string][]byte) string {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	entries := make([]fileHashEntry, 0, len(paths))
	for _, path := range paths {
		content := files[path]
		entries = append(entries, fileHashEntry{
			Path:        path,
			ContentHash: HashArtifact("file", content),
			Size:        len(content),
		})
	}
	return HashArtifact("files", mustJSON(entries))
}

func ComputeContextHash(issueID string, relevantFiles []string, issueHash, filesHash string) string {
	files := append([]string(nil), relevantFiles...)
	sort.Strings(files)

	canonical := contextHashInput{
		IssueID:       issueID,
		RelevantFiles: files,
		IssueHash:     issueHash,
		FilesHash:     filesHash,
	}
	return HashArtifact("context", mustJSON(canonical))
}

func ComputePatchHash(unifiedDiffText string) string {
	return HashArtifact("patch", []byte(unifiedDiffText))
}

func ComputeRationaleHash(rationaleText string) string {
	return HashArtifact("rationale", []byte(rationaleText))
}

func ComputeDiffHash(diffText string) string {
	return HashArtifact("diff", []byte(diffText))
}

func ComputeTestLogHash(testOutput string) string {
	return HashArtifact("test-log", []byte(testOutput))
}

func RepositoryContextClaims(taskID, repo, issueID string, result ContextResult) map[string]interface{} {
	return map[string]interface{}{
		"task_id":        taskID,
		"repo":           repo,
		"issue_id":       issueID,
		"issue.read":     true,
		"repo.read":      true,
		"issue_hash":     result.IssueHash,
		"files_hash":     result.FilesHash,
		"context_hash":   result.ContextHash,
		"relevant_files": append([]string(nil), result.RelevantFile...),
	}
}

func ContextScopeClaims(taskID, repo, issueID string) map[string]interface{} {
	return map[string]interface{}{
		"task_id":    taskID,
		"repo":       repo,
		"issue_id":   issueID,
		"branch_id":  BranchContext,
		"issue.read": true,
		"repo.read":  true,
	}
}

func ContextResultClaims(taskID, repo, issueID string, result ContextResult) map[string]interface{} {
	return map[string]interface{}{
		"task_id":        taskID,
		"repo":           repo,
		"issue_id":       issueID,
		"branch_id":      BranchContext,
		"issue_hash":     result.IssueHash,
		"files_hash":     result.FilesHash,
		"context_hash":   result.ContextHash,
		"relevant_files": append([]string(nil), result.RelevantFile...),
	}
}

func PatchScopeClaims(taskID, repo, issueID, contextHash string) map[string]interface{} {
	return map[string]interface{}{
		"task_id":          taskID,
		"repo":             repo,
		"issue_id":         issueID,
		"branch_id":        BranchPatch,
		"patch.propose":    true,
		"analysis.execute": true,
		"context_hash":     contextHash,
	}
}

func PatchProposalClaims(taskID, repo, issueID, contextHash string, result PatchResult) map[string]interface{} {
	modelID := result.ModelID
	if modelID == "" {
		modelID = "deterministic-patch-agent"
	}
	return map[string]interface{}{
		"task_id":          taskID,
		"repo":             repo,
		"issue_id":         issueID,
		"patch.propose":    true,
		"analysis.execute": true,
		"context_hash":     contextHash,
		"patch_hash":       result.PatchHash,
		"rationale_hash":   result.RationaleHash,
		"model_id":         modelID,
		"risk_level":       result.RiskLevel,
	}
}

func PatchResultClaims(taskID, repo, issueID, contextHash string, result PatchResult) map[string]interface{} {
	modelID := result.ModelID
	if modelID == "" {
		modelID = "deterministic-patch-agent"
	}
	return map[string]interface{}{
		"task_id":        taskID,
		"repo":           repo,
		"issue_id":       issueID,
		"branch_id":      BranchPatch,
		"context_hash":   contextHash,
		"patch_hash":     result.PatchHash,
		"rationale_hash": result.RationaleHash,
		"model_id":       modelID,
		"risk_level":     result.RiskLevel,
	}
}

func RepositoryScopeClaims(taskID, repo, issueID, contextHash, patchHash string) map[string]interface{} {
	return map[string]interface{}{
		"task_id":          taskID,
		"repo":             repo,
		"issue_id":         issueID,
		"branch_id":        BranchRepository,
		"context_hash":     contextHash,
		"patch_hash":       patchHash,
		"allowed_paths":    "internal/api/projects.go,internal/api/projects_test.go",
		"branch_prefix":    BranchPrefix,
		"patch.apply":      true,
		"test.execute":     true,
		"artifact.release": true,
	}
}

func PatchApplicationClaims(taskID, repo, issueID string, result ApplyResult) map[string]interface{} {
	modifiedPaths := result.ModifiedPath
	if len(modifiedPaths) == 0 {
		modifiedPaths = result.FilesChanged
	}
	return map[string]interface{}{
		"task_id":        taskID,
		"repo":           repo,
		"issue_id":       issueID,
		"patch.apply":    true,
		"patch_hash":     result.PatchHash,
		"diff_hash":      result.DiffHash,
		"applied":        result.Applied,
		"modified_paths": append([]string(nil), modifiedPaths...),
		"files_changed":  append([]string(nil), result.FilesChanged...),
	}
}

func TestExecutionClaims(taskID, repo, issueID string, result TestResult) map[string]interface{} {
	testResult := result.TestResult
	if testResult == "" {
		if result.Passed {
			testResult = "passed"
		} else {
			testResult = "failed"
		}
	}
	return map[string]interface{}{
		"task_id":       taskID,
		"repo":          repo,
		"issue_id":      issueID,
		"test.execute":  true,
		"diff_hash":     result.DiffHash,
		"test_log_hash": result.TestLogHash,
		"passed":        result.Passed,
		"test_result":   testResult,
		"command":       result.Command,
	}
}

func FinalArtifactClaims(taskID, repo, issueID string, result FinalArtifactResult) map[string]interface{} {
	return map[string]interface{}{
		"task_id":          taskID,
		"repo":             repo,
		"issue_id":         issueID,
		"artifact.release": true,
		"context_hash":     result.ContextHash,
		"patch_hash":       result.PatchHash,
		"diff_hash":        result.DiffHash,
		"test_log_hash":    result.TestLogHash,
		"artifact_hash":    result.ArtifactHash,
		"branch":           result.Branch,
		"test_result":      result.TestResult,
		"status":           result.Status,
	}
}

type fileHashEntry struct {
	Path        string `json:"path"`
	ContentHash string `json:"content_hash"`
	Size        int    `json:"size"`
}

type contextHashInput struct {
	IssueID       string   `json:"issue_id"`
	RelevantFiles []string `json:"relevant_files"`
	IssueHash     string   `json:"issue_hash"`
	FilesHash     string   `json:"files_hash"`
}

func mustJSON(v interface{}) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}
