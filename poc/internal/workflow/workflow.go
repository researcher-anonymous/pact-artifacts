package workflow

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	pathpkg "path"
	"strings"
	"time"

	"flow-poc/internal/pocconfig"
	pact "flow-poc/pact"
	sd "flow-poc/sd"
)

const (
	TaskID             = "task-issue-184-empty-project-id"
	Repo               = "example/api-service"
	IssueID            = "184"
	BranchPrefix       = "fix/issue-184"
	ContextPlaceholder = "pending-context-hash"
	ContextHash        = "ctx:issue-184-empty-project-id:v1"
	PatchHash          = "patch:guard-empty-project-id:v1"
	RationaleHash      = "rationale:empty-project-id-validation:v1"
	ReviewResultHash   = "review:approved-safe-empty-project-id:v1"
)

var RootPermissions = []string{
	"issue.read",
	"repo.read",
	"patch.propose",
	"analysis.execute",
	"patch.apply",
	"test.execute",
	"artifact.release",
	"pr.create",
}

var PermissionVocabulary = map[string]struct{}{
	"issue.read":       {},
	"repo.read":        {},
	"patch.propose":    {},
	"analysis.execute": {},
	"patch.apply":      {},
	"test.execute":     {},
	"artifact.release": {},
	"pr.create":        {},
}

type ContextResult struct {
	IssueID      string   `json:"issue_id"`
	Title        string   `json:"title"`
	RelevantFile []string `json:"relevant_files"`
	ContextHash  string   `json:"context_hash"`
	IssueHash    string   `json:"issue_hash,omitempty"`
	FilesHash    string   `json:"files_hash,omitempty"`
}

type PatchResult struct {
	ContextHash   string `json:"context_hash,omitempty"`
	PatchHash     string `json:"patch_hash"`
	RationaleHash string `json:"rationale_hash"`
	ModelID       string `json:"model_id,omitempty"`
	RiskLevel     string `json:"risk_level"`
}

type ReviewResult struct {
	ReviewResultHash string `json:"review_result_hash"`
	Decision         string `json:"decision"`
}

func RootClaims(perms []string) map[string]interface{} {
	if len(perms) == 0 {
		perms = RootPermissions
	}
	claims := map[string]interface{}{
		"task_id":              TaskID,
		"repo":                 Repo,
		"issue_id":             IssueID,
		"branch_prefix":        BranchPrefix,
		"allowed_paths":        "internal/api/projects.go,internal/api/projects_test.go",
		"context_hash":         ContextPlaceholder,
		"context_hash_pending": true,
	}
	for _, p := range perms {
		claims[p] = true
	}
	return claims
}

func ContextClaims() map[string]interface{} {
	return map[string]interface{}{
		"task_id":      TaskID,
		"repo":         Repo,
		"issue_id":     IssueID,
		"issue.read":   true,
		"repo.read":    true,
		"context_hash": ContextHash,
	}
}

func PatchClaims(contextHash string) map[string]interface{} {
	return map[string]interface{}{
		"task_id":          TaskID,
		"repo":             Repo,
		"issue_id":         IssueID,
		"patch.propose":    true,
		"analysis.execute": true,
		"context_hash":     contextHash,
		"patch_hash":       PatchHash,
		"rationale_hash":   RationaleHash,
		"risk_level":       "low",
	}
}

func ReviewClaims(patchHash string, approved bool) map[string]interface{} {
	decision := "approved"
	if !approved {
		decision = "rejected"
	}
	return map[string]interface{}{
		"task_id":            TaskID,
		"repo":               Repo,
		"issue_id":           IssueID,
		"context_hash":       ContextHash,
		"patch_hash":         patchHash,
		"review_result_hash": ReviewResultHash,
		"decision":           decision,
	}
}

func PRClaims(patchHash, reviewResultHash string) map[string]interface{} {
	return map[string]interface{}{
		"task_id":            TaskID,
		"repo":               Repo,
		"issue_id":           IssueID,
		"branch_prefix":      BranchPrefix,
		"branch":             BranchPrefix + "-empty-project-id",
		"pr.create":          true,
		"context_hash":       ContextHash,
		"patch_hash":         patchHash,
		"review_result_hash": reviewResultHash,
	}
}

func Indexes(keys []string, selected ...string) ([]int, error) {
	indexByKey := map[string]int{}
	for i, key := range keys {
		indexByKey[key] = i
	}
	out := make([]int, 0, len(selected))
	for _, key := range selected {
		idx, ok := indexByKey[key]
		if !ok {
			return nil, fmt.Errorf("claim %q not found", key)
		}
		out = append(out, idx)
	}
	return out, nil
}

func ClaimsFromOpenings(openings []sd.FieldOpening) (map[string]interface{}, error) {
	claims := map[string]interface{}{}
	for _, opening := range openings {
		var v interface{}
		if err := json.Unmarshal(opening.Value, &v); err != nil {
			return nil, err
		}
		claims[opening.Tag] = v
	}
	return claims, nil
}

func ClaimsFromDisclosure(d *sd.Disclosure) (map[string]interface{}, error) {
	if d == nil {
		return nil, fmt.Errorf("nil disclosure")
	}
	ok, err := sd.VerifyDisclosure(d)
	if err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("disclosure verification failed")
		}
		return nil, err
	}
	return ClaimsFromOpenings(d.Openings)
}

func BoolClaim(claims map[string]interface{}, key string) bool {
	v, ok := claims[key]
	b, _ := v.(bool)
	return ok && b
}

func StringClaim(claims map[string]interface{}, key string) string {
	v, ok := claims[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func ValidateWithRevocation(token string, evidence *pact.Evidence, presentations map[int]*sd.Disclosure, relation pact.VerifierRelation, rc *pact.RevocationCheckpoint, now time.Time) error {
	_, err := pact.ValidatePACT(token, pact.ModeSchoCo, pact.ValidationOptions{
		Evidence:             evidence,
		Presentations:        presentations,
		VerifierRelation:     relation,
		TrustedIssuerPK:      pocconfig.RevocationIssuerPublicKey(),
		RequireRevocation:    true,
		Tau:                  time.Minute,
		ClockSkew:            5 * time.Second,
		Now:                  now,
		RevocationCheckpoint: rc,
	})
	return err
}

type CodeMaintenanceRelation struct{}

type BranchPresentation struct {
	Token    string         `json:"token"`
	Evidence *pact.Evidence `json:"evidence"`
}

type CodeMaintenanceBranchPresentation struct {
	Context    BranchPresentation `json:"context"`
	Patch      BranchPresentation `json:"patch"`
	Repository BranchPresentation `json:"repository"`
}

func ValidateBranchedCodeMaintenance(presentation CodeMaintenanceBranchPresentation, rc *pact.RevocationCheckpoint, now time.Time) error {
	contextPayload, contextNodes, err := validateBranchPresentation("context", presentation.Context, rc, now, 2)
	if err != nil {
		return err
	}
	patchPayload, patchNodes, err := validateBranchPresentation("patch", presentation.Patch, rc, now, 2)
	if err != nil {
		return err
	}
	repoPayload, repoNodes, err := validateBranchPresentation("repository", presentation.Repository, rc, now, 4)
	if err != nil {
		return err
	}

	if contextPayload.TID0 == "" {
		return fmt.Errorf("context branch missing tid_0")
	}
	if patchPayload.TID0 != contextPayload.TID0 || repoPayload.TID0 != contextPayload.TID0 {
		return fmt.Errorf("branches do not share tid_0")
	}

	root := contextNodes[0]
	for label, nodes := range map[string]map[int]map[string]interface{}{
		"patch":      patchNodes,
		"repository": repoNodes,
	} {
		if err := validateSameRootClaims(root, nodes[0], label); err != nil {
			return err
		}
	}

	if err := validateBranchCommonBindings(contextNodes, 2, root, "context"); err != nil {
		return err
	}
	if err := validateBranchCommonBindings(patchNodes, 2, root, "patch"); err != nil {
		return err
	}
	if err := validateBranchCommonBindings(repoNodes, 4, root, "repository"); err != nil {
		return err
	}
	if err := validatePermissions(contextNodes, 2, contextBranchAllowedNodePermissions); err != nil {
		return err
	}
	if err := validatePermissions(patchNodes, 2, patchBranchAllowedNodePermissions); err != nil {
		return err
	}
	if err := validatePermissions(repoNodes, 4, repositoryBranchAllowedNodePermissions); err != nil {
		return err
	}

	if StringClaim(contextNodes[1], "branch_id") != BranchContext {
		return fmt.Errorf("context scope missing branch_id")
	}
	if !BoolClaim(contextNodes[1], "issue.read") || !BoolClaim(contextNodes[1], "repo.read") {
		return fmt.Errorf("context scope lacks issue.read/repo.read")
	}
	if StringClaim(contextNodes[2], "branch_id") != BranchContext {
		return fmt.Errorf("context result missing branch_id")
	}
	if _, err := requiredString(contextNodes[2], "issue_hash", "context result"); err != nil {
		return err
	}
	if _, err := requiredString(contextNodes[2], "files_hash", "context result"); err != nil {
		return err
	}
	contextHash, err := requiredString(contextNodes[2], "context_hash", "context result")
	if err != nil {
		return err
	}

	if StringClaim(patchNodes[1], "branch_id") != BranchPatch {
		return fmt.Errorf("patch scope missing branch_id")
	}
	if !BoolClaim(patchNodes[1], "patch.propose") || !BoolClaim(patchNodes[1], "analysis.execute") {
		return fmt.Errorf("patch scope lacks patch.propose/analysis.execute")
	}
	if StringClaim(patchNodes[1], "context_hash") != contextHash {
		return fmt.Errorf("patch scope not bound to context_hash")
	}
	if StringClaim(patchNodes[2], "branch_id") != BranchPatch {
		return fmt.Errorf("patch result missing branch_id")
	}
	if StringClaim(patchNodes[2], "context_hash") != contextHash {
		return fmt.Errorf("patch result not bound to context_hash")
	}
	patchHash, err := requiredString(patchNodes[2], "patch_hash", "patch result")
	if err != nil {
		return err
	}
	if _, err := requiredString(patchNodes[2], "rationale_hash", "patch result"); err != nil {
		return err
	}
	if _, err := requiredString(patchNodes[2], "model_id", "patch result"); err != nil {
		return err
	}

	if StringClaim(repoNodes[1], "branch_id") != BranchRepository {
		return fmt.Errorf("repository scope missing branch_id")
	}
	if StringClaim(repoNodes[1], "context_hash") != contextHash {
		return fmt.Errorf("repository scope not bound to context_hash")
	}
	if StringClaim(repoNodes[1], "patch_hash") != patchHash {
		return fmt.Errorf("repository scope not bound to patch_hash")
	}
	allowedPaths := stringSliceClaim(repoNodes[1], "allowed_paths")
	if len(allowedPaths) == 0 {
		allowedPaths = stringSliceClaim(root, "allowed_paths")
	}
	if len(allowedPaths) == 0 {
		return fmt.Errorf("repository scope missing allowed_paths")
	}
	branchPrefix := StringClaim(repoNodes[1], "branch_prefix")
	if branchPrefix == "" {
		branchPrefix, err = requiredString(root, "branch_prefix", "root")
		if err != nil {
			return err
		}
	}

	if !BoolClaim(repoNodes[2], "patch.apply") {
		return fmt.Errorf("application node lacks patch.apply")
	}
	if StringClaim(repoNodes[2], "patch_hash") != patchHash {
		return fmt.Errorf("application node not bound to patch_hash")
	}
	diffHash, err := requiredString(repoNodes[2], "diff_hash", "application node")
	if err != nil {
		return err
	}
	modifiedPaths := stringSliceClaim(repoNodes[2], "modified_paths")
	if len(modifiedPaths) == 0 {
		modifiedPaths = stringSliceClaim(repoNodes[2], "files_changed")
	}
	if len(modifiedPaths) == 0 {
		return fmt.Errorf("application node missing modified_paths")
	}
	for _, modified := range modifiedPaths {
		if !pathAllowed(modified, allowedPaths) {
			return fmt.Errorf("modified path %s outside allowed_paths", modified)
		}
	}

	if !BoolClaim(repoNodes[3], "test.execute") {
		return fmt.Errorf("test node lacks test.execute")
	}
	if StringClaim(repoNodes[3], "diff_hash") != diffHash {
		return fmt.Errorf("test node not bound to diff_hash")
	}
	testLogHash, err := requiredString(repoNodes[3], "test_log_hash", "test node")
	if err != nil {
		return err
	}
	if testResult(repoNodes[3]) != "passed" {
		return fmt.Errorf("test_result is not passed")
	}

	if !BoolClaim(repoNodes[4], "artifact.release") {
		return fmt.Errorf("final artifact node lacks artifact.release")
	}
	if StringClaim(repoNodes[4], "diff_hash") != diffHash {
		return fmt.Errorf("final artifact not bound to diff_hash")
	}
	if StringClaim(repoNodes[4], "test_log_hash") != testLogHash {
		return fmt.Errorf("final artifact not bound to test_log_hash")
	}
	finalBranch, err := requiredString(repoNodes[4], "branch", "final artifact node")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(finalBranch, branchPrefix) {
		return fmt.Errorf("final branch does not match branch_prefix")
	}
	if testResult(repoNodes[4]) != "passed" {
		return fmt.Errorf("final release requires test_result=passed")
	}
	return nil
}

func (CodeMaintenanceRelation) EvaluatedNodes(p *pact.Payload) []int {
	if p != nil && len(p.List) >= 5 {
		return []int{0, 1, 2, 3, 4, 5}
	}
	return []int{0, 1, 2, 3, 4}
}

func (r CodeMaintenanceRelation) Evaluate(p *pact.Payload, e *pact.Evidence) error {
	if e == nil {
		return fmt.Errorf("missing full-chain evidence")
	}
	if p != nil && len(p.List) >= 5 {
		return r.evaluateLocalSixNode(e)
	}
	return r.evaluateLegacyFiveNode(e)
}

func (CodeMaintenanceRelation) evaluateLocalSixNode(e *pact.Evidence) error {
	nodes, err := claimsForNodes(e, 5)
	if err != nil {
		return err
	}
	root := nodes[0]
	if err := validateCommonBindings(nodes, 5); err != nil {
		return err
	}
	branchPrefix, err := requiredString(root, "branch_prefix", "root")
	if err != nil {
		return err
	}
	if err := validatePermissions(nodes, 5, localAllowedNodePermissions); err != nil {
		return err
	}

	if !BoolClaim(nodes[1], "issue.read") || !BoolClaim(nodes[1], "repo.read") {
		return fmt.Errorf("context node lacks issue.read/repo.read")
	}
	if _, err := requiredString(nodes[1], "issue_hash", "context node"); err != nil {
		return err
	}
	if _, err := requiredString(nodes[1], "files_hash", "context node"); err != nil {
		return err
	}
	contextHash, err := requiredString(nodes[1], "context_hash", "context node")
	if err != nil {
		return err
	}

	if !BoolClaim(nodes[2], "patch.propose") || !BoolClaim(nodes[2], "analysis.execute") {
		return fmt.Errorf("patch node lacks patch.propose/analysis.execute")
	}
	if StringClaim(nodes[2], "context_hash") != contextHash {
		return fmt.Errorf("patch_hash not bound to context_hash")
	}
	patchHash, err := requiredString(nodes[2], "patch_hash", "patch node")
	if err != nil {
		return err
	}
	if _, err := requiredString(nodes[2], "rationale_hash", "patch node"); err != nil {
		return err
	}
	if _, err := requiredString(nodes[2], "model_id", "patch node"); err != nil {
		return err
	}

	if !BoolClaim(nodes[3], "patch.apply") {
		return fmt.Errorf("application node lacks patch.apply")
	}
	if StringClaim(nodes[3], "patch_hash") != patchHash {
		return fmt.Errorf("application node not bound to patch_hash")
	}
	diffHash, err := requiredString(nodes[3], "diff_hash", "application node")
	if err != nil {
		return err
	}
	modifiedPaths := stringSliceClaim(nodes[3], "modified_paths")
	if len(modifiedPaths) == 0 {
		modifiedPaths = stringSliceClaim(nodes[3], "files_changed")
	}
	if len(modifiedPaths) == 0 {
		return fmt.Errorf("application node missing modified_paths")
	}
	allowedPaths := stringSliceClaim(root, "allowed_paths")
	if len(allowedPaths) == 0 {
		return fmt.Errorf("root missing allowed_paths")
	}
	for _, modified := range modifiedPaths {
		if !pathAllowed(modified, allowedPaths) {
			return fmt.Errorf("modified path %s outside allowed_paths", modified)
		}
	}

	if !BoolClaim(nodes[4], "test.execute") {
		return fmt.Errorf("test node lacks test.execute")
	}
	if StringClaim(nodes[4], "diff_hash") != diffHash {
		return fmt.Errorf("test node not bound to diff_hash")
	}
	testLogHash, err := requiredString(nodes[4], "test_log_hash", "test node")
	if err != nil {
		return err
	}
	if testResult(nodes[4]) != "passed" {
		return fmt.Errorf("test_result is not passed")
	}

	if !BoolClaim(nodes[5], "artifact.release") {
		return fmt.Errorf("final artifact node lacks artifact.release")
	}
	if StringClaim(nodes[5], "diff_hash") != diffHash {
		return fmt.Errorf("final artifact not bound to diff_hash")
	}
	if StringClaim(nodes[5], "test_log_hash") != testLogHash {
		return fmt.Errorf("final artifact not bound to test_log_hash")
	}
	finalBranch, err := requiredString(nodes[5], "branch", "final artifact node")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(finalBranch, branchPrefix) {
		return fmt.Errorf("final branch does not match branch_prefix")
	}
	if testResult(nodes[5]) != "passed" {
		return fmt.Errorf("final release requires test_result=passed")
	}
	return nil
}

func (CodeMaintenanceRelation) evaluateLegacyFiveNode(e *pact.Evidence) error {
	nodes, err := claimsForNodes(e, 4)
	if err != nil {
		return err
	}
	root := nodes[0]
	if err := validateCommonBindings(nodes, 4); err != nil {
		return err
	}
	branchPrefix, err := requiredString(root, "branch_prefix", "root")
	if err != nil {
		return err
	}
	if err := validatePermissions(nodes, 4, legacyAllowedNodePermissions); err != nil {
		return err
	}

	if !BoolClaim(nodes[1], "issue.read") || !BoolClaim(nodes[1], "repo.read") {
		return fmt.Errorf("context node lacks issue.read/repo.read")
	}
	contextHash, err := requiredString(nodes[1], "context_hash", "context node")
	if err != nil {
		return err
	}
	if !BoolClaim(nodes[2], "patch.propose") || !BoolClaim(nodes[2], "analysis.execute") {
		return fmt.Errorf("patch node lacks patch.propose/analysis.execute")
	}
	patchHash, err := requiredString(nodes[2], "patch_hash", "patch node")
	if err != nil {
		return err
	}
	if StringClaim(nodes[2], "context_hash") != contextHash {
		return fmt.Errorf("patch_hash not bound to context_hash")
	}
	reviewHash := StringClaim(nodes[3], "review_result_hash")
	if reviewHash == "" {
		return fmt.Errorf("review node missing review_result_hash")
	}
	if StringClaim(nodes[3], "patch_hash") != patchHash {
		return fmt.Errorf("review node not bound to patch_hash")
	}
	if StringClaim(nodes[3], "decision") != "approved" {
		return fmt.Errorf("review decision is not approved")
	}
	if !BoolClaim(nodes[4], "pr.create") {
		return fmt.Errorf("final node lacks pr.create")
	}
	finalBranch := StringClaim(nodes[4], "branch")
	if finalBranch == "" {
		return fmt.Errorf("final node missing branch")
	}
	if !strings.HasPrefix(finalBranch, branchPrefix) {
		return fmt.Errorf("final branch does not match branch_prefix")
	}
	if StringClaim(nodes[4], "patch_hash") != patchHash {
		return fmt.Errorf("PR node not bound to patch_hash")
	}
	if StringClaim(nodes[4], "review_result_hash") != reviewHash {
		return fmt.Errorf("pr.create requires review_result_hash")
	}
	return nil
}

func claimsForNodes(e *pact.Evidence, lastNode int) (map[int]map[string]interface{}, error) {
	nodes := map[int]map[string]interface{}{}
	for i := 0; i <= lastNode; i++ {
		openings, ok := e.NodeOpenings[i]
		if !ok || len(openings) == 0 {
			return nil, fmt.Errorf("missing evidence for node %d", i)
		}
		claims, err := ClaimsFromOpenings(openings)
		if err != nil {
			return nil, err
		}
		nodes[i] = claims
	}
	return nodes, nil
}

func validateCommonBindings(nodes map[int]map[string]interface{}, lastNode int) error {
	root := nodes[0]
	for _, key := range []string{"task_id", "repo", "issue_id"} {
		if StringClaim(root, key) == "" {
			return fmt.Errorf("root missing %s", key)
		}
		for i := 1; i <= lastNode; i++ {
			got := StringClaim(nodes[i], key)
			if got == "" {
				return fmt.Errorf("node %d missing %s", i, key)
			}
			if got != StringClaim(root, key) {
				return fmt.Errorf("%s mismatch at node %d", key, i)
			}
		}
	}
	return nil
}

func validatePermissions(nodes map[int]map[string]interface{}, lastNode int, allowedForNode func(int) map[string]bool) error {
	rootPerms, err := enabledPermissions(nodes[0])
	if err != nil {
		return err
	}
	for i := 1; i <= lastNode; i++ {
		perms, err := enabledPermissions(nodes[i])
		if err != nil {
			return fmt.Errorf("node %d: %v", i, err)
		}
		allowed := allowedForNode(i)
		for perm := range perms {
			if !rootPerms[perm] {
				return fmt.Errorf("permission %s increases at node %d", perm, i)
			}
			if !allowed[perm] {
				return fmt.Errorf("permission %s is not allowed at node %d", perm, i)
			}
		}
	}
	return nil
}

func enabledPermissions(claims map[string]interface{}) (map[string]bool, error) {
	out := map[string]bool{}
	for key, value := range claims {
		enabled, ok := value.(bool)
		if !ok || !enabled {
			continue
		}
		if _, ok := PermissionVocabulary[key]; !ok {
			if strings.Contains(key, ".") {
				return nil, fmt.Errorf("unexpected enabled permission %s", key)
			}
			continue
		}
		out[key] = true
	}
	return out, nil
}

func legacyAllowedNodePermissions(nodeIndex int) map[string]bool {
	switch nodeIndex {
	case 1:
		return map[string]bool{"issue.read": true, "repo.read": true}
	case 2:
		return map[string]bool{"patch.propose": true, "analysis.execute": true}
	case 3:
		return map[string]bool{}
	case 4:
		return map[string]bool{"pr.create": true}
	default:
		return map[string]bool{}
	}
}

func localAllowedNodePermissions(nodeIndex int) map[string]bool {
	switch nodeIndex {
	case 1:
		return map[string]bool{"issue.read": true, "repo.read": true}
	case 2:
		return map[string]bool{"patch.propose": true, "analysis.execute": true}
	case 3:
		return map[string]bool{"patch.apply": true}
	case 4:
		return map[string]bool{"test.execute": true}
	case 5:
		return map[string]bool{"artifact.release": true}
	default:
		return map[string]bool{}
	}
}

func contextBranchAllowedNodePermissions(nodeIndex int) map[string]bool {
	switch nodeIndex {
	case 1:
		return map[string]bool{"issue.read": true, "repo.read": true}
	default:
		return map[string]bool{}
	}
}

func patchBranchAllowedNodePermissions(nodeIndex int) map[string]bool {
	switch nodeIndex {
	case 1:
		return map[string]bool{"patch.propose": true, "analysis.execute": true}
	default:
		return map[string]bool{}
	}
}

func repositoryBranchAllowedNodePermissions(nodeIndex int) map[string]bool {
	switch nodeIndex {
	case 1:
		return map[string]bool{"patch.apply": true, "test.execute": true, "artifact.release": true}
	case 2:
		return map[string]bool{"patch.apply": true}
	case 3:
		return map[string]bool{"test.execute": true}
	case 4:
		return map[string]bool{"artifact.release": true}
	default:
		return map[string]bool{}
	}
}

func validateBranchPresentation(label string, branch BranchPresentation, rc *pact.RevocationCheckpoint, now time.Time, lastNode int) (*pact.Payload, map[int]map[string]interface{}, error) {
	if branch.Token == "" {
		return nil, nil, fmt.Errorf("%s branch missing token", label)
	}
	if branch.Evidence == nil {
		return nil, nil, fmt.Errorf("%s branch missing evidence", label)
	}
	if err := ValidateWithRevocation(branch.Token, branch.Evidence, nil, nil, rc, now); err != nil {
		return nil, nil, fmt.Errorf("%s branch validation failed: %w", label, err)
	}
	payload, err := payloadFromToken(branch.Token)
	if err != nil {
		return nil, nil, fmt.Errorf("%s branch payload decode failed: %w", label, err)
	}
	if len(payload.List) != lastNode {
		return nil, nil, fmt.Errorf("%s branch has %d extension nodes, want %d", label, len(payload.List), lastNode)
	}
	nodes, err := claimsForNodes(branch.Evidence, lastNode)
	if err != nil {
		return nil, nil, fmt.Errorf("%s branch: %w", label, err)
	}
	return payload, nodes, nil
}

func validateSameRootClaims(want, got map[string]interface{}, label string) error {
	for _, key := range []string{"task_id", "repo", "issue_id", "branch_prefix"} {
		if StringClaim(got, key) != StringClaim(want, key) {
			return fmt.Errorf("%s branch root %s mismatch", label, key)
		}
	}
	wantAllowed := strings.Join(stringSliceClaim(want, "allowed_paths"), "\x00")
	gotAllowed := strings.Join(stringSliceClaim(got, "allowed_paths"), "\x00")
	if wantAllowed != gotAllowed {
		return fmt.Errorf("%s branch root allowed_paths mismatch", label)
	}
	return nil
}

func validateBranchCommonBindings(nodes map[int]map[string]interface{}, lastNode int, root map[string]interface{}, label string) error {
	for _, key := range []string{"task_id", "repo", "issue_id"} {
		if StringClaim(root, key) == "" {
			return fmt.Errorf("root missing %s", key)
		}
		for i := 1; i <= lastNode; i++ {
			got := StringClaim(nodes[i], key)
			if got == "" {
				return fmt.Errorf("%s branch node %d missing %s", label, i, key)
			}
			if got != StringClaim(root, key) {
				return fmt.Errorf("%s mismatch at %s branch node %d", key, label, i)
			}
		}
	}
	return nil
}

func payloadFromToken(token string) (*pact.Payload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid jws format")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var payload pact.Payload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func requiredString(claims map[string]interface{}, key, label string) (string, error) {
	value := StringClaim(claims, key)
	if value == "" {
		return "", fmt.Errorf("%s missing %s", label, key)
	}
	return value, nil
}

func stringSliceClaim(claims map[string]interface{}, key string) []string {
	value, ok := claims[key]
	if !ok {
		return nil
	}
	switch v := value.(type) {
	case []string:
		return append([]string(nil), v...)
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil
			}
			out = append(out, s)
		}
		return out
	case string:
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				out = append(out, trimmed)
			}
		}
		return out
	default:
		return nil
	}
}

func pathAllowed(modified string, allowedPaths []string) bool {
	cleanModified := cleanRelativePath(modified)
	if cleanModified == "" {
		return false
	}
	for _, allowed := range allowedPaths {
		cleanAllowed := cleanRelativePath(allowed)
		if cleanAllowed == "" {
			continue
		}
		if cleanModified == cleanAllowed || strings.HasPrefix(cleanModified, cleanAllowed+"/") {
			return true
		}
	}
	return false
}

func cleanRelativePath(p string) string {
	if p == "" || strings.HasPrefix(p, "/") {
		return ""
	}
	cleaned := pathpkg.Clean(p)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return ""
	}
	return cleaned
}

func testResult(claims map[string]interface{}) string {
	result := StringClaim(claims, "test_result")
	if result != "" {
		return result
	}
	if BoolClaim(claims, "passed") {
		return "passed"
	}
	return "failed"
}
