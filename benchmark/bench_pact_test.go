package pact_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"anonymous-artifact/schoco"
	pact "flow-poc/pact"
	sd "flow-poc/sd"
	"github.com/golang-jwt/jwt/v5"
)

const (
	workflowSteps      = 6
	taskID             = "task-issue-184-empty-project-id"
	repo               = "example/api-service"
	issueID            = "184"
	branchPrefix       = "fix/issue-184"
	contextPlaceholder = "pending-context-hash"
	contextHash        = "ctx:issue-184-empty-project-id:v1"
	issueHash          = "issue:184-empty-project-id:v1"
	filesHash          = "files:projects-api-fixture:v1"
	patchHash          = "patch:guard-empty-project-id:v1"
	rationaleHash      = "rationale:empty-project-id-validation:v1"
	modelID            = "deterministic-patch-agent"
	diffHash           = "diff:guard-empty-project-id-applied:v1"
	testLogHash        = "test-log:fixture-go-test-passed:v1"
	artifactHash       = "artifact:local-bugfix-release:v1"
)

var (
	benchNow           = time.Unix(1000, 0)
	chainLengths       = []int{0, 1, 2, 4, 8, 16}
	crossoverDepths    = []int{1, 2, 5, 10, 20, 50, 100}
	fieldsPerNodeVals  = []int{4, 8, 16}
	disclosureOpenings = []int{1, 2, 4, 8}
	benchSink          any
)

type jwsFixture struct {
	issuer *ecdsa.PrivateKey
	tokens []string
}

type pactFixture struct {
	mode       int8
	tid        string
	token      string
	evidence   *pact.Evidence
	disclosure map[int]*sd.Disclosure
	issuerPK   []byte
	resolver   pact.IDKeyResolver
	rc         *pact.RevocationCheckpoint
	nextIDKey  *ecdsa.PrivateKey
}

type pactPresentationSizes struct {
	TokenBytes                   int
	FullEvidenceBytes            int
	SelectiveDisclosureBytes     int
	TokenPlusEvidenceBytes       int
	TokenPlusDisclosureBytes     int
	TransparentPayloadTokenBytes int
	RevocationCheckpointBytes    int
}

type pactScenario struct {
	name                string
	tid                 string
	claims              []map[string]interface{}
	relation            pact.VerifierRelation
	transparentRelation pact.VerifierRelation
	disclosureSelector  func(nodeIndex int, keys []string, disclosureRatio float64) []int
}

type codeMaintenanceBranchFixture struct {
	mode       int8
	tid        string
	context    pactFixture
	patch      pactFixture
	repository pactFixture
	rc         *pact.RevocationCheckpoint
}

type jwsCodeMaintenanceBranchFixture struct {
	issuer     *ecdsa.PrivateKey
	context    []string
	patch      []string
	repository []string
}

type jwsCodeMaintenanceStaticFixture struct {
	issuer *ecdsa.PrivateKey
	token  string
}

const (
	codeMaintenanceBranchCount         = 3
	codeMaintenanceContextBranchNodes  = 3
	codeMaintenancePatchBranchNodes    = 3
	codeMaintenanceRepositoryNodes     = 5
	codeMaintenanceAuthenticatedNodes  = 11
	codeMaintenanceUniqueLogicalNodes  = 9
	codeMaintenancePACTIssuerRoots     = 3
	codeMaintenanceJWSReissuedTokens   = 11
	codeMaintenanceJWSStaticTokenCount = 1
	codeMaintenanceNodesPerBranch      = "context=3;patch=3;repository=5"
)

type codeMaintenanceRelation struct{}

func (codeMaintenanceRelation) EvaluatedNodes(*pact.Payload) []int {
	return []int{0, 1, 2, 3, 4, 5}
}

func (codeMaintenanceRelation) Evaluate(_ *pact.Payload, e *pact.Evidence) error {
	if e == nil {
		return fmt.Errorf("missing full-chain evidence")
	}
	nodes, err := claimsFromEvidenceRange(e, 5)
	if err != nil {
		return err
	}
	return evaluateCodeMaintenanceNodes(nodes)
}

type transparentCodeMaintenanceRelation struct{}

func (transparentCodeMaintenanceRelation) EvaluatedNodes(*pact.Payload) []int {
	return []int{0, 1, 2, 3, 4, 5}
}

func (transparentCodeMaintenanceRelation) Evaluate(doc *pact.Payload, _ *pact.Evidence) error {
	nodes, err := claimsFromTransparentPayloadRange(doc, 5)
	if err != nil {
		return err
	}
	return evaluateCodeMaintenanceNodes(nodes)
}

func evaluateCodeMaintenanceNodes(nodes map[int]map[string]interface{}) error {
	root := nodes[0]
	for _, key := range []string{"task_id", "repo", "issue_id"} {
		rootValue, _ := root[key].(string)
		if rootValue == "" {
			return fmt.Errorf("root missing %s", key)
		}
		for i := 1; i <= 5; i++ {
			got, _ := nodes[i][key].(string)
			if got == "" || got != rootValue {
				return fmt.Errorf("%s mismatch at node %d", key, i)
			}
		}
	}
	rootPerms, err := enabledPermissions(root)
	if err != nil {
		return err
	}
	for i := 1; i <= 5; i++ {
		perms, err := enabledPermissions(nodes[i])
		if err != nil {
			return err
		}
		allowed := allowedNodePermissions(i)
		for perm := range perms {
			if !rootPerms[perm] || !allowed[perm] {
				return fmt.Errorf("permission %s not allowed at node %d", perm, i)
			}
		}
	}
	if !boolClaim(nodes[1], "issue.read") || !boolClaim(nodes[1], "repo.read") {
		return fmt.Errorf("context node lacks issue.read/repo.read")
	}
	ch := stringClaim(nodes[1], "context_hash")
	if ch == "" || stringClaim(nodes[1], "issue_hash") == "" || stringClaim(nodes[1], "files_hash") == "" {
		return fmt.Errorf("context node missing repository context evidence")
	}
	if !boolClaim(nodes[2], "patch.propose") || !boolClaim(nodes[2], "analysis.execute") {
		return fmt.Errorf("patch node lacks patch.propose/analysis.execute")
	}
	ph := stringClaim(nodes[2], "patch_hash")
	if ph == "" || stringClaim(nodes[2], "context_hash") != ch || stringClaim(nodes[2], "rationale_hash") == "" || stringClaim(nodes[2], "model_id") == "" {
		return fmt.Errorf("patch not bound to context")
	}
	if !boolClaim(nodes[3], "patch.apply") || stringClaim(nodes[3], "patch_hash") != ph {
		return fmt.Errorf("application not bound to patch")
	}
	dh := stringClaim(nodes[3], "diff_hash")
	modifiedPaths := stringSliceClaim(nodes[3], "modified_paths")
	if dh == "" || len(modifiedPaths) == 0 {
		return fmt.Errorf("application missing diff_hash/modified_paths")
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
	if !boolClaim(nodes[4], "test.execute") || stringClaim(nodes[4], "diff_hash") != dh {
		return fmt.Errorf("tests not bound to diff")
	}
	tlh := stringClaim(nodes[4], "test_log_hash")
	if stringClaim(nodes[4], "test_result") != "passed" || tlh == "" {
		return fmt.Errorf("tests did not pass")
	}
	if !boolClaim(nodes[5], "artifact.release") {
		return fmt.Errorf("final node lacks artifact.release")
	}
	if stringClaim(nodes[5], "diff_hash") != dh || stringClaim(nodes[5], "test_log_hash") != tlh {
		return fmt.Errorf("final artifact not bound to test evidence")
	}
	if stringClaim(nodes[5], "test_result") != "passed" || stringClaim(nodes[5], "artifact_hash") == "" {
		return fmt.Errorf("final artifact release requires passed tests")
	}
	bp := stringClaim(root, "branch_prefix")
	if bp == "" || stringClaim(nodes[5], "branch") == "" || !strings.HasPrefix(stringClaim(nodes[5], "branch"), bp) {
		return fmt.Errorf("branch prefix mismatch")
	}
	return nil
}

type dataProcessingRelation struct{}

func (dataProcessingRelation) EvaluatedNodes(*pact.Payload) []int {
	return []int{0, 1, 2, 3, 4}
}

func (dataProcessingRelation) Evaluate(_ *pact.Payload, e *pact.Evidence) error {
	if e == nil {
		return fmt.Errorf("missing full-chain evidence")
	}
	nodes, err := claimsFromEvidenceRange(e, 4)
	if err != nil {
		return err
	}
	return evaluateDataProcessingNodes(nodes)
}

type transparentDataProcessingRelation struct{}

func (transparentDataProcessingRelation) EvaluatedNodes(*pact.Payload) []int {
	return []int{0, 1, 2, 3, 4}
}

func (transparentDataProcessingRelation) Evaluate(doc *pact.Payload, _ *pact.Evidence) error {
	nodes, err := claimsFromTransparentPayloadRange(doc, 4)
	if err != nil {
		return err
	}
	return evaluateDataProcessingNodes(nodes)
}

func evaluateDataProcessingNodes(nodes map[int]map[string]interface{}) error {
	root := nodes[0]
	for _, key := range []string{"task_id", "dataset_id", "purpose"} {
		rootValue, _ := root[key].(string)
		if rootValue == "" {
			return fmt.Errorf("root missing %s", key)
		}
		for i := 1; i <= 4; i++ {
			got, _ := nodes[i][key].(string)
			if got == "" || got != rootValue {
				return fmt.Errorf("%s mismatch at node %d", key, i)
			}
		}
	}

	rootAudienceRank, ok := audienceRank(stringClaim(root, "audience"))
	if !ok {
		return fmt.Errorf("root missing audience")
	}
	rootValidity, ok := numericClaim(root, "valid_until")
	if !ok {
		return fmt.Errorf("root missing valid_until")
	}
	rootRetention, ok := numericClaim(root, "retention_limit")
	if !ok {
		return fmt.Errorf("root missing retention_limit")
	}
	allowedFields := stringSliceClaim(root, "allowed_fields")
	if len(allowedFields) == 0 {
		return fmt.Errorf("root missing allowed_fields")
	}
	sensitiveFields := stringSliceClaim(root, "sensitive_fields")
	if len(sensitiveFields) == 0 {
		return fmt.Errorf("root missing sensitive_fields")
	}
	rootPerms, err := enabledDataProcessingPermissions(root)
	if err != nil {
		return err
	}
	prevAudienceRank := rootAudienceRank
	prevValidity := rootValidity
	prevRetention := rootRetention
	for i := 1; i <= 4; i++ {
		nodeAudienceRank, ok := audienceRank(stringClaim(nodes[i], "audience"))
		if !ok || nodeAudienceRank > prevAudienceRank {
			return fmt.Errorf("audience expanded at node %d", i)
		}
		validity, ok := numericClaim(nodes[i], "valid_until")
		if !ok || validity > prevValidity {
			return fmt.Errorf("validity increased at node %d", i)
		}
		retention, ok := numericClaim(nodes[i], "retention_limit")
		if !ok || retention > prevRetention {
			return fmt.Errorf("retention expanded at node %d", i)
		}
		prevAudienceRank = nodeAudienceRank
		prevValidity = validity
		prevRetention = retention
		perms, err := enabledDataProcessingPermissions(nodes[i])
		if err != nil {
			return err
		}
		allowed := allowedDataProcessingPermissions(i)
		for perm := range perms {
			if !rootPerms[perm] || !allowed[perm] {
				return fmt.Errorf("permission %s not allowed at node %d", perm, i)
			}
			if perm == "report.release" && i != 4 {
				return fmt.Errorf("report.release appears before final step")
			}
		}
	}

	if !boolClaim(nodes[1], "dataset.read") {
		return fmt.Errorf("dataset retrieval lacks dataset.read")
	}
	if !sliceSubset(stringSliceClaim(nodes[1], "retrieved_fields"), allowedFields, sensitiveFields) {
		return fmt.Errorf("retrieved_fields outside dataset field universe")
	}
	filterHash := stringClaim(nodes[2], "filter_hash")
	if !boolClaim(nodes[2], "field.filter") || filterHash == "" {
		return fmt.Errorf("filter node lacks field.filter/filter_hash")
	}
	filteredFields := stringSliceClaim(nodes[2], "released_fields")
	if !sliceSubset(filteredFields, allowedFields) || sliceIntersects(filteredFields, sensitiveFields) {
		return fmt.Errorf("filtered release violates field policy")
	}
	summaryHash := stringClaim(nodes[3], "summary_hash")
	if !boolClaim(nodes[3], "aggregate.compute") || summaryHash != summaryHashForFilter(filterHash) {
		return fmt.Errorf("summary not bound to filter")
	}
	if stringClaim(nodes[3], "aggregation_hash") != aggregationHashForSummary(summaryHash) {
		return fmt.Errorf("aggregation not bound to summary")
	}
	summaryFields := stringSliceClaim(nodes[3], "released_fields")
	if !sliceSubset(summaryFields, allowedFields) || sliceIntersects(summaryFields, sensitiveFields) {
		return fmt.Errorf("summary release violates field policy")
	}
	reportHash := stringClaim(nodes[4], "report_hash")
	releasedFields := stringSliceClaim(nodes[4], "released_fields")
	if !sliceSubset(releasedFields, allowedFields) || sliceIntersects(releasedFields, sensitiveFields) {
		return fmt.Errorf("report release violates field policy")
	}
	if stringClaim(nodes[4], "aggregation_hash") != aggregationHashForSummary(summaryHash) {
		return fmt.Errorf("report aggregation not bound to summary")
	}
	if !boolClaim(nodes[4], "report.release") || reportHash != reportHashForSummary(summaryHash) || stringClaim(nodes[4], "summary_hash") != summaryHash {
		return fmt.Errorf("report not bound to summary")
	}
	return nil
}

func claimsFromEvidenceRange(e *pact.Evidence, maxNodeIndex int) (map[int]map[string]interface{}, error) {
	nodes := map[int]map[string]interface{}{}
	for i := 0; i <= maxNodeIndex; i++ {
		claims, err := claimsFromEvidence(e, i)
		if err != nil {
			return nil, err
		}
		nodes[i] = claims
	}
	return nodes, nil
}

func claimsFromEvidence(e *pact.Evidence, nodeIndex int) (map[string]interface{}, error) {
	openings, ok := e.NodeOpenings[nodeIndex]
	if !ok || len(openings) == 0 {
		return nil, fmt.Errorf("missing evidence for node %d", nodeIndex)
	}
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

func claimsFromTransparentPayloadRange(doc *pact.Payload, maxNodeIndex int) (map[int]map[string]interface{}, error) {
	nodes := map[int]map[string]interface{}{}
	for i := 0; i <= maxNodeIndex; i++ {
		claims, err := claimsFromTransparentPayload(doc, i)
		if err != nil {
			return nil, err
		}
		nodes[i] = claims
	}
	return nodes, nil
}

func claimsFromTransparentPayload(doc *pact.Payload, nodeIndex int) (map[string]interface{}, error) {
	nodePayload, err := transparentPayloadForNode(doc, nodeIndex)
	if err != nil {
		return nil, err
	}
	if nodePayload.Data == nil {
		return nil, fmt.Errorf("missing transparent payload data for node %d", nodeIndex)
	}
	claims := map[string]interface{}{}
	for key, value := range nodePayload.Data {
		claims[key] = value
	}
	return claims, nil
}

func transparentPayloadForNode(doc *pact.Payload, nodeIndex int) (*pact.Payload, error) {
	if doc == nil {
		return nil, fmt.Errorf("nil payload")
	}
	if nodeIndex == 0 {
		return doc, nil
	}
	idx := nodeIndex - 1
	if idx < 0 || idx >= len(doc.List) || doc.List[idx] == nil || doc.List[idx].Payload == nil {
		return nil, fmt.Errorf("node %d not found", nodeIndex)
	}
	return doc.List[idx].Payload, nil
}

func enabledPermissions(claims map[string]interface{}) (map[string]bool, error) {
	vocab := map[string]bool{"issue.read": true, "repo.read": true, "patch.propose": true, "analysis.execute": true, "patch.apply": true, "test.execute": true, "artifact.release": true}
	out := map[string]bool{}
	for key, value := range claims {
		enabled, _ := value.(bool)
		if !enabled {
			continue
		}
		if !vocab[key] {
			if strings.Contains(key, ".") {
				return nil, fmt.Errorf("unexpected permission %s", key)
			}
			continue
		}
		out[key] = true
	}
	return out, nil
}

func allowedNodePermissions(nodeIndex int) map[string]bool {
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

func enabledDataProcessingPermissions(claims map[string]interface{}) (map[string]bool, error) {
	vocab := map[string]bool{"dataset.read": true, "field.filter": true, "aggregate.compute": true, "report.release": true}
	out := map[string]bool{}
	for key, value := range claims {
		enabled, _ := value.(bool)
		if !enabled {
			continue
		}
		if !vocab[key] {
			if strings.Contains(key, ".") {
				return nil, fmt.Errorf("unexpected permission %s", key)
			}
			continue
		}
		out[key] = true
	}
	return out, nil
}

func allowedDataProcessingPermissions(nodeIndex int) map[string]bool {
	switch nodeIndex {
	case 1:
		return map[string]bool{"dataset.read": true}
	case 2:
		return map[string]bool{"field.filter": true}
	case 3:
		return map[string]bool{"aggregate.compute": true}
	case 4:
		return map[string]bool{"report.release": true}
	default:
		return map[string]bool{}
	}
}

func boolClaim(claims map[string]interface{}, key string) bool {
	v, _ := claims[key].(bool)
	return v
}

func stringClaim(claims map[string]interface{}, key string) string {
	v, _ := claims[key].(string)
	return v
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

func sliceSubset(values []string, allowedSets ...[]string) bool {
	if len(values) == 0 {
		return false
	}
	allowed := map[string]bool{}
	for _, allowedSet := range allowedSets {
		for _, value := range allowedSet {
			allowed[value] = true
		}
	}
	for _, value := range values {
		if !allowed[value] {
			return false
		}
	}
	return true
}

func sliceIntersects(left, right []string) bool {
	rightSet := map[string]bool{}
	for _, value := range right {
		rightSet[value] = true
	}
	for _, value := range left {
		if rightSet[value] {
			return true
		}
	}
	return false
}

func audienceRank(audience string) (int, bool) {
	ranks := map[string]int{
		"internal":      3,
		"risk-team":     2,
		"risk-analysts": 1,
	}
	rank, ok := ranks[audience]
	return rank, ok
}

func pathAllowed(modified string, allowedPaths []string) bool {
	cleanModified := strings.Trim(strings.ReplaceAll(modified, "\\", "/"), "/")
	if cleanModified == "" || strings.HasPrefix(cleanModified, "../") || strings.Contains(cleanModified, "/../") {
		return false
	}
	for _, allowed := range allowedPaths {
		cleanAllowed := strings.Trim(strings.ReplaceAll(allowed, "\\", "/"), "/")
		if cleanAllowed == "" {
			continue
		}
		if cleanModified == cleanAllowed || strings.HasPrefix(cleanModified, cleanAllowed+"/") {
			return true
		}
	}
	return false
}

func numericClaim(claims map[string]interface{}, key string) (int64, bool) {
	switch v := claims[key].(type) {
	case int:
		return int64(v), true
	case int64:
		return v, true
	case float64:
		return int64(v), true
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	default:
		return 0, false
	}
}

func pkix(pub any) []byte {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return b
}

func workflowClaimSets() []map[string]interface{} {
	return []map[string]interface{}{
		rootClaims(),
		contextClaims(),
		patchClaims(contextHash),
		applyClaims(patchHash),
		testClaims(diffHash),
		finalArtifactClaims(patchHash, diffHash, testLogHash),
	}
}

func contextBranchClaimSets() []map[string]interface{} {
	return []map[string]interface{}{
		rootClaims(),
		contextScopeClaims(),
		contextResultClaims(),
	}
}

func patchBranchClaimSets() []map[string]interface{} {
	return []map[string]interface{}{
		rootClaims(),
		patchScopeClaims(contextHash),
		patchResultClaims(contextHash),
	}
}

func repositoryBranchClaimSets() []map[string]interface{} {
	return []map[string]interface{}{
		rootClaims(),
		repositoryScopeClaims(contextHash, patchHash),
		applyClaims(patchHash),
		testClaims(diffHash),
		finalArtifactClaims(patchHash, diffHash, testLogHash),
	}
}

func codeMaintenanceScenario() pactScenario {
	return pactScenario{
		name:                "CodeMaintenance",
		tid:                 taskID,
		claims:              workflowClaimSets(),
		relation:            codeMaintenanceRelation{},
		transparentRelation: transparentCodeMaintenanceRelation{},
	}
}

func dataProcessingScenario() pactScenario {
	return pactScenario{
		name:                "DataProcessing",
		tid:                 "task-data-processing-report-v1",
		claims:              dataProcessingClaimSets(),
		relation:            dataProcessingRelation{},
		transparentRelation: transparentDataProcessingRelation{},
		disclosureSelector:  dataProcessingDisclosureIndexes,
	}
}

func rootClaims() map[string]interface{} {
	return map[string]interface{}{
		"task_id":              taskID,
		"repo":                 repo,
		"issue_id":             issueID,
		"branch_prefix":        branchPrefix,
		"allowed_paths":        []string{"internal/api/projects.go", "internal/api/projects_test.go"},
		"context_hash":         contextPlaceholder,
		"context_hash_pending": true,
		"issue.read":           true,
		"repo.read":            true,
		"patch.propose":        true,
		"analysis.execute":     true,
		"patch.apply":          true,
		"test.execute":         true,
		"artifact.release":     true,
	}
}

func contextClaims() map[string]interface{} {
	return map[string]interface{}{"task_id": taskID, "repo": repo, "issue_id": issueID, "issue.read": true, "repo.read": true, "issue_hash": issueHash, "files_hash": filesHash, "context_hash": contextHash, "relevant_files": []string{"internal/api/projects.go", "internal/api/projects_test.go"}}
}

func contextScopeClaims() map[string]interface{} {
	return map[string]interface{}{"task_id": taskID, "repo": repo, "issue_id": issueID, "branch_id": "context", "issue.read": true, "repo.read": true}
}

func contextResultClaims() map[string]interface{} {
	return map[string]interface{}{"task_id": taskID, "repo": repo, "issue_id": issueID, "branch_id": "context", "issue_hash": issueHash, "files_hash": filesHash, "context_hash": contextHash, "relevant_files": []string{"internal/api/projects.go", "internal/api/projects_test.go"}}
}

func patchScopeClaims(ch string) map[string]interface{} {
	return map[string]interface{}{"task_id": taskID, "repo": repo, "issue_id": issueID, "branch_id": "patch", "patch.propose": true, "analysis.execute": true, "context_hash": ch}
}

func patchClaims(ch string) map[string]interface{} {
	return map[string]interface{}{"task_id": taskID, "repo": repo, "issue_id": issueID, "patch.propose": true, "analysis.execute": true, "context_hash": ch, "patch_hash": patchHash, "rationale_hash": rationaleHash, "model_id": modelID, "risk_level": "low"}
}

func patchResultClaims(ch string) map[string]interface{} {
	return map[string]interface{}{"task_id": taskID, "repo": repo, "issue_id": issueID, "branch_id": "patch", "context_hash": ch, "patch_hash": patchHash, "rationale_hash": rationaleHash, "model_id": modelID, "risk_level": "low"}
}

func repositoryScopeClaims(ch, ph string) map[string]interface{} {
	return map[string]interface{}{"task_id": taskID, "repo": repo, "issue_id": issueID, "branch_id": "repository", "context_hash": ch, "patch_hash": ph, "allowed_paths": []string{"internal/api/projects.go", "internal/api/projects_test.go"}, "branch_prefix": branchPrefix, "patch.apply": true, "test.execute": true, "artifact.release": true}
}

func applyClaims(ph string) map[string]interface{} {
	return map[string]interface{}{"task_id": taskID, "repo": repo, "issue_id": issueID, "patch.apply": true, "patch_hash": ph, "diff_hash": diffHash, "applied": true, "modified_paths": []string{"internal/api/projects.go"}}
}

func testClaims(dh string) map[string]interface{} {
	return map[string]interface{}{"task_id": taskID, "repo": repo, "issue_id": issueID, "test.execute": true, "diff_hash": dh, "test_result": "passed", "test_log_hash": testLogHash, "command": "go test ./...", "passed": true}
}

func finalArtifactClaims(ph, dh, tlh string) map[string]interface{} {
	return map[string]interface{}{"task_id": taskID, "repo": repo, "issue_id": issueID, "artifact.release": true, "patch_hash": ph, "diff_hash": dh, "test_log_hash": tlh, "artifact_hash": artifactHash, "branch": branchPrefix + "-empty-project-id", "test_result": "passed", "status": "ok"}
}

func dataProcessingClaimSets() []map[string]interface{} {
	filterHash := "filter:dataset-customers-redacted:v1"
	summaryHash := summaryHashForFilter(filterHash)
	aggregationHash := aggregationHashForSummary(summaryHash)
	reportHash := reportHashForSummary(summaryHash)
	return []map[string]interface{}{
		dataRootClaims(),
		dataRetrievalClaims(),
		dataFilterClaims(filterHash),
		dataSummaryClaims(filterHash, summaryHash, aggregationHash),
		dataReportClaims(summaryHash, aggregationHash, reportHash),
	}
}

func dataRootClaims() map[string]interface{} {
	return map[string]interface{}{
		"task_id":           "task-data-processing-report-v1",
		"dataset_id":        "dataset-customers-2024q4",
		"purpose":           "quarterly-risk-summary",
		"audience":          "internal",
		"valid_until":       benchNow.Add(2 * time.Hour).Unix(),
		"retention_limit":   30,
		"allowed_fields":    []string{"customer_id", "risk_score", "region", "account_age"},
		"sensitive_fields":  []string{"email", "ssn", "date_of_birth"},
		"dataset.read":      true,
		"field.filter":      true,
		"aggregate.compute": true,
		"report.release":    true,
	}
}

func dataRetrievalClaims() map[string]interface{} {
	return map[string]interface{}{
		"task_id":         "task-data-processing-report-v1",
		"dataset_id":      "dataset-customers-2024q4",
		"purpose":         "quarterly-risk-summary",
		"audience":        "risk-team",
		"valid_until":     benchNow.Add(90 * time.Minute).Unix(),
		"retention_limit": 20,
		"dataset.read":    true,
		"retrieved_fields": []string{
			"customer_id", "risk_score", "region", "account_age",
			"email", "ssn", "date_of_birth",
		},
		"source_partition": "customers/2024q4",
	}
}

func dataFilterClaims(filterHash string) map[string]interface{} {
	return map[string]interface{}{
		"task_id":         "task-data-processing-report-v1",
		"dataset_id":      "dataset-customers-2024q4",
		"purpose":         "quarterly-risk-summary",
		"audience":        "risk-team",
		"valid_until":     benchNow.Add(75 * time.Minute).Unix(),
		"retention_limit": 14,
		"field.filter":    true,
		"allowed_fields":  []string{"customer_id", "risk_score", "region", "account_age"},
		"sensitive_fields": []string{
			"email", "ssn", "date_of_birth",
		},
		"released_fields": []string{"customer_id", "risk_score", "region"},
		"filter_hash":     filterHash,
		"filter_policy":   "drop-sensitive-fields",
	}
}

func dataSummaryClaims(filterHash, summaryHash, aggregationHash string) map[string]interface{} {
	return map[string]interface{}{
		"task_id":            "task-data-processing-report-v1",
		"dataset_id":         "dataset-customers-2024q4",
		"purpose":            "quarterly-risk-summary",
		"audience":           "risk-team",
		"valid_until":        benchNow.Add(time.Hour).Unix(),
		"retention_limit":    7,
		"aggregate.compute":  true,
		"released_fields":    []string{"risk_score", "region"},
		"filter_hash":        filterHash,
		"summary_hash":       summaryHash,
		"aggregation_hash":   aggregationHash,
		"aggregation_method": "region-risk-mean",
	}
}

func dataReportClaims(summaryHash, aggregationHash, reportHash string) map[string]interface{} {
	return map[string]interface{}{
		"task_id":          "task-data-processing-report-v1",
		"dataset_id":       "dataset-customers-2024q4",
		"purpose":          "quarterly-risk-summary",
		"audience":         "risk-analysts",
		"valid_until":      benchNow.Add(45 * time.Minute).Unix(),
		"retention_limit":  3,
		"report.release":   true,
		"released_fields":  []string{"risk_score", "region"},
		"summary_hash":     summaryHash,
		"aggregation_hash": aggregationHash,
		"report_hash":      reportHash,
		"report_format":    "redacted-csv",
	}
}

func summaryHashForFilter(filterHash string) string {
	return "summary:" + filterHash
}

func reportHashForSummary(summaryHash string) string {
	return "report:" + summaryHash
}

func aggregationHashForSummary(summaryHash string) string {
	return "aggregation:" + summaryHash
}

func syntheticClaims(node, fields int) map[string]interface{} {
	return syntheticClaimsWithTID(taskID, node, fields)
}

func syntheticClaimsWithTID(tid string, node, fields int) map[string]interface{} {
	claims := map[string]interface{}{
		"task_id":  tid,
		"repo":     repo,
		"issue_id": issueID,
		"node":     node,
	}
	for i := 0; i < fields; i++ {
		claims[fmt.Sprintf("field_%02d", i)] = fmt.Sprintf("node-%02d-value-%02d", node, i)
	}
	return claims
}

func selectiveDisclosureRequiredTags(opened int) []string {
	required := make([]string, opened)
	for i := range required {
		required[i] = fmt.Sprintf("field_%02d", i)
	}
	return required
}

type selectiveDisclosureLayerFixture struct {
	depthK        int
	fieldsPerNode int
	opened        int
	roots         map[int][]byte
	evidence      map[int][]sd.FieldOpening
	disclosures   map[int]*sd.Disclosure
	multiproofs   map[int]*sd.MerkleMultiProofDisclosure
	requiredTags  []string
}

func buildSelectiveDisclosureLayerFixture(depthK, fields, opened int) selectiveDisclosureLayerFixture {
	if opened < 1 || opened > fields {
		panic("opened fields must be in [1, fields]")
	}
	tid := fmt.Sprintf("%s-sd-layer-k%d-f%d-open%d", taskID, depthK, fields, opened)
	f := selectiveDisclosureLayerFixture{
		depthK:        depthK,
		fieldsPerNode: fields,
		opened:        opened,
		roots:         map[int][]byte{},
		evidence:      map[int][]sd.FieldOpening{},
		disclosures:   map[int]*sd.Disclosure{},
		multiproofs:   map[int]*sd.MerkleMultiProofDisclosure{},
		requiredTags:  selectiveDisclosureRequiredTags(opened),
	}
	selected := selectedIndexes(fields, float64(opened)/float64(fields))
	for node := 0; node < depthK; node++ {
		openings := make([]sd.FieldOpening, 0, fields)
		for field := 0; field < fields; field++ {
			tag := fmt.Sprintf("field_%02d", field)
			value := fmt.Sprintf("tid=%s/node=%02d/field=%02d", tid, node, field)
			opening, err := sd.NewDeterministicFieldOpeningForTest(tid, node, field, tag, value)
			if err != nil {
				panic(err)
			}
			openings = append(openings, opening)
		}
		commitments, err := sd.OpeningsToCommitments(openings)
		if err != nil {
			panic(err)
		}
		root, err := sd.MerkleRoot(commitments)
		if err != nil {
			panic(err)
		}
		disclosure, err := sd.CreateDisclosureFromOpenings(openings, selected)
		if err != nil {
			panic(err)
		}
		multiproof, err := sd.CreateMerkleMultiProofDisclosureFromOpenings(openings, selected)
		if err != nil {
			panic(err)
		}
		f.roots[node] = root
		f.evidence[node] = openings
		f.disclosures[node] = disclosure
		f.multiproofs[node] = multiproof
	}
	return f
}

func newIDKeys(ext int) (*ecdsa.PrivateKey, []*ecdsa.PrivateKey) {
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	signers := make([]*ecdsa.PrivateKey, ext)
	for i := range signers {
		signers[i], err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
	}
	return issuer, signers
}

func rootIDPayload(issuer *ecdsa.PrivateKey, signers []*ecdsa.PrivateKey, tid string) *pact.Payload {
	p := &pact.Payload{
		Ver:       pact.ModeID,
		TID0:      tid,
		NodeIndex: 0,
		Iat:       benchNow.Unix(),
		Iss:       &pact.IDClaim{CN: "issuer", PK: pkix(&issuer.PublicKey)},
	}
	if len(signers) > 0 {
		p.NextSignerPK = pkix(&signers[0].PublicKey)
		p.NextNotBefore = benchNow.Add(-time.Minute).Unix()
		p.NextNotAfter = benchNow.Add(time.Hour).Unix()
	}
	return p
}

func rootSchoCoPayload(pk []byte, tid string) *pact.Payload {
	return &pact.Payload{
		Ver:       pact.ModeSchoCo,
		TID0:      tid,
		NodeIndex: 0,
		Iat:       benchNow.Unix(),
		Iss:       &pact.IDClaim{CN: "issuer", PK: pk},
	}
}

func attachNode(
	p *pact.Payload,
	tid string,
	nodeIndex int,
	claims map[string]interface{},
	evidence *pact.Evidence,
	disclosures map[int]*sd.Disclosure,
	disclosureRatio float64,
) {
	attachNodeWithSelector(p, tid, nodeIndex, claims, evidence, disclosures, disclosureRatio, nil)
}

func attachNodeWithSelector(
	p *pact.Payload,
	tid string,
	nodeIndex int,
	claims map[string]interface{},
	evidence *pact.Evidence,
	disclosures map[int]*sd.Disclosure,
	disclosureRatio float64,
	selector func(nodeIndex int, keys []string, disclosureRatio float64) []int,
) {
	keys, openings, err := pact.AttachCommitmentRootToPayload(p, tid, nodeIndex, claims)
	if err != nil {
		panic(err)
	}
	evidence.NodeOpenings[nodeIndex] = openings
	selected := selectedIndexes(len(keys), disclosureRatio)
	if selector != nil {
		selected = selector(nodeIndex, keys, disclosureRatio)
	}
	disclosures[nodeIndex], err = sd.CreateDisclosureFromOpenings(openings, selected)
	if err != nil {
		panic(err)
	}
}

func dataProcessingDisclosureIndexes(nodeIndex int, keys []string, disclosureRatio float64) []int {
	switch nodeIndex {
	case 0:
		return indexesForKeys(keys, "task_id", "dataset_id", "purpose", "audience", "valid_until", "retention_limit", "allowed_fields", "sensitive_fields")
	case 1:
		return indexesForKeys(keys, "task_id", "dataset_id", "purpose", "audience", "valid_until", "retention_limit", "dataset.read")
	case 2:
		return indexesForKeys(keys, "task_id", "dataset_id", "purpose", "audience", "valid_until", "retention_limit", "field.filter", "released_fields", "filter_hash")
	case 3:
		return indexesForKeys(keys, "task_id", "dataset_id", "purpose", "audience", "valid_until", "retention_limit", "aggregate.compute", "released_fields", "filter_hash", "summary_hash")
	case 4:
		return indexesForKeys(keys, "task_id", "dataset_id", "purpose", "audience", "valid_until", "retention_limit", "report.release", "released_fields", "summary_hash", "report_hash")
	default:
		return selectedIndexes(len(keys), disclosureRatio)
	}
}

func codeMaintenanceBranchDisclosureIndexes(nodeIndex int, keys []string, disclosureRatio float64) []int {
	common := []string{"task_id", "repo", "issue_id"}
	switch nodeIndex {
	case 0:
		return indexesForExistingKeys(keys, append(common, "branch_prefix")...)
	case 1:
		return indexesForExistingKeys(keys, append(common,
			"branch_id",
			"issue.read",
			"repo.read",
			"patch.propose",
			"analysis.execute",
			"context_hash",
			"patch_hash",
			"allowed_paths",
			"branch_prefix",
			"patch.apply",
			"test.execute",
			"artifact.release",
		)...)
	case 2:
		return indexesForExistingKeys(keys, append(common,
			"branch_id",
			"context_hash",
			"issue_hash",
			"files_hash",
			"relevant_files",
			"patch_hash",
			"rationale_hash",
			"model_id",
			"risk_level",
			"patch.apply",
			"diff_hash",
			"modified_paths",
			"applied",
		)...)
	case 3:
		return indexesForExistingKeys(keys, append(common,
			"test.execute",
			"diff_hash",
			"test_result",
			"test_log_hash",
			"command",
			"passed",
		)...)
	case 4:
		return indexesForExistingKeys(keys, append(common,
			"artifact.release",
			"diff_hash",
			"test_log_hash",
			"artifact_hash",
			"branch",
			"test_result",
			"status",
		)...)
	default:
		return selectedIndexes(len(keys), disclosureRatio)
	}
}

func indexesForKeys(keys []string, selected ...string) []int {
	indexByKey := map[string]int{}
	for i, key := range keys {
		indexByKey[key] = i
	}
	out := make([]int, 0, len(selected))
	for _, key := range selected {
		idx, ok := indexByKey[key]
		if !ok {
			panic(fmt.Sprintf("disclosure key %s not found", key))
		}
		out = append(out, idx)
	}
	return out
}

func indexesForExistingKeys(keys []string, selected ...string) []int {
	indexByKey := map[string]int{}
	for i, key := range keys {
		indexByKey[key] = i
	}
	out := make([]int, 0, len(selected))
	for _, key := range selected {
		if idx, ok := indexByKey[key]; ok {
			out = append(out, idx)
		}
	}
	return out
}

func selectedIndexes(n int, ratio float64) []int {
	if n == 0 {
		return nil
	}
	count := int(float64(n) * ratio)
	if count < 1 {
		count = 1
	}
	if count > n {
		count = n
	}
	out := make([]int, count)
	for i := range out {
		out[i] = i
	}
	return out
}

func buildPACTWorkflowFixture(mode int8) pactFixture {
	scenario := codeMaintenanceScenario()
	return buildPACTFixture(mode, scenario.claims, scenario.tid, 0.5)
}

func buildPACTScalingFixture(mode int8, extensions, fields int, disclosureRatio float64) pactFixture {
	tid := fmt.Sprintf("%s-k%d-f%d", taskID, extensions, fields)
	claims := make([]map[string]interface{}, extensions+1)
	for i := range claims {
		claims[i] = syntheticClaimsWithTID(tid, i, fields)
	}
	return buildPACTFixture(mode, claims, tid, disclosureRatio)
}

func buildPACTFixture(mode int8, claims []map[string]interface{}, tid string, disclosureRatio float64) pactFixture {
	return buildPACTFixtureWithSelector(mode, claims, tid, disclosureRatio, nil)
}

func buildPACTScenarioFixture(mode int8, scenario pactScenario) pactFixture {
	return buildPACTFixtureWithSelector(mode, scenario.claims, scenario.tid, 0.5, scenario.disclosureSelector)
}

func buildCodeMaintenanceBranchFixture(mode int8) codeMaintenanceBranchFixture {
	context := buildPACTFixture(mode, contextBranchClaimSets(), taskID, 0.5)
	patch := buildPACTFixture(mode, patchBranchClaimSets(), taskID, 0.5)
	repository := buildPACTFixture(mode, repositoryBranchClaimSets(), taskID, 0.5)
	return codeMaintenanceBranchFixture{
		mode:       mode,
		tid:        taskID,
		context:    context,
		patch:      patch,
		repository: repository,
		rc:         repository.rc,
	}
}

func buildCodeMaintenanceBranchSelectiveFixture(mode int8) codeMaintenanceBranchFixture {
	context := buildPACTFixtureWithSelector(mode, contextBranchClaimSets(), taskID, 0.5, codeMaintenanceBranchDisclosureIndexes)
	patch := buildPACTFixtureWithSelector(mode, patchBranchClaimSets(), taskID, 0.5, codeMaintenanceBranchDisclosureIndexes)
	repository := buildPACTFixtureWithSelector(mode, repositoryBranchClaimSets(), taskID, 0.5, codeMaintenanceBranchDisclosureIndexes)
	return codeMaintenanceBranchFixture{
		mode:       mode,
		tid:        taskID,
		context:    context,
		patch:      patch,
		repository: repository,
		rc:         repository.rc,
	}
}

func buildCodeMaintenanceBranchTransparentFixture(mode int8) codeMaintenanceBranchFixture {
	context := buildTransparentPayloadFixture(mode, contextBranchClaimSets(), taskID)
	patch := buildTransparentPayloadFixture(mode, patchBranchClaimSets(), taskID)
	repository := buildTransparentPayloadFixture(mode, repositoryBranchClaimSets(), taskID)
	return codeMaintenanceBranchFixture{
		mode:       mode,
		tid:        taskID,
		context:    context,
		patch:      patch,
		repository: repository,
		rc:         repository.rc,
	}
}

func buildTransparentPayloadScenarioFixture(mode int8, scenario pactScenario) pactFixture {
	return buildTransparentPayloadFixture(mode, scenario.claims, scenario.tid)
}

func validateCodeMaintenanceBranchFixture(f codeMaintenanceBranchFixture) error {
	for label, branch := range map[string]pactFixture{
		"context":    f.context,
		"patch":      f.patch,
		"repository": f.repository,
	} {
		opts := validationOptions(branch, branch.evidence, nil, nil, branch.rc)
		if _, err := pact.ValidatePACT(branch.token, branch.mode, opts); err != nil {
			return fmt.Errorf("%s branch validation failed: %w", label, err)
		}
	}
	contextNodes, err := claimsFromEvidenceRange(f.context.evidence, 2)
	if err != nil {
		return err
	}
	patchNodes, err := claimsFromEvidenceRange(f.patch.evidence, 2)
	if err != nil {
		return err
	}
	repoNodes, err := claimsFromEvidenceRange(f.repository.evidence, 4)
	if err != nil {
		return err
	}
	return evaluateCodeMaintenanceBranches(contextNodes, patchNodes, repoNodes)
}

func validateCodeMaintenanceBranchTransparentFixture(f codeMaintenanceBranchFixture) error {
	for label, branch := range map[string]pactFixture{
		"context":    f.context,
		"patch":      f.patch,
		"repository": f.repository,
	} {
		opts := validationOptions(branch, nil, nil, nil, branch.rc)
		if _, err := pact.ValidatePACT(branch.token, branch.mode, opts); err != nil {
			return fmt.Errorf("%s branch validation failed: %w", label, err)
		}
	}
	contextNodes, err := claimsFromTransparentPayloadRange(payloadFromFixtureToken(f.context), 2)
	if err != nil {
		return err
	}
	patchNodes, err := claimsFromTransparentPayloadRange(payloadFromFixtureToken(f.patch), 2)
	if err != nil {
		return err
	}
	repoNodes, err := claimsFromTransparentPayloadRange(payloadFromFixtureToken(f.repository), 4)
	if err != nil {
		return err
	}
	return evaluateCodeMaintenanceBranches(contextNodes, patchNodes, repoNodes)
}

func validateCodeMaintenanceBranchSelectiveFixture(f codeMaintenanceBranchFixture) error {
	for label, branch := range map[string]pactFixture{
		"context":    f.context,
		"patch":      f.patch,
		"repository": f.repository,
	} {
		opts := validationOptions(branch, nil, branch.disclosure, nil, branch.rc)
		if _, err := pact.ValidatePACT(branch.token, branch.mode, opts); err != nil {
			return fmt.Errorf("%s branch validation failed: %w", label, err)
		}
	}
	contextNodes, err := claimsFromDisclosuresRange(f.context.disclosure, 2)
	if err != nil {
		return err
	}
	patchNodes, err := claimsFromDisclosuresRange(f.patch.disclosure, 2)
	if err != nil {
		return err
	}
	repoNodes, err := claimsFromDisclosuresRange(f.repository.disclosure, 4)
	if err != nil {
		return err
	}
	return evaluateCodeMaintenanceBranches(contextNodes, patchNodes, repoNodes)
}

func payloadFromFixtureToken(f pactFixture) *pact.Payload {
	parts := strings.Split(f.token, ".")
	if len(parts) != 3 {
		panic("invalid fixture token")
	}
	payloadB, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		panic(err)
	}
	var doc pact.Payload
	if err := json.Unmarshal(payloadB, &doc); err != nil {
		panic(err)
	}
	return &doc
}

func claimsFromDisclosuresRange(disclosures map[int]*sd.Disclosure, maxNodeIndex int) (map[int]map[string]interface{}, error) {
	nodes := map[int]map[string]interface{}{}
	for i := 0; i <= maxNodeIndex; i++ {
		claims, err := claimsFromDisclosure(disclosures[i], i)
		if err != nil {
			return nil, err
		}
		nodes[i] = claims
	}
	return nodes, nil
}

func claimsFromDisclosure(d *sd.Disclosure, nodeIndex int) (map[string]interface{}, error) {
	if d == nil || len(d.Openings) == 0 {
		return nil, fmt.Errorf("missing disclosure for node %d", nodeIndex)
	}
	claims := map[string]interface{}{}
	for _, opening := range d.Openings {
		if opening.NodeIndex != nodeIndex {
			return nil, fmt.Errorf("node %d disclosure contains opening for node %d", nodeIndex, opening.NodeIndex)
		}
		var v interface{}
		if err := json.Unmarshal(opening.Value, &v); err != nil {
			return nil, err
		}
		claims[opening.Tag] = v
	}
	return claims, nil
}

func evaluateCodeMaintenanceBranches(contextNodes, patchNodes, repoNodes map[int]map[string]interface{}) error {
	root := contextNodes[0]
	for _, nodes := range []map[int]map[string]interface{}{patchNodes, repoNodes} {
		for _, key := range []string{"task_id", "repo", "issue_id", "branch_prefix"} {
			if stringClaim(nodes[0], key) != stringClaim(root, key) {
				return fmt.Errorf("branch root %s mismatch", key)
			}
		}
	}
	for _, binding := range []struct {
		nodes map[int]map[string]interface{}
		last  int
	}{
		{contextNodes, 2},
		{patchNodes, 2},
		{repoNodes, 4},
	} {
		for _, key := range []string{"task_id", "repo", "issue_id"} {
			for i := 1; i <= binding.last; i++ {
				if stringClaim(binding.nodes[i], key) != stringClaim(root, key) {
					return fmt.Errorf("%s mismatch at branch node %d", key, i)
				}
			}
		}
	}
	if stringClaim(contextNodes[1], "branch_id") != "context" || !boolClaim(contextNodes[1], "issue.read") || !boolClaim(contextNodes[1], "repo.read") {
		return fmt.Errorf("invalid context scope")
	}
	ch := stringClaim(contextNodes[2], "context_hash")
	if stringClaim(contextNodes[2], "branch_id") != "context" || ch == "" || stringClaim(contextNodes[2], "issue_hash") == "" || stringClaim(contextNodes[2], "files_hash") == "" {
		return fmt.Errorf("invalid context result")
	}
	if stringClaim(patchNodes[1], "branch_id") != "patch" || stringClaim(patchNodes[1], "context_hash") != ch {
		return fmt.Errorf("patch scope not bound to context")
	}
	ph := stringClaim(patchNodes[2], "patch_hash")
	if stringClaim(patchNodes[2], "branch_id") != "patch" || stringClaim(patchNodes[2], "context_hash") != ch || ph == "" || stringClaim(patchNodes[2], "rationale_hash") == "" || stringClaim(patchNodes[2], "model_id") == "" {
		return fmt.Errorf("invalid patch result")
	}
	if stringClaim(repoNodes[1], "branch_id") != "repository" || stringClaim(repoNodes[1], "context_hash") != ch || stringClaim(repoNodes[1], "patch_hash") != ph {
		return fmt.Errorf("repository scope not bound to context and patch")
	}
	if !boolClaim(repoNodes[2], "patch.apply") || stringClaim(repoNodes[2], "patch_hash") != ph {
		return fmt.Errorf("application not bound to patch")
	}
	dh := stringClaim(repoNodes[2], "diff_hash")
	if dh == "" {
		return fmt.Errorf("application missing diff_hash")
	}
	allowedPaths := stringSliceClaim(repoNodes[1], "allowed_paths")
	for _, modified := range stringSliceClaim(repoNodes[2], "modified_paths") {
		if !pathAllowed(modified, allowedPaths) {
			return fmt.Errorf("modified path %s outside allowed_paths", modified)
		}
	}
	if !boolClaim(repoNodes[3], "test.execute") || stringClaim(repoNodes[3], "diff_hash") != dh || stringClaim(repoNodes[3], "test_result") != "passed" {
		return fmt.Errorf("tests not bound to diff")
	}
	tlh := stringClaim(repoNodes[3], "test_log_hash")
	if tlh == "" {
		return fmt.Errorf("test missing test_log_hash")
	}
	if !boolClaim(repoNodes[4], "artifact.release") || stringClaim(repoNodes[4], "diff_hash") != dh || stringClaim(repoNodes[4], "test_log_hash") != tlh {
		return fmt.Errorf("release not bound to test evidence")
	}
	if stringClaim(repoNodes[4], "test_result") != "passed" || stringClaim(repoNodes[4], "artifact_hash") == "" {
		return fmt.Errorf("release requires passed test artifact")
	}
	if !strings.HasPrefix(stringClaim(repoNodes[4], "branch"), stringClaim(repoNodes[1], "branch_prefix")) {
		return fmt.Errorf("branch prefix mismatch")
	}
	return nil
}

func buildPACTFixtureWithSelector(mode int8, claims []map[string]interface{}, tid string, disclosureRatio float64, selector func(nodeIndex int, keys []string, disclosureRatio float64) []int) pactFixture {
	if len(claims) == 0 {
		panic("empty fixture")
	}
	evidence := &pact.Evidence{NodeOpenings: map[int][]sd.FieldOpening{}}
	disclosures := map[int]*sd.Disclosure{}
	extensions := len(claims) - 1

	switch mode {
	case pact.ModeID:
		issuer, signers := newIDKeys(extensions + 1)
		root := rootIDPayload(issuer, signers, tid)
		attachNodeWithSelector(root, tid, 0, claims[0], evidence, disclosures, disclosureRatio, selector)
		token, err := pact.CreateJWS(root, pact.ModeID, issuer)
		if err != nil {
			panic(err)
		}
		for i := 1; i < len(claims); i++ {
			node := &pact.Payload{
				Ver:       pact.ModeID,
				TID0:      tid,
				NodeIndex: i,
				Iat:       benchNow.Unix(),
				Iss:       &pact.IDClaim{CN: fmt.Sprintf("bearer-%d", i), PK: pkix(&signers[i-1].PublicKey)},
			}
			if i < len(signers) {
				node.NextSignerPK = pkix(&signers[i].PublicKey)
				node.NextNotBefore = benchNow.Add(-time.Minute).Unix()
				node.NextNotAfter = benchNow.Add(time.Hour).Unix()
			}
			attachNodeWithSelector(node, tid, i, claims[i], evidence, disclosures, disclosureRatio, selector)
			token, err = pact.ExtendJWS(token, &pact.LDNode{Payload: node}, pact.ModeID, signers[i-1])
			if err != nil {
				panic(err)
			}
		}
		rc, err := pact.CreateRevocationCheckpoint(issuer, 1, benchNow.Unix(), nil)
		if err != nil {
			panic(err)
		}
		return pactFixture{
			mode:       pact.ModeID,
			tid:        tid,
			token:      token,
			evidence:   evidence,
			disclosure: disclosures,
			issuerPK:   pkix(&issuer.PublicKey),
			resolver:   pact.LocalIDKeyResolver{},
			rc:         rc,
			nextIDKey:  signers[extensions],
		}

	case pact.ModeSchoCo:
		sk, pk, err := schoco.KeyPair()
		if err != nil {
			panic(err)
		}
		root := rootSchoCoPayload(pk.Bytes(), tid)
		attachNodeWithSelector(root, tid, 0, claims[0], evidence, disclosures, disclosureRatio, selector)
		token, err := pact.CreateJWS(root, pact.ModeSchoCo, sk)
		if err != nil {
			panic(err)
		}
		for i := 1; i < len(claims); i++ {
			node := &pact.Payload{
				Ver:       pact.ModeSchoCo,
				TID0:      tid,
				NodeIndex: i,
				Iat:       benchNow.Unix(),
				Iss:       &pact.IDClaim{CN: fmt.Sprintf("node-%d", i)},
			}
			attachNodeWithSelector(node, tid, i, claims[i], evidence, disclosures, disclosureRatio, selector)
			token, err = pact.ExtendJWS(token, &pact.LDNode{Payload: node}, pact.ModeSchoCo)
			if err != nil {
				panic(err)
			}
		}
		rcKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		rc, err := pact.CreateRevocationCheckpoint(rcKey, 1, benchNow.Unix(), nil)
		if err != nil {
			panic(err)
		}
		return pactFixture{
			mode:       pact.ModeSchoCo,
			tid:        tid,
			token:      token,
			evidence:   evidence,
			disclosure: disclosures,
			issuerPK:   pkix(&rcKey.PublicKey),
			rc:         rc,
		}
	default:
		panic("unknown PACT mode")
	}
}

func buildTransparentPayloadFixture(mode int8, claims []map[string]interface{}, tid string) pactFixture {
	if len(claims) == 0 {
		panic("empty transparent payload fixture")
	}
	extensions := len(claims) - 1

	switch mode {
	case pact.ModeID:
		issuer, signers := newIDKeys(extensions + 1)
		root := rootIDPayload(issuer, signers, tid)
		attachTransparentClaims(root, claims[0])
		token, err := pact.CreateJWS(root, pact.ModeID, issuer)
		if err != nil {
			panic(err)
		}
		for i := 1; i < len(claims); i++ {
			node := &pact.Payload{
				Ver:       pact.ModeID,
				TID0:      tid,
				NodeIndex: i,
				Iat:       benchNow.Unix(),
				Iss:       &pact.IDClaim{CN: fmt.Sprintf("bearer-%d", i), PK: pkix(&signers[i-1].PublicKey)},
			}
			if i < len(signers) {
				node.NextSignerPK = pkix(&signers[i].PublicKey)
				node.NextNotBefore = benchNow.Add(-time.Minute).Unix()
				node.NextNotAfter = benchNow.Add(time.Hour).Unix()
			}
			attachTransparentClaims(node, claims[i])
			token, err = pact.ExtendJWS(token, &pact.LDNode{Payload: node}, pact.ModeID, signers[i-1])
			if err != nil {
				panic(err)
			}
		}
		rc, err := pact.CreateRevocationCheckpoint(issuer, 1, benchNow.Unix(), nil)
		if err != nil {
			panic(err)
		}
		return pactFixture{
			mode:      pact.ModeID,
			tid:       tid,
			token:     token,
			issuerPK:  pkix(&issuer.PublicKey),
			resolver:  pact.LocalIDKeyResolver{},
			rc:        rc,
			nextIDKey: signers[extensions],
		}

	case pact.ModeSchoCo:
		sk, pk, err := schoco.KeyPair()
		if err != nil {
			panic(err)
		}
		root := rootSchoCoPayload(pk.Bytes(), tid)
		attachTransparentClaims(root, claims[0])
		token, err := pact.CreateJWS(root, pact.ModeSchoCo, sk)
		if err != nil {
			panic(err)
		}
		for i := 1; i < len(claims); i++ {
			node := &pact.Payload{
				Ver:       pact.ModeSchoCo,
				TID0:      tid,
				NodeIndex: i,
				Iat:       benchNow.Unix(),
				Iss:       &pact.IDClaim{CN: fmt.Sprintf("node-%d", i)},
			}
			attachTransparentClaims(node, claims[i])
			token, err = pact.ExtendJWS(token, &pact.LDNode{Payload: node}, pact.ModeSchoCo)
			if err != nil {
				panic(err)
			}
		}
		rcKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		rc, err := pact.CreateRevocationCheckpoint(rcKey, 1, benchNow.Unix(), nil)
		if err != nil {
			panic(err)
		}
		return pactFixture{
			mode:     pact.ModeSchoCo,
			tid:      tid,
			token:    token,
			issuerPK: pkix(&rcKey.PublicKey),
			rc:       rc,
		}
	default:
		panic("unknown PACT mode")
	}
}

func attachTransparentClaims(p *pact.Payload, claims map[string]interface{}) {
	p.Data = cloneClaims(claims)
}

func validationOptions(f pactFixture, evidence *pact.Evidence, disclosures map[int]*sd.Disclosure, relation pact.VerifierRelation, rc *pact.RevocationCheckpoint) pact.ValidationOptions {
	return pact.ValidationOptions{
		Evidence:             evidence,
		Presentations:        disclosures,
		VerifierRelation:     relation,
		RevocationCheckpoint: rc,
		Tau:                  time.Minute,
		ClockSkew:            5 * time.Second,
		RequireRevocation:    rc != nil,
		TrustedIssuerPK:      f.issuerPK,
		Now:                  benchNow,
		IDKeyResolver:        f.resolver,
	}
}

func cloneClaimSets(claimSets []map[string]interface{}) []map[string]interface{} {
	out := make([]map[string]interface{}, len(claimSets))
	for i, claims := range claimSets {
		out[i] = cloneClaims(claims)
	}
	return out
}

func cloneClaims(claims map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(claims))
	for key, value := range claims {
		out[key] = value
	}
	return out
}

func disclosureTags(d *sd.Disclosure) map[string]bool {
	tags := map[string]bool{}
	if d == nil {
		return tags
	}
	for _, opening := range d.Openings {
		tags[opening.Tag] = true
	}
	return tags
}

func requireTags(t *testing.T, tags map[string]bool, required ...string) {
	t.Helper()
	for _, tag := range required {
		if !tags[tag] {
			t.Fatalf("missing disclosed tag %q", tag)
		}
	}
}

func rejectTags(t *testing.T, tags map[string]bool, rejected ...string) {
	t.Helper()
	for _, tag := range rejected {
		if tags[tag] {
			t.Fatalf("unexpected disclosed tag %q", tag)
		}
	}
}

func TestDataProcessingRelationRejectsSensitiveReportRelease(t *testing.T) {
	scenario := dataProcessingScenario()
	claims := cloneClaimSets(scenario.claims)
	claims[4]["released_fields"] = []string{"risk_score", "email"}
	f := buildPACTFixtureWithSelector(pact.ModeSchoCo, claims, scenario.tid, 0.5, scenario.disclosureSelector)
	opts := validationOptions(f, f.evidence, nil, scenario.relation, f.rc)

	if _, err := pact.ValidatePACT(f.token, f.mode, opts); err == nil {
		t.Fatal("expected sensitive released_fields to be rejected")
	}
}

func TestDataProcessingRelationRejectsAudienceExpansion(t *testing.T) {
	scenario := dataProcessingScenario()
	claims := cloneClaimSets(scenario.claims)
	claims[4]["audience"] = "internal"
	f := buildPACTFixtureWithSelector(pact.ModeSchoCo, claims, scenario.tid, 0.5, scenario.disclosureSelector)
	opts := validationOptions(f, f.evidence, nil, scenario.relation, f.rc)

	if _, err := pact.ValidatePACT(f.token, f.mode, opts); err == nil {
		t.Fatal("expected audience expansion to be rejected")
	}
}

func TestDataProcessingRelationRejectsUnboundReport(t *testing.T) {
	scenario := dataProcessingScenario()
	claims := cloneClaimSets(scenario.claims)
	claims[4]["report_hash"] = "report:wrong-summary"
	f := buildPACTFixtureWithSelector(pact.ModeSchoCo, claims, scenario.tid, 0.5, scenario.disclosureSelector)
	opts := validationOptions(f, f.evidence, nil, scenario.relation, f.rc)

	if _, err := pact.ValidatePACT(f.token, f.mode, opts); err == nil {
		t.Fatal("expected report_hash not bound to summary_hash to be rejected")
	}
}

func TestDataProcessingSelectiveDisclosureShape(t *testing.T) {
	scenario := dataProcessingScenario()
	f := buildPACTScenarioFixture(pact.ModeSchoCo, scenario)

	filterTags := disclosureTags(f.disclosure[2])
	requireTags(t, filterTags, "task_id", "dataset_id", "purpose", "audience", "valid_until", "retention_limit", "field.filter", "released_fields", "filter_hash")
	rejectTags(t, filterTags, "sensitive_fields", "filter_policy", "retrieved_fields")

	reportTags := disclosureTags(f.disclosure[4])
	requireTags(t, reportTags, "task_id", "dataset_id", "purpose", "audience", "valid_until", "retention_limit", "report.release", "released_fields", "summary_hash", "report_hash")
	rejectTags(t, reportTags, "allowed_fields", "sensitive_fields", "retrieved_fields", "filter_policy")

	if len(f.disclosure[4].Openings) >= len(f.evidence.NodeOpenings[4]) {
		t.Fatal("expected report release disclosure to omit internal report fields")
	}
}

func TestDataProcessingSelectiveWorkflowValidates(t *testing.T) {
	scenario := dataProcessingScenario()
	f := buildPACTScenarioFixture(pact.ModeSchoCo, scenario)
	opts := validationOptions(f, nil, f.disclosure, nil, f.rc)

	if _, err := pact.ValidatePACT(f.token, f.mode, opts); err != nil {
		t.Fatalf("expected selective DataProcessing presentation to validate: %v", err)
	}
}

func TestSelectiveDisclosureBenchmarkValidationAndTamperRejection(t *testing.T) {
	const (
		depthK        = 2
		fieldsPerNode = 8
		opened        = 4
	)
	f := buildSelectiveDisclosureLayerFixture(depthK, fieldsPerNode, opened)

	for nodeIndex, openings := range f.evidence {
		if len(openings) != fieldsPerNode {
			t.Fatalf("node %d evidence has %d openings, want %d", nodeIndex, len(openings), fieldsPerNode)
		}
	}
	for nodeIndex, disclosure := range f.disclosures {
		if len(disclosure.Openings) != opened {
			t.Fatalf("node %d disclosure has %d openings, want %d", nodeIndex, len(disclosure.Openings), opened)
		}
	}
	if err := validateSelectiveDisclosureLayerFixture(f); err != nil {
		t.Fatalf("valid selective disclosure rejected: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*sd.Disclosure)
	}{
		{
			name: "value",
			mutate: func(d *sd.Disclosure) {
				d.Openings[0].Value = json.RawMessage(`"tampered"`)
			},
		},
		{
			name: "salt",
			mutate: func(d *sd.Disclosure) {
				d.Openings[0].Salt[0] ^= 0x01
			},
		},
		{
			name: "node_index",
			mutate: func(d *sd.Disclosure) {
				d.Openings[0].NodeIndex++
			},
		},
		{
			name: "commitment_root",
			mutate: func(d *sd.Disclosure) {
				d.Root[0] ^= 0x01
			},
		},
		{
			name: "merkle_path",
			mutate: func(d *sd.Disclosure) {
				d.Proofs[0][0][0] ^= 0x01
			},
		},
		{
			name: "missing_required_field",
			mutate: func(d *sd.Disclosure) {
				d.Indices = d.Indices[1:]
				d.Openings = d.Openings[1:]
				d.Proofs = d.Proofs[1:]
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tampered := f
			tampered.disclosures = cloneDisclosureMapForTest(t, f.disclosures)
			tc.mutate(tampered.disclosures[0])
			if err := validateSelectiveDisclosureLayerFixture(tampered); err == nil {
				t.Fatal("tampered selective disclosure unexpectedly validated")
			}
		})
	}
}

func TestSelectiveDisclosureMultiproofValidationAndTamperRejection(t *testing.T) {
	const (
		depthK        = 2
		fieldsPerNode = 8
		opened        = 4
	)
	f := buildSelectiveDisclosureLayerFixture(depthK, fieldsPerNode, opened)

	for nodeIndex, multiproof := range f.multiproofs {
		if len(multiproof.Openings) != opened {
			t.Fatalf("node %d multiproof has %d openings, want %d", nodeIndex, len(multiproof.Openings), opened)
		}
		if len(multiproof.ProofNodes) == 0 {
			t.Fatalf("node %d multiproof has no proof nodes", nodeIndex)
		}
	}
	if err := validateSelectiveDisclosureLayerMultiproofFixture(f); err != nil {
		t.Fatalf("valid selective multiproof rejected: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*selectiveDisclosureLayerFixture)
	}{
		{
			name: "value",
			mutate: func(f *selectiveDisclosureLayerFixture) {
				f.multiproofs[0].Openings[0].Value = json.RawMessage(`"tampered"`)
			},
		},
		{
			name: "salt",
			mutate: func(f *selectiveDisclosureLayerFixture) {
				f.multiproofs[0].Openings[0].Salt[0] ^= 0x01
			},
		},
		{
			name: "node_index",
			mutate: func(f *selectiveDisclosureLayerFixture) {
				f.multiproofs[0].Openings[0].NodeIndex++
			},
		},
		{
			name: "commitment_root",
			mutate: func(f *selectiveDisclosureLayerFixture) {
				f.roots[0][0] ^= 0x01
			},
		},
		{
			name: "proof_hash",
			mutate: func(f *selectiveDisclosureLayerFixture) {
				f.multiproofs[0].ProofNodes[0].Hash[0] ^= 0x01
			},
		},
		{
			name: "proof_position",
			mutate: func(f *selectiveDisclosureLayerFixture) {
				f.multiproofs[0].ProofNodes[0].Index++
			},
		},
		{
			name: "missing_required_field",
			mutate: func(f *selectiveDisclosureLayerFixture) {
				f.multiproofs[0].Indices = f.multiproofs[0].Indices[1:]
				f.multiproofs[0].Openings = f.multiproofs[0].Openings[1:]
			},
		},
		{
			name: "wrong_field_index",
			mutate: func(f *selectiveDisclosureLayerFixture) {
				f.multiproofs[0].Openings[0].FieldIndex++
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tampered := cloneSelectiveDisclosureLayerFixtureForTest(t, f)
			tc.mutate(&tampered)
			if err := validateSelectiveDisclosureLayerMultiproofFixture(tampered); err == nil {
				t.Fatal("tampered selective multiproof unexpectedly validated")
			}
		})
	}
}

func cloneDisclosureMapForTest(t *testing.T, in map[int]*sd.Disclosure) map[int]*sd.Disclosure {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out map[int]*sd.Disclosure
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func cloneSelectiveDisclosureLayerFixtureForTest(t *testing.T, in selectiveDisclosureLayerFixture) selectiveDisclosureLayerFixture {
	t.Helper()
	out := in
	out.roots = cloneByteMapForTest(in.roots)
	out.evidence = cloneOpeningsMapForTest(t, in.evidence)
	out.disclosures = cloneDisclosureMapForTest(t, in.disclosures)
	out.multiproofs = cloneMultiProofMapForTest(t, in.multiproofs)
	out.requiredTags = append([]string(nil), in.requiredTags...)
	return out
}

func cloneByteMapForTest(in map[int][]byte) map[int][]byte {
	out := make(map[int][]byte, len(in))
	for k, v := range in {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

func cloneOpeningsMapForTest(t *testing.T, in map[int][]sd.FieldOpening) map[int][]sd.FieldOpening {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out map[int][]sd.FieldOpening
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func cloneMultiProofMapForTest(t *testing.T, in map[int]*sd.MerkleMultiProofDisclosure) map[int]*sd.MerkleMultiProofDisclosure {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out map[int]*sd.MerkleMultiProofDisclosure
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTransparentPayloadSizeMetrics(t *testing.T) {
	scenario := codeMaintenanceScenario()
	regular := buildPACTScenarioFixture(pact.ModeSchoCo, scenario)
	transparent := buildTransparentPayloadScenarioFixture(pact.ModeSchoCo, scenario)
	sizes, err := pactPresentationSizeMetrics(regular, &transparent)
	if err != nil {
		t.Fatalf("compute presentation sizes: %v", err)
	}

	if sizes.TokenBytes != len(regular.token) {
		t.Fatalf("token_bytes = %d, want %d", sizes.TokenBytes, len(regular.token))
	}
	if sizes.TransparentPayloadTokenBytes != len(transparent.token) || sizes.TransparentPayloadTokenBytes == 0 {
		t.Fatalf("transparent_payload_token_bytes = %d, want token length %d", sizes.TransparentPayloadTokenBytes, len(transparent.token))
	}
	if sizes.TokenPlusEvidenceBytes <= sizes.TokenBytes {
		t.Fatal("token_plus_evidence_bytes should include evidence bytes")
	}
	if sizes.TokenPlusDisclosureBytes <= sizes.TokenBytes {
		t.Fatal("token_plus_disclosure_bytes should include disclosure bytes")
	}
}

func TestTransparentPayloadDoesNotCountEvidenceOrDisclosure(t *testing.T) {
	scenario := dataProcessingScenario()
	regular := buildPACTScenarioFixture(pact.ModeSchoCo, scenario)
	transparent := buildTransparentPayloadScenarioFixture(pact.ModeSchoCo, scenario)
	sizes, err := pactPresentationSizeMetrics(regular, &transparent)
	if err != nil {
		t.Fatalf("compute presentation sizes: %v", err)
	}

	if transparent.evidence != nil {
		t.Fatal("transparent payload fixture should not carry complete evidence")
	}
	if transparent.disclosure != nil {
		t.Fatal("transparent payload fixture should not carry selective disclosures")
	}
	if sizes.TransparentPayloadTokenBytes != len(transparent.token) {
		t.Fatal("transparent payload size should count only the signed token")
	}
	if sizes.TransparentPayloadTokenBytes == sizes.TokenPlusEvidenceBytes || sizes.TransparentPayloadTokenBytes == sizes.TokenPlusDisclosureBytes {
		t.Fatal("transparent payload size should be independent from Token+E and Token+D package sizes")
	}
}

func TestTokenEvidenceAndDisclosureMetricsRemainSeparate(t *testing.T) {
	scenario := dataProcessingScenario()
	regular := buildPACTScenarioFixture(pact.ModeSchoCo, scenario)
	transparent := buildTransparentPayloadScenarioFixture(pact.ModeSchoCo, scenario)
	sizes, err := pactPresentationSizeMetrics(regular, &transparent)
	if err != nil {
		t.Fatalf("compute presentation sizes: %v", err)
	}
	evBytes, err := json.Marshal(regular.evidence)
	if err != nil {
		t.Fatal(err)
	}
	discBytes, err := json.Marshal(regular.disclosure)
	if err != nil {
		t.Fatal(err)
	}

	if sizes.TokenPlusEvidenceBytes != len(regular.token)+len(evBytes) {
		t.Fatal("Token+E metric changed unexpectedly")
	}
	if sizes.TokenPlusDisclosureBytes != len(regular.token)+len(discBytes) {
		t.Fatal("Token+D metric changed unexpectedly")
	}
}

func TestTransparentPayloadWorkflowValidationRejectsInvalidState(t *testing.T) {
	scenario := codeMaintenanceScenario()
	claims := cloneClaimSets(scenario.claims)
	claims[5]["branch"] = "feature/wrong-prefix"
	badScenario := pactScenario{
		name:                scenario.name,
		tid:                 scenario.tid,
		claims:              claims,
		transparentRelation: scenario.transparentRelation,
	}
	transparent := buildTransparentPayloadScenarioFixture(pact.ModeSchoCo, badScenario)
	opts := validationOptions(transparent, nil, nil, badScenario.transparentRelation, transparent.rc)

	if _, err := pact.ValidatePACT(transparent.token, transparent.mode, opts); err == nil {
		t.Fatal("expected transparent payload relation to reject invalid branch")
	}
}

func TestJWSReissuedCodeMaintenanceBranchValidatesSignedClaims(t *testing.T) {
	f := newJWSCodeMaintenanceBranchFixture()
	if err := validateJWSCodeMaintenanceBranchFixture(f); err != nil {
		t.Fatalf("JWS-reissued CodeMaintenanceBranch should validate: %v", err)
	}

	f.repository[4] = issueJWSToken(f.issuer, map[string]interface{}{
		"task_id":          taskID,
		"repo":             repo,
		"issue_id":         issueID,
		"artifact.release": true,
		"diff_hash":        diffHash,
		"test_log_hash":    "wrong-test-log",
		"artifact_hash":    artifactHash,
		"branch":           branchPrefix + "-empty-project-id",
		"test_result":      "passed",
		"status":           "ok",
	})
	if err := validateJWSCodeMaintenanceBranchFixture(f); err == nil {
		t.Fatal("JWS-reissued CodeMaintenanceBranch accepted inconsistent signed claims")
	}
}

func TestCodeMaintenanceBranchPresentationProfilesValidate(t *testing.T) {
	for _, tc := range pactModes() {
		tc := tc
		t.Run(tc.name+"/transparent", func(t *testing.T) {
			f := buildCodeMaintenanceBranchTransparentFixture(tc.mode)
			if err := validateCodeMaintenanceBranchTransparentFixture(f); err != nil {
				t.Fatalf("transparent CodeMaintenanceBranch should validate: %v", err)
			}
		})
		t.Run(tc.name+"/complete", func(t *testing.T) {
			f := buildCodeMaintenanceBranchFixture(tc.mode)
			if err := validateCodeMaintenanceBranchFixture(f); err != nil {
				t.Fatalf("complete CodeMaintenanceBranch should validate: %v", err)
			}
		})
		t.Run(tc.name+"/selective", func(t *testing.T) {
			f := buildCodeMaintenanceBranchSelectiveFixture(tc.mode)
			if err := validateCodeMaintenanceBranchSelectiveFixture(f); err != nil {
				t.Fatalf("selective CodeMaintenanceBranch should validate: %v", err)
			}
		})
	}
}

func TestCodeMaintenanceSelectivePresentationRejectsMissingRequiredField(t *testing.T) {
	f := buildCodeMaintenanceBranchSelectiveFixture(pact.ModeSchoCo)
	removeDisclosureOpening(t, f.repository.disclosure[4], "artifact_hash")
	if err := validateCodeMaintenanceBranchSelectiveFixture(f); err == nil {
		t.Fatal("selective CodeMaintenanceBranch accepted a missing required final field")
	}
}

func TestCodeMaintenanceIssuerInteractionCounts(t *testing.T) {
	if got := codeMaintenanceJWSStaticTokenCount; got != 1 {
		t.Fatalf("JWS-static issuer interactions = %d, want 1", got)
	}
	if got := codeMaintenanceJWSReissuedTokens; got != 11 {
		t.Fatalf("JWS-reissued issuer interactions = %d, want 11", got)
	}
	if got := codeMaintenancePACTIssuerRoots; got != 3 {
		t.Fatalf("PACT issuer interactions = %d, want 3", got)
	}
}

func removeDisclosureOpening(t *testing.T, d *sd.Disclosure, tag string) {
	t.Helper()
	if d == nil {
		t.Fatal("nil disclosure")
	}
	for i, opening := range d.Openings {
		if opening.Tag == tag {
			d.Openings = append(d.Openings[:i], d.Openings[i+1:]...)
			return
		}
	}
	t.Fatalf("opening %q not found", tag)
}

func issuePACTRoot(mode int8, tid string, claims map[string]interface{}) string {
	switch mode {
	case pact.ModeID:
		issuer, signers := newIDKeys(1)
		root := rootIDPayload(issuer, signers, tid)
		evidence := &pact.Evidence{NodeOpenings: map[int][]sd.FieldOpening{}}
		disclosures := map[int]*sd.Disclosure{}
		attachNode(root, tid, 0, claims, evidence, disclosures, 0.5)
		token, err := pact.CreateJWS(root, pact.ModeID, issuer)
		if err != nil {
			panic(err)
		}
		return token
	case pact.ModeSchoCo:
		sk, pk, err := schoco.KeyPair()
		if err != nil {
			panic(err)
		}
		root := rootSchoCoPayload(pk.Bytes(), tid)
		evidence := &pact.Evidence{NodeOpenings: map[int][]sd.FieldOpening{}}
		disclosures := map[int]*sd.Disclosure{}
		attachNode(root, tid, 0, claims, evidence, disclosures, 0.5)
		token, err := pact.CreateJWS(root, pact.ModeSchoCo, sk)
		if err != nil {
			panic(err)
		}
		return token
	default:
		panic("unknown PACT mode")
	}
}

func extendPACTOnce(f pactFixture, nodeIndex int, claims map[string]interface{}) string {
	return extendPACTOnceWithClaims(f, nodeIndex, claims, 0.5)
}

func extendPACTOnceWithClaims(f pactFixture, nodeIndex int, claims map[string]interface{}, disclosureRatio float64) string {
	node := &pact.Payload{
		Ver:       f.mode,
		TID0:      f.tid,
		NodeIndex: nodeIndex,
		Iat:       benchNow.Unix(),
		Iss:       &pact.IDClaim{CN: "bench-next"},
	}
	evidence := &pact.Evidence{NodeOpenings: map[int][]sd.FieldOpening{}}
	disclosures := map[int]*sd.Disclosure{}
	if f.mode == pact.ModeID {
		node.Iss.PK = pkix(&f.nextIDKey.PublicKey)
	}
	attachNode(node, f.tid, nodeIndex, claims, evidence, disclosures, disclosureRatio)
	var (
		token string
		err   error
	)
	if f.mode == pact.ModeID {
		token, err = pact.ExtendJWS(f.token, &pact.LDNode{Payload: node}, pact.ModeID, f.nextIDKey)
	} else {
		token, err = pact.ExtendJWS(f.token, &pact.LDNode{Payload: node}, pact.ModeSchoCo)
	}
	if err != nil {
		panic(err)
	}
	return token
}

func newJWSFixture(tokens int) jwsFixture {
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	claimSets := workflowClaimSets()
	out := jwsFixture{issuer: issuer, tokens: make([]string, 0, tokens)}
	for i := 0; i < tokens; i++ {
		out.tokens = append(out.tokens, issueJWSToken(issuer, claimSets[i%len(claimSets)]))
	}
	return out
}

func newJWSStaticCodeMaintenanceFixture() jwsCodeMaintenanceStaticFixture {
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return jwsCodeMaintenanceStaticFixture{
		issuer: issuer,
		token:  issueJWSToken(issuer, finalArtifactClaims(patchHash, diffHash, testLogHash)),
	}
}

func validateJWSStaticCodeMaintenanceFixture(f jwsCodeMaintenanceStaticFixture) error {
	claims, err := validateJWSTokenClaims(f.token, f.issuer)
	if err != nil {
		return err
	}
	for _, key := range []string{"patch_hash", "diff_hash", "test_log_hash", "artifact_hash", "branch"} {
		if stringClaim(claims, key) == "" {
			return fmt.Errorf("final artifact missing %s", key)
		}
	}
	if !boolClaim(claims, "artifact.release") {
		return fmt.Errorf("final artifact token lacks artifact.release")
	}
	if stringClaim(claims, "test_result") != "passed" || stringClaim(claims, "status") != "ok" {
		return fmt.Errorf("final artifact token is not a passed release")
	}
	if !strings.HasPrefix(stringClaim(claims, "branch"), branchPrefix) {
		return fmt.Errorf("final artifact branch prefix mismatch")
	}
	return nil
}

func newJWSCodeMaintenanceBranchFixture() jwsCodeMaintenanceBranchFixture {
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return jwsCodeMaintenanceBranchFixture{
		issuer:     issuer,
		context:    issueJWSTokens(issuer, contextBranchClaimSets()),
		patch:      issueJWSTokens(issuer, patchBranchClaimSets()),
		repository: issueJWSTokens(issuer, repositoryBranchClaimSets()),
	}
}

func issueJWSTokens(issuer *ecdsa.PrivateKey, claimSets []map[string]interface{}) []string {
	tokens := make([]string, 0, len(claimSets))
	for _, claims := range claimSets {
		tokens = append(tokens, issueJWSToken(issuer, claims))
	}
	return tokens
}

func validateJWSCodeMaintenanceBranchFixture(f jwsCodeMaintenanceBranchFixture) error {
	contextNodes, err := validateJWSBranchClaims(f.context, f.issuer)
	if err != nil {
		return fmt.Errorf("context branch validation failed: %w", err)
	}
	patchNodes, err := validateJWSBranchClaims(f.patch, f.issuer)
	if err != nil {
		return fmt.Errorf("patch branch validation failed: %w", err)
	}
	repoNodes, err := validateJWSBranchClaims(f.repository, f.issuer)
	if err != nil {
		return fmt.Errorf("repository branch validation failed: %w", err)
	}
	return evaluateCodeMaintenanceBranches(contextNodes, patchNodes, repoNodes)
}

func validateJWSBranchClaims(tokens []string, issuer *ecdsa.PrivateKey) (map[int]map[string]interface{}, error) {
	nodes := map[int]map[string]interface{}{}
	for i, token := range tokens {
		claims, err := validateJWSTokenClaims(token, issuer)
		if err != nil {
			return nil, err
		}
		nodes[i] = claims
	}
	return nodes, nil
}

func issueJWSToken(issuer *ecdsa.PrivateKey, claims map[string]interface{}) string {
	jwtClaims := jwt.MapClaims{}
	for k, v := range claims {
		jwtClaims[k] = v
	}
	jwtClaims["iat"] = benchNow.Unix()
	jwtClaims["iss"] = "authorization-server"
	token, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwtClaims).SignedString(issuer)
	if err != nil {
		panic(err)
	}
	return token
}

func validateJWSToken(token string, issuer *ecdsa.PrivateKey) error {
	_, err := validateJWSTokenClaims(token, issuer)
	return err
}

func validateJWSTokenClaims(token string, issuer *ecdsa.PrivateKey) (map[string]interface{}, error) {
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodES256 {
			return nil, fmt.Errorf("unexpected alg %s", t.Method.Alg())
		}
		return &issuer.PublicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !parsed.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	for _, key := range []string{"task_id", "repo", "issue_id"} {
		if _, ok := claims[key].(string); !ok {
			return nil, fmt.Errorf("missing claim %s", key)
		}
	}
	out := make(map[string]interface{}, len(claims))
	for key, value := range claims {
		out[key] = value
	}
	return out, nil
}

func pactPresentationSizeMetrics(f pactFixture, transparent *pactFixture) (pactPresentationSizes, error) {
	evBytes, err := json.Marshal(f.evidence)
	if err != nil {
		return pactPresentationSizes{}, err
	}
	discBytes, err := json.Marshal(f.disclosure)
	if err != nil {
		return pactPresentationSizes{}, err
	}
	rcBytes, err := json.Marshal(f.rc)
	if err != nil {
		return pactPresentationSizes{}, err
	}
	sizes := pactPresentationSizes{
		TokenBytes:                len(f.token),
		FullEvidenceBytes:         len(evBytes),
		SelectiveDisclosureBytes:  len(discBytes),
		TokenPlusEvidenceBytes:    len(f.token) + len(evBytes),
		TokenPlusDisclosureBytes:  len(f.token) + len(discBytes),
		RevocationCheckpointBytes: len(rcBytes),
	}
	if transparent != nil {
		sizes.TransparentPayloadTokenBytes = len(transparent.token)
	}
	return sizes, nil
}

func reportPACTSizeMetrics(b *testing.B, f pactFixture) {
	reportPACTSizeMetricsWithTransparent(b, f, nil)
}

func reportPACTSizeMetricsWithTransparent(b *testing.B, f pactFixture, transparent *pactFixture) {
	b.Helper()
	sizes, err := pactPresentationSizeMetrics(f, transparent)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(sizes.TokenBytes), "token_bytes")
	b.ReportMetric(float64(sizes.FullEvidenceBytes), "full_evidence_bytes")
	b.ReportMetric(float64(sizes.SelectiveDisclosureBytes), "selective_disclosure_bytes")
	b.ReportMetric(float64(sizes.TokenPlusEvidenceBytes), "token_plus_evidence_bytes")
	b.ReportMetric(float64(sizes.TokenPlusDisclosureBytes), "token_plus_disclosure_bytes")
	if transparent != nil {
		b.ReportMetric(float64(sizes.TransparentPayloadTokenBytes), "transparent_payload_token_bytes")
	}
	b.ReportMetric(float64(sizes.RevocationCheckpointBytes), "checkpoint_bytes")
}

func reportCodeMaintenanceBranchMetrics(b *testing.B, f codeMaintenanceBranchFixture) {
	b.Helper()
	contextPresentation := presentationBytes(f.context)
	patchPresentation := presentationBytes(f.patch)
	repositoryPresentation := presentationBytes(f.repository)
	jointBytes, err := json.Marshal(map[string]interface{}{
		"context": map[string]interface{}{
			"token":    f.context.token,
			"evidence": f.context.evidence,
		},
		"patch": map[string]interface{}{
			"token":    f.patch.token,
			"evidence": f.patch.evidence,
		},
		"repository": map[string]interface{}{
			"token":    f.repository.token,
			"evidence": f.repository.evidence,
		},
		"revocation_checkpoint": f.rc,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(3, "branch_count")
	b.ReportMetric(3, "context_branch_nodes")
	b.ReportMetric(3, "patch_branch_nodes")
	b.ReportMetric(5, "repository_branch_nodes")
	b.ReportMetric(11, "authenticated_nodes_repeated_root")
	b.ReportMetric(9, "unique_logical_nodes")
	b.ReportMetric(float64(len(f.context.token)), "context_branch_token_bytes")
	b.ReportMetric(float64(len(f.patch.token)), "patch_branch_token_bytes")
	b.ReportMetric(float64(len(f.repository.token)), "repository_branch_token_bytes")
	b.ReportMetric(float64(contextPresentation), "context_branch_presentation_bytes")
	b.ReportMetric(float64(patchPresentation), "patch_branch_presentation_bytes")
	b.ReportMetric(float64(repositoryPresentation), "repository_branch_presentation_bytes")
	b.ReportMetric(float64(len(jointBytes)), "joint_presentation_bytes")
	if f.rc != nil {
		rcBytes, _ := json.Marshal(f.rc)
		b.ReportMetric(float64(len(rcBytes)), "checkpoint_bytes")
	}
}

func presentationBytes(f pactFixture) int {
	evBytes, _ := json.Marshal(f.evidence)
	return len(f.token) + len(evBytes)
}

func reportCodeMaintenanceCommonMetrics(b *testing.B, issuerInteractions, authenticatedNodes int, tokenBytes, presentationBytes, checkpointBytes, packageBytes int) {
	b.Helper()
	b.ReportMetric(float64(codeMaintenanceBranchCount), "branch_count")
	b.ReportMetric(float64(codeMaintenanceContextBranchNodes), "context_branch_nodes")
	b.ReportMetric(float64(codeMaintenancePatchBranchNodes), "patch_branch_nodes")
	b.ReportMetric(float64(codeMaintenanceRepositoryNodes), "repository_branch_nodes")
	b.ReportMetric(float64(authenticatedNodes), "authenticated_nodes")
	b.ReportMetric(float64(authenticatedNodes), "authenticated_nodes_repeated_root")
	b.ReportMetric(float64(codeMaintenanceUniqueLogicalNodes), "unique_logical_nodes")
	b.ReportMetric(float64(issuerInteractions), "issuer_interactions")
	b.ReportMetric(float64(tokenBytes), "serialized_token_bytes")
	b.ReportMetric(float64(presentationBytes), "serialized_presentation_bytes")
	b.ReportMetric(float64(checkpointBytes), "checkpoint_bytes")
	b.ReportMetric(float64(tokenBytes+presentationBytes+checkpointBytes), "total_serialized_bytes_validated")
	if packageBytes > 0 {
		b.ReportMetric(float64(packageBytes), "serialized_package_bytes")
	}
}

func reportJWSStaticCodeMaintenanceMetrics(b *testing.B, f jwsCodeMaintenanceStaticFixture) {
	b.Helper()
	reportCodeMaintenanceCommonMetrics(b, codeMaintenanceJWSStaticTokenCount, 1, len(f.token), 0, 0, len(f.token))
}

func reportJWSReissuedCodeMaintenanceMetrics(b *testing.B, f jwsCodeMaintenanceBranchFixture) {
	b.Helper()
	tokenBytes := sumStringLens(f.context) + sumStringLens(f.patch) + sumStringLens(f.repository)
	packageBytes := jsonLen(map[string]interface{}{
		"context":    f.context,
		"patch":      f.patch,
		"repository": f.repository,
	})
	reportCodeMaintenanceCommonMetrics(b, codeMaintenanceJWSReissuedTokens, codeMaintenanceAuthenticatedNodes, tokenBytes, 0, 0, packageBytes)
}

func reportPACTCodeMaintenanceMetrics(b *testing.B, f codeMaintenanceBranchFixture, profile string) {
	b.Helper()
	tokenBytes := len(f.context.token) + len(f.patch.token) + len(f.repository.token)
	checkpointBytes := jsonLen(f.rc)
	presentationBytes := 0
	packageValue := map[string]interface{}{
		"revocation_checkpoint": f.rc,
	}
	switch profile {
	case "transparent":
		packageValue["context"] = map[string]interface{}{"token": f.context.token}
		packageValue["patch"] = map[string]interface{}{"token": f.patch.token}
		packageValue["repository"] = map[string]interface{}{"token": f.repository.token}
	case "complete":
		contextEvidenceBytes := jsonLen(f.context.evidence)
		patchEvidenceBytes := jsonLen(f.patch.evidence)
		repositoryEvidenceBytes := jsonLen(f.repository.evidence)
		presentationBytes = contextEvidenceBytes + patchEvidenceBytes + repositoryEvidenceBytes
		b.ReportMetric(float64(contextEvidenceBytes), "context_branch_evidence_bytes")
		b.ReportMetric(float64(patchEvidenceBytes), "patch_branch_evidence_bytes")
		b.ReportMetric(float64(repositoryEvidenceBytes), "repository_branch_evidence_bytes")
		packageValue["context"] = map[string]interface{}{"token": f.context.token, "evidence": f.context.evidence}
		packageValue["patch"] = map[string]interface{}{"token": f.patch.token, "evidence": f.patch.evidence}
		packageValue["repository"] = map[string]interface{}{"token": f.repository.token, "evidence": f.repository.evidence}
	case "selective":
		contextDisclosureBytes := jsonLen(f.context.disclosure)
		patchDisclosureBytes := jsonLen(f.patch.disclosure)
		repositoryDisclosureBytes := jsonLen(f.repository.disclosure)
		presentationBytes = contextDisclosureBytes + patchDisclosureBytes + repositoryDisclosureBytes
		b.ReportMetric(float64(contextDisclosureBytes), "context_branch_disclosure_bytes")
		b.ReportMetric(float64(patchDisclosureBytes), "patch_branch_disclosure_bytes")
		b.ReportMetric(float64(repositoryDisclosureBytes), "repository_branch_disclosure_bytes")
		packageValue["context"] = map[string]interface{}{"token": f.context.token, "disclosure": f.context.disclosure}
		packageValue["patch"] = map[string]interface{}{"token": f.patch.token, "disclosure": f.patch.disclosure}
		packageValue["repository"] = map[string]interface{}{"token": f.repository.token, "disclosure": f.repository.disclosure}
	default:
		b.Fatalf("unknown CodeMaintenance profile %q", profile)
	}
	b.ReportMetric(float64(len(f.context.token)), "context_branch_token_bytes")
	b.ReportMetric(float64(len(f.patch.token)), "patch_branch_token_bytes")
	b.ReportMetric(float64(len(f.repository.token)), "repository_branch_token_bytes")
	reportCodeMaintenanceCommonMetrics(b, codeMaintenancePACTIssuerRoots, codeMaintenanceAuthenticatedNodes, tokenBytes, presentationBytes, checkpointBytes, jsonLen(packageValue))
}

func sumStringLens(values []string) int {
	total := 0
	for _, value := range values {
		total += len(value)
	}
	return total
}

func jsonLen(v interface{}) int {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return len(b)
}

func validateRequiredOpenings(nodeIndex int, openings []sd.FieldOpening, required []string) error {
	if len(openings) != len(required) {
		return fmt.Errorf("node %d disclosed %d fields, want %d", nodeIndex, len(openings), len(required))
	}
	seen := make(map[string]bool, len(openings))
	for _, opening := range openings {
		if opening.NodeIndex != nodeIndex {
			return fmt.Errorf("node %d opening %s has node index %d", nodeIndex, opening.Tag, opening.NodeIndex)
		}
		seen[opening.Tag] = true
	}
	for _, tag := range required {
		if !seen[tag] {
			return fmt.Errorf("node %d missing disclosed field %s", nodeIndex, tag)
		}
	}
	return nil
}

func validateCompleteEvidenceLayerFixture(f selectiveDisclosureLayerFixture) error {
	required := selectiveDisclosureRequiredTags(f.fieldsPerNode)
	for nodeIndex := 0; nodeIndex < f.depthK; nodeIndex++ {
		openings, ok := f.evidence[nodeIndex]
		if !ok {
			return fmt.Errorf("missing evidence for node %d", nodeIndex)
		}
		if err := validateRequiredOpenings(nodeIndex, openings, required); err != nil {
			return err
		}
		commitments, err := sd.OpeningsToCommitments(openings)
		if err != nil {
			return err
		}
		root, err := sd.MerkleRoot(commitments)
		if err != nil {
			return err
		}
		if !bytes.Equal(root, f.roots[nodeIndex]) {
			return fmt.Errorf("evidence root mismatch for node %d", nodeIndex)
		}
	}
	return nil
}

func validateSelectiveDisclosureLayerFixture(f selectiveDisclosureLayerFixture) error {
	for nodeIndex := 0; nodeIndex < f.depthK; nodeIndex++ {
		disclosure, ok := f.disclosures[nodeIndex]
		if !ok || disclosure == nil {
			return fmt.Errorf("missing disclosure for node %d", nodeIndex)
		}
		if err := validateRequiredOpenings(nodeIndex, disclosure.Openings, f.requiredTags); err != nil {
			return err
		}
		okv, err := sd.VerifyDisclosure(disclosure)
		if err != nil || !okv {
			return fmt.Errorf("disclosure verification failed for node %d: %v", nodeIndex, err)
		}
		if !bytes.Equal(disclosure.Root, f.roots[nodeIndex]) {
			return fmt.Errorf("disclosure root mismatch for node %d", nodeIndex)
		}
	}
	return nil
}

func validateSelectiveDisclosureLayerMultiproofFixture(f selectiveDisclosureLayerFixture) error {
	for nodeIndex := 0; nodeIndex < f.depthK; nodeIndex++ {
		multiproof, ok := f.multiproofs[nodeIndex]
		if !ok || multiproof == nil {
			return fmt.Errorf("missing multiproof disclosure for node %d", nodeIndex)
		}
		if err := validateRequiredOpenings(nodeIndex, multiproof.Openings, f.requiredTags); err != nil {
			return err
		}
		root, ok := f.roots[nodeIndex]
		if !ok {
			return fmt.Errorf("missing root for node %d", nodeIndex)
		}
		if err := sd.VerifyMerkleMultiProofDisclosureAgainstRoot(multiproof, root); err != nil {
			return fmt.Errorf("multiproof verification failed for node %d: %v", nodeIndex, err)
		}
	}
	return nil
}

func pactModes() []struct {
	name string
	mode int8
} {
	return []struct {
		name string
		mode int8
	}{
		{"ID_ECDSA", pact.ModeID},
		{"SchoCo", pact.ModeSchoCo},
	}
}

func BenchmarkJWSStatic(b *testing.B) {
	b.Run("Operation/Issue", func(b *testing.B) {
		issuer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		claims := rootClaims()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchSink = issueJWSToken(issuer, claims)
		}
	})
	b.Run("Operation/Validate", func(b *testing.B) {
		f := newJWSFixture(1)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := validateJWSToken(f.tokens[0], f.issuer); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Operation/Size", func(b *testing.B) {
		f := newJWSFixture(1)
		b.ReportMetric(float64(len(f.tokens[0])), "token_bytes")
		for i := 0; i < b.N; i++ {
			benchSink = len(f.tokens[0])
		}
	})
	b.Run("CodeMaintenanceBranch/FinalArtifactLowerBound/Validate", func(b *testing.B) {
		f := newJWSStaticCodeMaintenanceFixture()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := validateJWSStaticCodeMaintenanceFixture(f); err != nil {
				b.Fatal(err)
			}
		}
		reportJWSStaticCodeMaintenanceMetrics(b, f)
	})
}

func BenchmarkJWSReissued(b *testing.B) {
	const n = workflowSteps
	b.Run("LinearSixState/Issue/N=6", func(b *testing.B) {
		issuer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		claimSets := workflowClaimSets()
		b.ReportMetric(float64(n), "issuer_interactions")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tokens := make([]string, 0, n)
			for j := 0; j < n; j++ {
				tokens = append(tokens, issueJWSToken(issuer, claimSets[j]))
			}
			benchSink = tokens
		}
	})
	b.Run("LinearSixState/Validate/N=6", func(b *testing.B) {
		f := newJWSFixture(n)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for _, token := range f.tokens {
				if err := validateJWSToken(token, f.issuer); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run("LinearSixState/Bytes/N=6", func(b *testing.B) {
		f := newJWSFixture(n)
		total := 0
		for _, token := range f.tokens {
			total += len(token)
		}
		b.ReportMetric(float64(total), "workflow_bytes")
		b.ReportMetric(float64(n), "issuer_interactions")
		for i := 0; i < b.N; i++ {
			benchSink = total
		}
	})
	b.Run("CodeMaintenanceBranch/ReissuedBranchStates/Validate", func(b *testing.B) {
		f := newJWSCodeMaintenanceBranchFixture()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := validateJWSCodeMaintenanceBranchFixture(f); err != nil {
				b.Fatal(err)
			}
		}
		reportJWSReissuedCodeMaintenanceMetrics(b, f)
	})
}

func BenchmarkPACTOperation(b *testing.B) {
	for _, tc := range pactModes() {
		tc := tc
		b.Run(tc.name, func(b *testing.B) {
			b.Run("IssueRoot", func(b *testing.B) {
				claims := rootClaims()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					benchSink = issuePACTRoot(tc.mode, taskID, claims)
				}
			})
			b.Run("ExtendOneFromRoot", func(b *testing.B) {
				f := buildPACTScalingFixture(tc.mode, 0, 8, 0.5)
				claims := syntheticClaimsWithTID(f.tid, 1, 8)
				b.ReportMetric(0.0, "depth_k")
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					benchSink = extendPACTOnceWithClaims(f, 1, claims, 0.5)
				}
			})
			b.Run("ValidateRevocationCheckpoint", func(b *testing.B) {
				f := buildPACTWorkflowFixture(tc.mode)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if err := pact.ValidateRevocationCheckpoint(f.tid, f.rc, validationOptions(f, nil, nil, nil, f.rc)); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func BenchmarkPACTCodeMaintenance(b *testing.B) {
	for _, tc := range pactModes() {
		tc := tc
		b.Run(tc.name+"/TransparentPresentation/ValidateCodeMaintenanceJointBranches", func(b *testing.B) {
			f := buildCodeMaintenanceBranchTransparentFixture(tc.mode)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := validateCodeMaintenanceBranchTransparentFixture(f); err != nil {
					b.Fatal(err)
				}
			}
			reportPACTCodeMaintenanceMetrics(b, f, "transparent")
		})
		b.Run(tc.name+"/CompletePresentation/ValidateCodeMaintenanceJointBranches", func(b *testing.B) {
			f := buildCodeMaintenanceBranchFixture(tc.mode)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := validateCodeMaintenanceBranchFixture(f); err != nil {
					b.Fatal(err)
				}
			}
			reportPACTCodeMaintenanceMetrics(b, f, "complete")
		})
		b.Run(tc.name+"/SelectivePresentation/ValidateCodeMaintenanceJointBranches", func(b *testing.B) {
			f := buildCodeMaintenanceBranchSelectiveFixture(tc.mode)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := validateCodeMaintenanceBranchSelectiveFixture(f); err != nil {
					b.Fatal(err)
				}
			}
			reportPACTCodeMaintenanceMetrics(b, f, "selective")
		})
	}
}

func BenchmarkPACTScenario(b *testing.B) {
	scenario := dataProcessingScenario()
	for _, tc := range pactModes() {
		tc := tc
		b.Run("DataProcessingLinear/"+tc.name+"/ValidateCompletePresentation", func(b *testing.B) {
			f := buildPACTScenarioFixture(tc.mode, scenario)
			transparent := buildTransparentPayloadScenarioFixture(tc.mode, scenario)
			opts := validationOptions(f, f.evidence, nil, scenario.relation, f.rc)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := pact.ValidatePACT(f.token, tc.mode, opts); err != nil {
					b.Fatal(err)
				}
			}
			reportPACTSizeMetricsWithTransparent(b, f, &transparent)
		})
		b.Run("DataProcessingLinear/"+tc.name+"/ValidateTransparentPresentation", func(b *testing.B) {
			f := buildPACTScenarioFixture(tc.mode, scenario)
			transparent := buildTransparentPayloadScenarioFixture(tc.mode, scenario)
			opts := validationOptions(transparent, nil, nil, scenario.transparentRelation, transparent.rc)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := pact.ValidatePACT(transparent.token, tc.mode, opts); err != nil {
					b.Fatal(err)
				}
			}
			reportPACTSizeMetricsWithTransparent(b, f, &transparent)
		})
		b.Run("DataProcessingLinear/"+tc.name+"/ValidateSelectivePresentation", func(b *testing.B) {
			f := buildPACTScenarioFixture(tc.mode, scenario)
			transparent := buildTransparentPayloadScenarioFixture(tc.mode, scenario)
			opts := validationOptions(f, nil, f.disclosure, nil, f.rc)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := pact.ValidatePACT(f.token, tc.mode, opts); err != nil {
					b.Fatal(err)
				}
			}
			reportPACTSizeMetricsWithTransparent(b, f, &transparent)
		})
	}
}

func BenchmarkPACTDepthScaling(b *testing.B) {
	for _, tc := range pactModes() {
		tc := tc
		for _, k := range crossoverDepths {
			k := k
			prefix := "SyntheticLinear/" + tc.name + "/k=" + strconv.Itoa(k)
			b.Run(prefix+"/ValidateChain", func(b *testing.B) {
				f := buildPACTScalingFixture(tc.mode, k, 8, 0.5)
				opts := validationOptions(f, nil, nil, nil, nil)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := pact.ValidatePACT(f.token, tc.mode, opts); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run(prefix+"/ValidateTokenPlusEvidence", func(b *testing.B) {
				f := buildPACTScalingFixture(tc.mode, k, 8, 0.5)
				opts := validationOptions(f, f.evidence, nil, nil, nil)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := pact.ValidatePACT(f.token, tc.mode, opts); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run(prefix+"/ValidateTokenPlusDisclosure", func(b *testing.B) {
				f := buildPACTScalingFixture(tc.mode, k, 8, 0.5)
				opts := validationOptions(f, nil, f.disclosure, nil, nil)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := pact.ValidatePACT(f.token, tc.mode, opts); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run(prefix+"/ExtendOneAtDepthK", func(b *testing.B) {
				f := buildPACTScalingFixture(tc.mode, k, 8, 0.5)
				claims := syntheticClaimsWithTID(f.tid, k+1, 8)
				b.ReportMetric(float64(k), "depth_k")
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					benchSink = extendPACTOnceWithClaims(f, k+1, claims, 0.5)
				}
			})
			b.Run(prefix+"/SizeToken", func(b *testing.B) {
				f := buildPACTScalingFixture(tc.mode, k, 8, 0.5)
				tokenBytes := len(f.token)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					benchSink = tokenBytes
				}
				b.ReportMetric(float64(tokenBytes), "token_bytes")
			})
			b.Run(prefix+"/SizeTokenPlusEvidence", func(b *testing.B) {
				f := buildPACTScalingFixture(tc.mode, k, 8, 0.5)
				evBytes, err := json.Marshal(f.evidence)
				if err != nil {
					b.Fatal(err)
				}
				fullEvidenceBytes := len(evBytes)
				tokenPlusEvidenceBytes := len(f.token) + fullEvidenceBytes
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					benchSink = fullEvidenceBytes
				}
				b.ReportMetric(float64(fullEvidenceBytes), "full_evidence_bytes")
				b.ReportMetric(float64(tokenPlusEvidenceBytes), "token_plus_evidence_bytes")
			})
			b.Run(prefix+"/SizeTokenPlusDisclosure", func(b *testing.B) {
				f := buildPACTScalingFixture(tc.mode, k, 8, 0.5)
				discBytes, err := json.Marshal(f.disclosure)
				if err != nil {
					b.Fatal(err)
				}
				selectiveDisclosureBytes := len(discBytes)
				tokenPlusDisclosureBytes := len(f.token) + selectiveDisclosureBytes
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					benchSink = selectiveDisclosureBytes
				}
				b.ReportMetric(float64(selectiveDisclosureBytes), "selective_disclosure_bytes")
				b.ReportMetric(float64(tokenPlusDisclosureBytes), "token_plus_disclosure_bytes")
			})
		}
	}
}

func BenchmarkPACTDisclosureLayer(b *testing.B) {
	const (
		depthK        = 10
		fieldsPerNode = 8
	)
	complete := buildSelectiveDisclosureLayerFixture(depthK, fieldsPerNode, fieldsPerNode)
	completeBytes, err := json.Marshal(complete.evidence)
	if err != nil {
		b.Fatal(err)
	}
	b.Run(fmt.Sprintf("k=%d/fields=%d/open=%d/complete", depthK, fieldsPerNode, fieldsPerNode), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := validateCompleteEvidenceLayerFixture(complete); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportMetric(float64(depthK), "depth_k")
		b.ReportMetric(float64(fieldsPerNode), "fields_per_node")
		b.ReportMetric(float64(fieldsPerNode), "opened_fields_per_node")
		b.ReportMetric(float64(len(completeBytes)), "evidence_bytes")
	})

	for _, opened := range disclosureOpenings {
		opened := opened
		f := buildSelectiveDisclosureLayerFixture(depthK, fieldsPerNode, opened)
		disclosureBytes, err := json.Marshal(f.disclosures)
		if err != nil {
			b.Fatal(err)
		}
		multiproofBytes, err := json.Marshal(sd.MultiProofMapWithoutRoot(f.multiproofs))
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("k=%d/fields=%d/open=%d/selective-current", depthK, fieldsPerNode, opened), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := validateSelectiveDisclosureLayerFixture(f); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(depthK), "depth_k")
			b.ReportMetric(float64(fieldsPerNode), "fields_per_node")
			b.ReportMetric(float64(opened), "opened_fields_per_node")
			b.ReportMetric(float64(len(disclosureBytes)), "evidence_bytes")
		})
		b.Run(fmt.Sprintf("k=%d/fields=%d/open=%d/selective-multiproof", depthK, fieldsPerNode, opened), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := validateSelectiveDisclosureLayerMultiproofFixture(f); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(depthK), "depth_k")
			b.ReportMetric(float64(fieldsPerNode), "fields_per_node")
			b.ReportMetric(float64(opened), "opened_fields_per_node")
			b.ReportMetric(float64(len(multiproofBytes)), "evidence_bytes")
		})
	}
}

func BenchmarkPACTParameterScaling(b *testing.B) {
	for _, tc := range []struct {
		name string
		mode int8
	}{
		{"ID_ECDSA", pact.ModeID},
		{"SchoCo", pact.ModeSchoCo},
	} {
		tc := tc
		b.Run("ChainLength/"+tc.name, func(b *testing.B) {
			for _, k := range chainLengths {
				k := k
				b.Run("k="+strconv.Itoa(k), func(b *testing.B) {
					f := buildPACTScalingFixture(tc.mode, k, 8, 0.5)
					opts := validationOptions(f, f.evidence, nil, nil, nil)
					evBytes, _ := json.Marshal(f.evidence)
					b.ReportMetric(float64(len(f.token)), "token_bytes")
					b.ReportMetric(float64(len(evBytes)), "full_evidence_bytes")
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if _, err := pact.ValidatePACT(f.token, tc.mode, opts); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
		b.Run("FieldsPerNode/"+tc.name, func(b *testing.B) {
			for _, fields := range fieldsPerNodeVals {
				fields := fields
				b.Run("fields="+strconv.Itoa(fields), func(b *testing.B) {
					f := buildPACTScalingFixture(tc.mode, 4, fields, 0.5)
					opts := validationOptions(f, f.evidence, nil, nil, nil)
					evBytes, _ := json.Marshal(f.evidence)
					b.ReportMetric(float64(len(f.token)), "token_bytes")
					b.ReportMetric(float64(len(evBytes)), "full_evidence_bytes")
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if _, err := pact.ValidatePACT(f.token, tc.mode, opts); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
	b.Run("EvidenceKind/LinearSixState", func(b *testing.B) {
		for _, tc := range []struct {
			name string
			mode int8
		}{
			{"ID_ECDSA", pact.ModeID},
			{"SchoCo", pact.ModeSchoCo},
		} {
			tc := tc
			b.Run(tc.name+"/CompletePresentation", func(b *testing.B) {
				f := buildPACTWorkflowFixture(tc.mode)
				opts := validationOptions(f, f.evidence, nil, nil, nil)
				evBytes, _ := json.Marshal(f.evidence)
				b.ReportMetric(float64(len(evBytes)), "evidence_bytes")
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := pact.ValidatePACT(f.token, tc.mode, opts); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run(tc.name+"/SelectivePresentation", func(b *testing.B) {
				f := buildPACTWorkflowFixture(tc.mode)
				opts := validationOptions(f, nil, f.disclosure, nil, nil)
				discBytes, _ := json.Marshal(f.disclosure)
				b.ReportMetric(float64(len(discBytes)), "disclosure_bytes")
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := pact.ValidatePACT(f.token, tc.mode, opts); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	})
}
