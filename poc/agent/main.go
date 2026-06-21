package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"reflect"
	"time"

	"flow-poc/internal/workflow"
	pact "flow-poc/pact"
	sd "flow-poc/sd"

	"github.com/a2aproject/a2a-go/a2a"
	"github.com/a2aproject/a2a-go/a2asrv"
	"github.com/a2aproject/a2a-go/a2asrv/eventqueue"
)

type agentExecutor struct{}

type patchTokenArtifacts struct {
	Token      string
	Disclosure *sd.Disclosure
	Openings   []sd.FieldOpening
}

type agentRequest struct {
	JWS                  string                     `json:"jws"`
	Presentations        map[string]json.RawMessage `json:"presentations"`
	ContextHash          string                     `json:"context_hash"`
	RevocationCheckpoint *pact.RevocationCheckpoint `json:"revocation_checkpoint"`
}

const deterministicModelID = "deterministic-patch-agent"

func (e *agentExecutor) Execute(ctx context.Context, reqCtx *a2asrv.RequestContext, q eventqueue.Queue) error {
	// extract the JSON text sent by the caller, using robust reflection
	text, err := extractTextFromRequestContext(reqCtx)
	if err != nil {
		return writeError(ctx, q, "failed to extract incoming message: "+err.Error())
	}

	var req agentRequest
	if err := json.Unmarshal([]byte(text), &req); err != nil {
		return writeError(ctx, q, "invalid JSON: "+err.Error())
	}
	log.Println("[Agent] patch request received")

	// --- Convert presentations ---
	presMap := map[int]*sd.Disclosure{}
	for k, raw := range req.Presentations {
		var idx int
		if _, err := fmt.Sscanf(k, "%d", &idx); err != nil {
			return writeError(ctx, q, "invalid presentation index: "+k)
		}
		d, err := sd.FromJSON(raw)
		if err != nil {
			return writeError(ctx, q, "invalid presentation data for index "+k+": "+err.Error())
		}
		presMap[idx] = d
	}

	// --- Validate token ---
	now := time.Now()
	if req.RevocationCheckpoint == nil {
		return writeError(ctx, q, "missing revocation checkpoint")
	}
	if err := workflow.ValidateWithRevocation(req.JWS, nil, presMap, nil, req.RevocationCheckpoint, now); err != nil {
		return writeError(ctx, q, "token validation failed: "+fmt.Sprint(err))
	}

	// --- Authorization: AS node (node 0) ---
	asPres, ok := presMap[0]
	if !ok {
		return writeError(ctx, q, "missing AS presentation (index 0)")
	}
	rootClaims, err := workflow.ClaimsFromDisclosure(asPres)
	if err != nil {
		return writeError(ctx, q, "invalid AS disclosure: "+err.Error())
	}
	if workflow.StringClaim(rootClaims, "repo") != workflow.Repo || workflow.StringClaim(rootClaims, "issue_id") != workflow.IssueID {
		return writeError(ctx, q, "token is not bound to requested repo/issue")
	}

	// --- Authorization: patch branch scope (node 1) ---
	scopePres, ok := presMap[1]
	if !ok {
		return writeError(ctx, q, "missing patch-scope presentation (index 1)")
	}
	scopeClaims, err := workflow.ClaimsFromDisclosure(scopePres)
	if err != nil {
		return writeError(ctx, q, "invalid patch-scope disclosure: "+err.Error())
	}
	if workflow.StringClaim(scopeClaims, "branch_id") != workflow.BranchPatch {
		return writeError(ctx, q, "patch branch scope required")
	}
	if !workflow.BoolClaim(scopeClaims, "patch.propose") || !workflow.BoolClaim(scopeClaims, "analysis.execute") {
		return writeError(ctx, q, "patch.propose and analysis.execute not authorized")
	}
	if workflow.StringClaim(scopeClaims, "context_hash") != req.ContextHash || req.ContextHash == "" {
		return writeError(ctx, q, "context_hash mismatch")
	}
	log.Println("[Agent] deterministic patch-agent mode")
	patchText := deterministicPatchText()
	rationaleText := deterministicRationaleText()
	patchHash := workflow.ComputePatchHash(patchText)
	rationaleHash := workflow.ComputeRationaleHash(rationaleText)
	log.Println("[Agent] patch_hash:", patchHash)
	log.Println("[Agent] model_id:", deterministicModelID)
	patchResult := workflow.PatchResult{
		ContextHash:   req.ContextHash,
		PatchHash:     patchHash,
		RationaleHash: rationaleHash,
		RiskLevel:     "low",
	}

	tokenArtifacts, err := extendPatchBranch(req.JWS, req.ContextHash, patchResult)
	if err != nil {
		return writeError(ctx, q, "extend patch branch failed: "+err.Error())
	}
	log.Println("[Agent] Extended patch branch locally: T_patch=[n0,n1_patch_scope,n2_patch_result]")

	// --- Success ---
	resp := map[string]any{
		"status":         "ok",
		"extended_token": tokenArtifacts.Token,
		"disclosure":     tokenArtifacts.Disclosure,
		"openings":       tokenArtifacts.Openings,
		"patch_text":     patchText,
		"patch_hash":     patchHash,
		"rationale_hash": rationaleHash,
		"model_id":       deterministicModelID,
		"risk_level":     patchResult.RiskLevel,
		"patch": map[string]any{
			"context_hash":   patchResult.ContextHash,
			"patch_text":     patchText,
			"patch_hash":     patchHash,
			"rationale_hash": rationaleHash,
			"rationale_text": rationaleText,
			"model_id":       deterministicModelID,
			"risk_level":     patchResult.RiskLevel,
		},
	}
	return q.Write(ctx, a2a.NewMessage(
		a2a.MessageRoleAgent,
		a2a.TextPart{Text: string(jsonMustMarshal(resp))},
	))
}

func extendPatchBranch(token, contextHash string, patchResult workflow.PatchResult) (*patchTokenArtifacts, error) {
	payload := &pact.Payload{
		Ver:       pact.ModeSchoCo,
		TID0:      workflow.TaskID,
		NodeIndex: 2,
		Iat:       time.Now().Unix(),
		Iss:       &pact.IDClaim{CN: "spiffe://example.org/patch-agent"},
	}
	keys, openings, err := pact.AttachCommitmentRootToPayload(payload, payload.TID0, 2, workflow.PatchResultClaims(workflow.TaskID, workflow.Repo, workflow.IssueID, contextHash, patchResult))
	if err != nil {
		return nil, err
	}
	selected, err := workflow.Indexes(keys, "task_id", "repo", "issue_id", "branch_id", "context_hash", "patch_hash", "rationale_hash", "model_id", "risk_level")
	if err != nil {
		return nil, err
	}
	disc, err := sd.CreateDisclosureFromOpenings(openings, selected)
	if err != nil {
		return nil, err
	}
	extended, err := pact.ExtendJWS(token, &pact.LDNode{Payload: payload}, pact.ModeSchoCo)
	if err != nil {
		return nil, err
	}
	return &patchTokenArtifacts{
		Token:      extended,
		Disclosure: disc,
		Openings:   openings,
	}, nil
}

func (e *agentExecutor) Cancel(ctx context.Context, reqCtx *a2asrv.RequestContext, q eventqueue.Queue) error {
	// noop
	return nil
}

func deterministicPatchText() string {
	return `diff --git a/internal/api/projects.go b/internal/api/projects.go
index 0000000..0000000 100644
--- a/internal/api/projects.go
+++ b/internal/api/projects.go
@@ -34,6 +34,13 @@ func NewHandler(store ProjectStore) *Handler {
 }
 
 func (h *Handler) GetProject(projectID string) Response {
+	if projectID == "" {
+		return Response{
+			StatusCode: StatusBadRequest,
+			Err:        errors.New("project_id is required"),
+		}
+	}
+
 	project, err := h.store.FindProject(projectID)
 	if err != nil {
 		return Response{
`
}

func deterministicRationaleText() string {
	return "Reject an empty project_id before the repository lookup so the API returns a deterministic bad-request validation error instead of wrapping a lookup miss as an internal server error."
}

// writeError sends an error in JSON format via the event queue
func writeError(ctx context.Context, q eventqueue.Queue, msg string) error {
	resp := map[string]string{"error": msg}
	return q.Write(ctx, a2a.NewMessage(
		a2a.MessageRoleAgent,
		a2a.TextPart{Text: string(jsonMustMarshal(resp))},
	))
}

// jsonMustMarshal ignores Marshal error (helper)
func jsonMustMarshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// --- Reflection helpers ---
// try to localize and extract the text of the first TextPart inside the RequestContext
// search common fields/methods via reflection and, if found, extract the string from the "Text" field.
func extractTextFromRequestContext(reqCtx any) (string, error) {
	if reqCtx == nil {
		return "", errors.New("nil request context")
	}

	rv := reflect.ValueOf(reqCtx)
	// if pointer, dereference to access methods/fields
	if rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return "", errors.New("nil pointer request context")
		}
		rv = rv.Elem()
	}

	// 1) try methods that may return the message
	methodCandidates := []string{"GetRequest", "GetMessage", "Request", "Message"}
	for _, m := range methodCandidates {
		if mv := rv.MethodByName(m); mv.IsValid() && mv.Type().NumIn() == 0 {
			out := mv.Call(nil)
			if len(out) > 0 {
				return extractTextFromMessageInterface(out[0].Interface())
			}
		}
	}

	// 2) try known fields (Request, Input, Message, Msg, Inbound, Incoming)
	fieldCandidates := []string{"Request", "Input", "Message", "Msg", "Inbound", "Incoming"}
	for _, fname := range fieldCandidates {
		f := rv.FieldByName(fname)
		if !f.IsValid() {
			continue
		}
		// if pointer, dereference
		val := f
		if val.Kind() == reflect.Ptr {
			if val.IsNil() {
				continue
			}
			val = val.Elem()
		}
		// if struct or interface, try to extract
		if val.Kind() == reflect.Struct || val.Kind() == reflect.Interface {
			iface := val.Interface()
			if text, err := extractTextFromMessageInterface(iface); err == nil {
				return text, nil
			}
		}
	}

	return "", errors.New("could not locate message in RequestContext (checked common fields/methods)")
}

// extractTextFromMessageInterface tries to extract the "Text" field from the first part of a message.
// Accepts both structs from the a2a package and other compatible types — uses reflection again.
func extractTextFromMessageInterface(msg any) (string, error) {
	if msg == nil {
		return "", errors.New("nil message")
	}
	rv := reflect.ValueOf(msg)
	if rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return "", errors.New("nil pointer message")
		}
		rv = rv.Elem()
	}

	// search for "Parts" field
	partsField := rv.FieldByName("Parts")
	if !partsField.IsValid() {
		// maybe the object itself is the part (rare), try to extract "Text" directly
		if text, err := extractTextFromPartInterface(msg); err == nil {
			return text, nil
		}
		return "", errors.New("message has no Parts field")
	}

	if partsField.Kind() != reflect.Slice {
		return "", errors.New("Parts is not a slice")
	}
	if partsField.Len() == 0 {
		return "", errors.New("Parts slice empty")
	}

	first := partsField.Index(0).Interface()
	return extractTextFromPartInterface(first)
}

// extracts the "Text" field from a part.
// Prefers type assertion to a2a.TextPart, if available.
func extractTextFromPartInterface(part any) (string, error) {
	// 1) try direct type assertion (faster if possible)
	if tp, ok := part.(a2a.TextPart); ok {
		return tp.Text, nil
	}
	// 2) fallback via reflection searching for "Text" field
	rv := reflect.ValueOf(part)
	if rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return "", errors.New("nil pointer part")
		}
		rv = rv.Elem()
	}
	textField := rv.FieldByName("Text")
	if textField.IsValid() && textField.Kind() == reflect.String {
		return textField.String(), nil
	}

	// 3) try Text() string method
	if mv := rv.MethodByName("Text"); mv.IsValid() && mv.Type().NumIn() == 0 && mv.Type().NumOut() == 1 && mv.Type().Out(0).Kind() == reflect.String {
		out := mv.Call(nil)
		return out[0].String(), nil
	}

	return "", errors.New("could not extract Text from part")
}

// --- main + agent card ---
func main() {
	host := "poc-agent"
	port := 8082

	agentCard := &a2a.AgentCard{
		Name:               "Authorization Agent",
		Description:        "Validates token + SD presentations",
		URL:                fmt.Sprintf("http://%s:%d/invoke", host, port),
		PreferredTransport: a2a.TransportProtocolJSONRPC,
		DefaultInputModes:  []string{"text"},
		DefaultOutputModes: []string{"text"},
		Capabilities:       a2a.AgentCapabilities{Streaming: false},
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("Failed to bind port: %v", err)
	}

	handler := a2asrv.NewHandler(&agentExecutor{})
	mux := http.NewServeMux()
	mux.Handle("/invoke", a2asrv.NewJSONRPCHandler(handler))
	mux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewStaticAgentCardHandler(agentCard))

	log.Printf("[Agent] listening on %s:%d", host, port)
	log.Fatal(http.Serve(listener, mux))
}
