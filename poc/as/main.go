package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"anonymous-artifact/schoco"
	"flow-poc/internal/pocconfig"
	"flow-poc/internal/workflow"
	pact "flow-poc/pact"
)

func main() {
	http.HandleFunc("/issueToken", issueTokenHandler)
	http.HandleFunc("/revocationCheckpoint", revocationCheckpointHandler)

	log.Println("[AS] Listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func revocationCheckpointHandler(w http.ResponseWriter, r *http.Request) {
	rc, err := newRevocationCheckpoint(time.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rc)
}

func issueTokenHandler(w http.ResponseWriter, r *http.Request) {
	// === Root key (SchoCo) ===
	rootSk, rootPk, err := schoco.KeyPair()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// === Parse request ===
	var req struct {
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Println("[AS] Requested permissions:", req.Permissions)

	// === 1) Claims to be attached to the root node ===
	claims := workflow.RootClaims(req.Permissions)

	// === 2) Build base payload ===
	payload := &pact.Payload{
		Ver:       pact.ModeSchoCo,
		TID0:      workflow.TaskID,
		NodeIndex: 0,
		Iat:       time.Now().Unix(),
		Iss: &pact.IDClaim{
			PK: rootPk.Bytes(),
			CN: "spiffe://example.org/AS",
		},
	}

	// === 3) Attach salted commitment root to payload ===
	keys, openings, err := pact.AttachCommitmentRootToPayload(payload, payload.TID0, 0, claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Println("[AS] Commitment root attached to payload")
	log.Println("[AS] Openings count:", len(openings))
	if verboseOutput() {
		log.Println("[AS] Fields order:", keys)
		log.Println("[AS] Payload after attach (Data metadata):", payload)
	}

	// === 4) Create JWS signing the payload ===
	jws, err := pact.CreateJWS(payload, 1, rootSk)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rc, err := newRevocationCheckpoint(time.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// === 6) Response (compatible com a PoC/Host atual) ===
	resp := map[string]any{
		"jws":                   jws,
		"keys":                  keys,
		"openings":              openings,
		"revocation_checkpoint": rc,
	}

	b, _ := json.MarshalIndent(resp, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)

	log.Println("[AS] Token issued following target flow (AttachCommitmentRootToPayload -> sign -> disclosure)")
	if verboseOutput() {
		log.Println("[AS] Response contents:", resp)
	}
}

func newRevocationCheckpoint(now time.Time) (*pact.RevocationCheckpoint, error) {
	rc, err := pact.CreateRevocationCheckpoint(
		pocconfig.RevocationIssuerKey(),
		uint64(now.Unix()/60),
		now.Unix(),
		nil,
	)
	if err != nil {
		return nil, err
	}
	rc.IssuerID = pocconfig.RevocationIssuerID
	rc.ExpiresAt = now.Add(2 * time.Minute).Unix()
	rc.Meta = map[string]string{"purpose": "pact-poc"}
	if err := pact.SignRevocationCheckpoint(pocconfig.RevocationIssuerKey(), rc); err != nil {
		return nil, err
	}
	return rc, nil
}

func verboseOutput() bool {
	return os.Getenv("PACT_POC_VERBOSE") == "1"
}
