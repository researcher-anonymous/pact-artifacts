package pact

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"anonymous-artifact/schoco"
	"filippo.io/edwards25519"
	sd "flow-poc/sd"
)

/*
	============================================================
	  Version constants

============================================================
*/
const (
	ModeID     = 0
	ModeSchoCo = 1

	IDBackendECDSA = "ECDSA"

	VerECDSA  = ModeID
	VerSchoCo = ModeSchoCo

	// VerSchnorr is retained only for legacy/internal benchmarks.
	VerSchnorr = 2
)

/* ============================================================
   JSON-LD payload structures
============================================================ */

type Payload struct {
	Ver           int8                   `json:"ver,omitempty"`
	TID0          string                 `json:"tid_0,omitempty"`
	NodeIndex     int                    `json:"node_index,omitempty"`
	NextSignerPK  []byte                 `json:"next_signer_pk,omitempty"`
	NextNotBefore int64                  `json:"next_not_before,omitempty"`
	NextNotAfter  int64                  `json:"next_not_after,omitempty"`
	Iat           int64                  `json:"iat,omitempty"`
	Iss           *IDClaim               `json:"iss,omitempty"`
	Aud           *IDClaim               `json:"aud,omitempty"`
	Sub           *IDClaim               `json:"sub,omitempty"`
	Data          map[string]interface{} `json:"data,omitempty"`
	List          []*LDNode              `json:"@list,omitempty"`
}

type IDClaim struct {
	CN string  `json:"cn,omitempty"`
	PK []byte  `json:"pk,omitempty"`
	ID *string `json:"id,omitempty"`
}

type LDNode struct {
	ID      string   `json:"@id,omitempty"`
	Payload *Payload `json:"payload"`
}

/* ============================================================
   Selective Disclosure claim
============================================================ */

type SDClaim struct {
	ID    string      `json:"id"`
	Value interface{} `json:"value"`
}

type Disclosure = sd.Disclosure

type Evidence struct {
	NodeOpenings map[int][]sd.FieldOpening `json:"node_openings"`
}

type VerifierRelation interface {
	Evaluate(*Payload, *Evidence) error
}

type EvaluatedNodeRelation interface {
	VerifierRelation
	EvaluatedNodes(*Payload) []int
}

type VerifierRelationFunc func(*Payload, *Evidence) error

func (f VerifierRelationFunc) Evaluate(p *Payload, e *Evidence) error {
	if f == nil {
		return nil
	}
	return f(p, e)
}

type RevocationCheckpoint struct {
	IssuerID    string            `json:"issuer_id,omitempty"`
	IssuerPK    []byte            `json:"issuer_pk,omitempty"`
	Epoch       uint64            `json:"epoch"`
	IssuedAt    int64             `json:"issued_at"`
	ExpiresAt   int64             `json:"expires_at,omitempty"`
	RevokedTIDs []string          `json:"revoked_tids,omitempty"`
	Revoked     []string          `json:"revoked,omitempty"`
	Alg         string            `json:"alg,omitempty"`
	Meta        map[string]string `json:"meta,omitempty"`
	Signature   []byte            `json:"signature"`
}

type ValidationOptions struct {
	Evidence             *Evidence
	Presentations        map[int]*sd.Disclosure
	VerifierRelation     VerifierRelation
	RevocationCheckpoint *RevocationCheckpoint
	Tau                  time.Duration
	ClockSkew            time.Duration
	RequireRevocation    bool
	TrustedIssuerPK      []byte
	Now                  time.Time
	IDKeyResolver        IDKeyResolver
}

type ValidationStage string

const (
	StageChainSignatures ValidationStage = "chain_signatures"
	StageCommitments     ValidationStage = "commitment_evidence"
	StageVerifier        ValidationStage = "verifier_relation"
	StageRevocation      ValidationStage = "revocation_checkpoint"
)

type ValidationResult struct {
	Stages map[ValidationStage]error
}

type IDKeyResolver interface {
	ResolveNextSigner(predecessor *Payload, now time.Time) ([]byte, error)
}

type LocalIDKeyResolver struct{}

func (LocalIDKeyResolver) ResolveNextSigner(predecessor *Payload, now time.Time) ([]byte, error) {
	if predecessor == nil {
		return nil, fmt.Errorf("nil predecessor")
	}
	if len(predecessor.NextSignerPK) == 0 {
		return nil, fmt.Errorf("predecessor has no next signer")
	}
	if predecessor.NextNotBefore > 0 && now.Before(time.Unix(predecessor.NextNotBefore, 0)) {
		return nil, fmt.Errorf("bearer material not yet valid")
	}
	if predecessor.NextNotAfter > 0 && !now.Before(time.Unix(predecessor.NextNotAfter, 0)) {
		return nil, fmt.Errorf("bearer material expired")
	}
	return predecessor.NextSignerPK, nil
}

/* ============================================================
   Base64 helpers
============================================================ */

var b64 = base64.RawURLEncoding

func b64Encode(b []byte) string { return b64.EncodeToString(b) }
func b64Decode(s string) ([]byte, error) {
	return b64.DecodeString(s)
}

func marshalCanonical(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func schocoSlotMessage(prefixIndex int, payloadBytes []byte) []byte {
	return schoco.PACTSlotMessage(uint64(prefixIndex+1), payloadBytes)
}

func SchoCoSlotMessageForTest(prefixIndex int, payloadBytes []byte) []byte {
	return schocoSlotMessage(prefixIndex, payloadBytes)
}

func SchoCoMessageSequenceForTest(doc *Payload, finalPayloadBytes []byte) ([][]byte, error) {
	if doc == nil {
		return nil, fmt.Errorf("nil payload")
	}
	messages := make([][]byte, 0, len(doc.List)+1)
	messages = append(messages, schocoSlotMessage(len(doc.List), finalPayloadBytes))
	for i := len(doc.List) - 1; i >= 0; i-- {
		p := prefixPayload(doc, i)
		b, err := marshalCanonical(p)
		if err != nil {
			return nil, err
		}
		messages = append(messages, schocoSlotMessage(i, b))
	}
	return messages, nil
}

/* ============================================================
   Data → Merkle leaves
============================================================ */

// DataToLeaves is a legacy unsalted selective-disclosure helper retained for
// backward-compatible experiments. Target PACT paths must use
// DataToFieldOpenings and salted commitments instead.
func DataToLeaves(data map[string]interface{}) (keys []string, leaves [][]byte, err error) {
	if data == nil {
		return nil, nil, fmt.Errorf("nil data")
	}

	keys = make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		leafObj := SDClaim{ID: k, Value: data[k]}
		b, err := marshalCanonical(leafObj)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal SDClaim %s: %v", k, err)
		}
		leaves = append(leaves, b)
	}
	return keys, leaves, nil
}

func DataToFieldOpenings(tid0 string, nodeIndex int, data map[string]interface{}) (keys []string, openings []sd.FieldOpening, err error) {
	return dataToFieldOpenings(tid0, nodeIndex, data, false)
}

func DataToFieldOpeningsDeterministicForTest(tid0 string, nodeIndex int, data map[string]interface{}) (keys []string, openings []sd.FieldOpening, err error) {
	return dataToFieldOpenings(tid0, nodeIndex, data, true)
}

func dataToFieldOpenings(tid0 string, nodeIndex int, data map[string]interface{}, deterministic bool) (keys []string, openings []sd.FieldOpening, err error) {
	if data == nil {
		return nil, nil, fmt.Errorf("nil data")
	}
	keys = make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for fieldIndex, k := range keys {
		var opening sd.FieldOpening
		var err error
		if deterministic {
			opening, err = sd.NewDeterministicFieldOpeningForTest(tid0, nodeIndex, fieldIndex, k, data[k])
		} else {
			opening, err = sd.NewRandomFieldOpening(tid0, nodeIndex, fieldIndex, k, data[k])
		}
		if err != nil {
			return nil, nil, err
		}
		openings = append(openings, opening)
	}
	return keys, openings, nil
}

func intBytes(v int) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	return b[:]
}

func AttachCommitmentRootToPayload(p *Payload, tid0 string, nodeIndex int, data map[string]interface{}) (keys []string, openings []sd.FieldOpening, err error) {
	if p == nil {
		return nil, nil, fmt.Errorf("nil payload")
	}
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("no data to attach")
	}
	if tid0 == "" {
		tid0 = p.TID0
	}
	if tid0 == "" {
		tid0 = deriveTID0(p)
	}
	p.TID0 = tid0
	p.NodeIndex = nodeIndex

	keys, openings, err = DataToFieldOpenings(tid0, nodeIndex, data)
	if err != nil {
		return nil, nil, err
	}
	commitments, err := sd.OpeningsToCommitments(openings)
	if err != nil {
		return nil, nil, err
	}
	root, err := sd.MerkleRoot(commitments)
	if err != nil {
		return nil, nil, err
	}
	p.Data = map[string]interface{}{
		"sd": map[string]string{
			"alg":  "pact-sd-v1-sha256-merkle",
			"root": b64Encode(root),
		},
	}
	return keys, openings, nil
}

func deriveTID0(p *Payload) string {
	cp := *p
	cp.Data = nil
	cp.List = nil
	cp.TID0 = ""
	b, _ := marshalCanonical(&cp)
	h := sha256.Sum256(b)
	return b64Encode(h[:])
}

// AttachSDRootToPayload is legacy and uses unsalted leaves. Production PACT
// paths should use AttachCommitmentRootToPayload.
func AttachSDRootToPayload(p *Payload, data map[string]interface{}) (keys []string, leaves [][]byte, err error) {
	if p == nil {
		return nil, nil, fmt.Errorf("nil payload")
	}
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("no data to attach")
	}

	keys, leaves, err = DataToLeaves(data)
	if err != nil {
		return nil, nil, err
	}

	root, err := sd.MerkleRoot(leaves)
	if err != nil {
		return nil, nil, err
	}

	p.Data = map[string]interface{}{
		"sd": map[string]string{
			"alg":  "sha256-merkle",
			"root": b64Encode(root),
		},
	}
	return keys, leaves, nil
}

func ExtractSDRootFromPayload(p *Payload) ([]byte, bool) {
	if p == nil || p.Data == nil {
		return nil, false
	}
	var rs string
	switch m := p.Data["sd"].(type) {
	case map[string]interface{}:
		v, ok := m["root"].(string)
		if !ok {
			return nil, false
		}
		rs = v
	case map[string]string:
		v, ok := m["root"]
		if !ok {
			return nil, false
		}
		rs = v
	default:
		return nil, false
	}
	b, err := b64Decode(rs)
	if err != nil {
		return nil, false
	}
	return b, true
}

/* ============================================================
   Semantic extraction from disclosure
============================================================ */

func ExtractSDClaimsFromDisclosure(d *sd.Disclosure) ([]SDClaim, error) {
	if d == nil {
		return nil, fmt.Errorf("nil disclosure")
	}
	if len(d.Openings) > 0 {
		claims := make([]SDClaim, 0, len(d.Openings))
		for _, opening := range d.Openings {
			var v interface{}
			if err := json.Unmarshal(opening.Value, &v); err != nil {
				return nil, fmt.Errorf("invalid opening value: %v", err)
			}
			if opening.Tag == "" {
				return nil, fmt.Errorf("opening missing tag")
			}
			claims = append(claims, SDClaim{ID: opening.Tag, Value: v})
		}
		return claims, nil
	}
	var claims []SDClaim
	for _, leaf := range d.Leaves {
		var c SDClaim
		if err := json.Unmarshal(leaf, &c); err != nil {
			return nil, fmt.Errorf("invalid SDClaim leaf: %v", err)
		}
		if c.ID == "" {
			return nil, fmt.Errorf("SDClaim missing id")
		}
		claims = append(claims, c)
	}
	return claims, nil
}

/* ============================================================
   Validate caching for SchoCo heavy prep work
   (cache key: exact payload bytes from JWS)
============================================================ */

var schocoVerifyCache sync.Map // map[string]*schocoCacheEntry

type schocoCacheEntry struct {
	rootPK   *edwards25519.Point
	prefixes [][]byte
	partSigs []*edwards25519.Point
}

/* ============================================================
   Create / Extend / Validate (JWS)
============================================================ */

func CreateJWS(payload *Payload, version int8, key interface{}) (string, error) {
	payloadBytes, err := marshalCanonical(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %v", err)
	}
	header := map[string]interface{}{"version": version}
	headerBytes, _ := json.Marshal(header)

	var sigBytes []byte
	switch version {
	case VerECDSA:
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("version %d requires *ecdsa.PrivateKey", version)
		}
		h := sha256.Sum256(payloadBytes)
		sigBytes, err = ecdsaKey.Sign(rand.Reader, h[:], crypto.SHA256)
		if err != nil {
			return "", fmt.Errorf("ecdsa sign: %v", err)
		}
	case VerSchoCo:
		sk, ok := key.(*edwards25519.Scalar)
		if !ok {
			return "", fmt.Errorf("version %d requires *edwards25519.Scalar", version)
		}
		sig, err := schoco.StdSignPACT(1, payloadBytes, sk)
		if err != nil {
			return "", fmt.Errorf("StdSignPACT: %v", err)
		}
		sigBytes, err = sig.MarshalBinary()
		if err != nil {
			return "", fmt.Errorf("MarshalBinary: %v", err)
		}
	case VerSchnorr:
		sk, ok := key.(*edwards25519.Scalar)
		if !ok {
			return "", fmt.Errorf("version %d requires *edwards25519.Scalar", version)
		}
		sig, err := schoco.StdSign(payloadBytes, sk)
		if err != nil {
			return "", fmt.Errorf("StdSign: %v", err)
		}
		sigBytes, err = sig.MarshalBinary()
		if err != nil {
			return "", fmt.Errorf("MarshalBinary: %v", err)
		}
	default:
		return "", fmt.Errorf("unsupported version: %d", version)
	}

	return strings.Join([]string{b64Encode(headerBytes), b64Encode(payloadBytes), b64Encode(sigBytes)}, "."), nil
}

func ExtendJWS(jws string, newNode *LDNode, version int8, key ...interface{}) (string, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid jws format")
	}
	headerB, _ := b64Decode(parts[0])
	payloadB, _ := b64Decode(parts[1])
	sigB, _ := b64Decode(parts[2])

	var doc Payload
	if err := json.Unmarshal(payloadB, &doc); err != nil {
		return "", fmt.Errorf("unmarshal payload: %v", err)
	}

	switch version {
	case VerECDSA:
		newNode.ID = b64Encode(sigB)
		if newNode.Payload != nil && newNode.Payload.NodeIndex == 0 {
			newNode.Payload.NodeIndex = len(doc.List) + 1
			if newNode.Payload.TID0 == "" {
				newNode.Payload.TID0 = doc.TID0
			}
		}
		doc.List = append(doc.List, newNode)
		if len(key) == 0 {
			return "", fmt.Errorf("ecdsa key required")
		}
		ecdsaKey, ok := key[0].(*ecdsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("key is not *ecdsa.PrivateKey")
		}
		newPayloadBytes, _ := marshalCanonical(&doc)
		h := sha256.Sum256(newPayloadBytes)
		newSig, _ := ecdsaKey.Sign(rand.Reader, h[:], crypto.SHA256)
		return strings.Join([]string{b64Encode(headerB), b64Encode(newPayloadBytes), b64Encode(newSig)}, "."), nil

	case VerSchoCo:
		// SchoCo: previous signature provides the aggregation key (S) and the partial (R) becomes node ID.
		prevSig, err := schoco.UnmarshalSignature(sigB)
		if err != nil {
			return "", fmt.Errorf("unmarshal previous signature: %v", err)
		}
		partSigB64 := b64Encode(prevSig.R.Bytes())
		newNode.ID = partSigB64
		if newNode.Payload != nil && newNode.Payload.NodeIndex == 0 {
			newNode.Payload.NodeIndex = len(doc.List) + 1
			if newNode.Payload.TID0 == "" {
				newNode.Payload.TID0 = doc.TID0
			}
		}
		doc.List = append(doc.List, newNode)

		newPayloadBytes, _ := marshalCanonical(&doc)
		partSig, newSig, err := schoco.AggregatePACT(uint64(len(doc.List)+1), newPayloadBytes, prevSig)
		if err != nil {
			return "", fmt.Errorf("AggregatePACT: %v", err)
		}
		newNode.ID = b64Encode(partSig.Bytes())
		newSigBytes, _ := newSig.MarshalBinary()

		var hdr map[string]interface{}
		_ = json.Unmarshal(headerB, &hdr)
		hdr["version"] = version
		hdrB, _ := json.Marshal(hdr)

		// Invalidate cache for this JWS payload (the payload bytes changed)
		// Note: old payloadB string was key for cache; it will be different for newPayloadBytes, so no need to delete explicitly.

		return strings.Join([]string{b64Encode(hdrB), b64Encode(newPayloadBytes), b64Encode(newSigBytes)}, "."), nil

	case VerSchnorr:
		// Schnorr puro sequencial: previous full signature becomes node ID, and caller must provide the schnorr private key
		newNodeID := b64Encode(sigB) // full previous signature as node ID (sequential semantics)
		newNode.ID = newNodeID
		if newNode.Payload != nil && newNode.Payload.NodeIndex == 0 {
			newNode.Payload.NodeIndex = len(doc.List) + 1
			if newNode.Payload.TID0 == "" {
				newNode.Payload.TID0 = doc.TID0
			}
		}
		doc.List = append(doc.List, newNode)

		if len(key) == 0 {
			return "", fmt.Errorf("schnorr key required for extension")
		}
		sk, ok := key[0].(*edwards25519.Scalar)
		if !ok {
			return "", fmt.Errorf("schnorr extension requires *edwards25519.Scalar key")
		}

		newPayloadBytes, err := marshalCanonical(&doc)
		if err != nil {
			return "", fmt.Errorf("marshal canonical: %v", err)
		}

		newSig, err := schoco.StdSign(newPayloadBytes, sk)
		if err != nil {
			return "", fmt.Errorf("StdSign schnorr: %v", err)
		}
		newSigBytes, _ := newSig.MarshalBinary()

		var hdr2 map[string]interface{}
		_ = json.Unmarshal(headerB, &hdr2)
		hdr2["version"] = version
		hdrB2, _ := json.Marshal(hdr2)

		return strings.Join([]string{b64Encode(hdrB2), b64Encode(newPayloadBytes), b64Encode(newSigBytes)}, "."), nil

	default:
		return "", fmt.Errorf("unsupported version: %d", version)
	}
}

func ValidateJWS(jws string, version int8, bundle ...*Payload) (bool, error) {
	return validateChainSignatures(jws, version, ValidationOptions{}, bundle...)
}

func validateChainSignatures(jws string, version int8, opts ValidationOptions, bundle ...*Payload) (bool, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid jws format")
	}
	payloadB, _ := b64Decode(parts[1])
	sigB, _ := b64Decode(parts[2])

	var doc Payload
	if err := json.Unmarshal(payloadB, &doc); err != nil {
		return false, fmt.Errorf("unmarshal payload: %v", err)
	}

	switch version {
	case VerECDSA:
		N := len(doc.List)
		for k := 0; k <= N; k++ {
			partial := prefixPayload(&doc, k)
			partialBytes, _ := marshalCanonical(partial)
			var sigToCheck []byte
			if k == N {
				sigToCheck = sigB
			} else {
				var err error
				if doc.List[k] == nil || doc.List[k].ID == "" {
					return false, fmt.Errorf("missing backward signature link for prefix %d", k)
				}
				sigToCheck, err = b64Decode(doc.List[k].ID)
				if err != nil {
					return false, fmt.Errorf("malformed backward signature link for prefix %d: %v", k, err)
				}
			}
			var pubKeyBytes []byte
			if k == 0 {
				pubKeyBytes = opts.TrustedIssuerPK
				if len(pubKeyBytes) == 0 && doc.Iss != nil {
					pubKeyBytes = doc.Iss.PK
				}
			} else if opts.IDKeyResolver != nil {
				pred, err := predecessorPayload(&doc, k)
				if err != nil {
					return false, err
				}
				now := opts.Now
				if now.IsZero() {
					now = time.Now()
				}
				resolved, err := opts.IDKeyResolver.ResolveNextSigner(pred, now)
				if err != nil {
					return false, fmt.Errorf("resolve authorized signer at step %d: %v", k, err)
				}
				pubKeyBytes = resolved
			} else if k > 0 && doc.List[k-1] != nil && doc.List[k-1].Payload != nil && doc.List[k-1].Payload.Iss != nil && len(doc.List[k-1].Payload.Iss.PK) > 0 {
				pubKeyBytes = doc.List[k-1].Payload.Iss.PK
			} else if len(bundle) > 0 {
				if bundle[0].List != nil && len(bundle[0].List) > 0 && bundle[0].List[0].Payload.Sub != nil {
					pubKeyBytes = bundle[0].List[0].Payload.Sub.PK
				}
			}
			if len(pubKeyBytes) == 0 {
				return false, fmt.Errorf("no public key available for step %d", k)
			}
			pub, err := x509.ParsePKIXPublicKey(pubKeyBytes)
			if err != nil {
				return false, fmt.Errorf("parse pkix pubkey (k=%d): %v", k, err)
			}
			h := sha256.Sum256(partialBytes)
			if !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), h[:], sigToCheck) {
				return false, fmt.Errorf("signature failed at step %d", k)
			}
		}
		return true, nil

	case VerSchoCo:
		// Agg verification path with caching of heavy prep work (messages, partSigs, rootPK)
		N := len(doc.List)
		lastSig, err := schoco.UnmarshalSignature(sigB)
		if err != nil {
			return false, fmt.Errorf("unmarshal lastSig: %v", err)
		}

		// key for cache is the exact payload bytes as present in the JWS
		cacheKey := string(payloadB)

		var entry *schocoCacheEntry
		if v, ok := schocoVerifyCache.Load(cacheKey); ok {
			entry = v.(*schocoCacheEntry)
		} else {
			// build fresh cache entry
			rootPK := new(edwards25519.Point)
			if _, err := rootPK.SetBytes(doc.Iss.PK); err != nil {
				return false, fmt.Errorf("SetBytes rootPK: %v", err)
			}

			// prefixes are kept in natural PACT order: P_0, P_1, ..., P_N.
			// VerifyPACT maps P_i to SchoCo slot i+1 and handles SchoCo's
			// reverse aggregate verification order internally.
			prefixes := make([][]byte, 0, N+1)
			for i := 0; i < N; i++ {
				p := prefixPayload(&doc, i)
				b, _ := marshalCanonical(p)
				prefixes = append(prefixes, b)
			}
			prefixes = append(prefixes, payloadB)

			// partSigs are also natural link order: R_0, R_1, ..., R_{N-1}.
			partSigs := make([]*edwards25519.Point, 0, N)
			for i := 0; i < N; i++ {
				node := doc.List[i]
				idBytes, _ := b64Decode(node.ID)
				pt, err := new(edwards25519.Point).SetBytes(idBytes)
				if err != nil {
					return false, fmt.Errorf("SetBytes partSig: %v", err)
				}
				partSigs = append(partSigs, pt)
			}

			entry = &schocoCacheEntry{
				rootPK:   rootPK,
				prefixes: prefixes,
				partSigs: partSigs,
			}
			schocoVerifyCache.Store(cacheKey, entry)
		}

		if !schoco.VerifyPACT(entry.rootPK, entry.prefixes, entry.partSigs, lastSig) {
			return false, fmt.Errorf("SchoCo verification failed")
		}
		return true, nil

	case VerSchnorr:
		// Sequential Schnorr verification (mirror ECDSA sequential, but using edwards25519 sigs)
		N := len(doc.List)

		// root public key (used for all steps in sequential mode)
		rootPK := new(edwards25519.Point)
		if _, err := rootPK.SetBytes(doc.Iss.PK); err != nil {
			return false, fmt.Errorf("SetBytes rootPK: %v", err)
		}

		for k := 0; k < N; k++ {
			partial := prefixPayload(&doc, k+1)
			partialBytes, _ := marshalCanonical(partial)

			var sigToCheck []byte
			if k == N-1 {
				sigToCheck = sigB
			} else {
				sigToCheck, _ = b64Decode(doc.List[k+1].ID)
			}

			sigStruct, err := schoco.UnmarshalSignature(sigToCheck)
			if err != nil {
				return false, fmt.Errorf("byteToSignature (k=%d): %v", k, err)
			}

			if !schoco.StdVerify(partialBytes, sigStruct, rootPK) {
				return false, fmt.Errorf("schnorr signature failed at step %d", k)
			}
		}
		return true, nil

	default:
		return false, fmt.Errorf("unsupported version: %d", version)
	}
}

func prefixPayload(doc *Payload, extensionCount int) *Payload {
	p := &Payload{
		Ver:           doc.Ver,
		TID0:          doc.TID0,
		NodeIndex:     doc.NodeIndex,
		NextSignerPK:  doc.NextSignerPK,
		NextNotBefore: doc.NextNotBefore,
		NextNotAfter:  doc.NextNotAfter,
		Iat:           doc.Iat,
		Iss:           doc.Iss,
		Aud:           doc.Aud,
		Sub:           doc.Sub,
		Data:          doc.Data,
	}
	if extensionCount > 0 {
		p.List = doc.List[:extensionCount]
	}
	return p
}

func predecessorPayload(doc *Payload, prefixIndex int) (*Payload, error) {
	if prefixIndex <= 0 {
		return nil, fmt.Errorf("prefix %d has no predecessor", prefixIndex)
	}
	if prefixIndex == 1 {
		return doc, nil
	}
	idx := prefixIndex - 2
	if idx < 0 || idx >= len(doc.List) || doc.List[idx] == nil || doc.List[idx].Payload == nil {
		return nil, fmt.Errorf("missing predecessor for prefix %d", prefixIndex)
	}
	return doc.List[idx].Payload, nil
}

func ValidatePACT(jws string, version int8, opts ValidationOptions) (*ValidationResult, error) {
	res := &ValidationResult{Stages: map[ValidationStage]error{}}
	if version == ModeID && len(opts.TrustedIssuerPK) == 0 {
		err := fmt.Errorf("missing trusted issuer key")
		res.Stages[StageChainSignatures] = err
		return res, err
	}
	doc, err := payloadFromJWS(jws)
	if err != nil {
		res.Stages[StageChainSignatures] = err
		return res, err
	}
	if version == ModeID && len(doc.List) > 0 && opts.IDKeyResolver == nil {
		err := fmt.Errorf("ID-mode extension validation requires IDKeyResolver")
		res.Stages[StageChainSignatures] = err
		return res, err
	}
	_, err = validateChainSignatures(jws, version, opts)
	res.Stages[StageChainSignatures] = err
	if err != nil {
		return res, err
	}

	err = validateCommitmentEvidence(doc, opts.Evidence, opts.Presentations, opts.VerifierRelation)
	res.Stages[StageCommitments] = err
	if err != nil {
		return res, err
	}

	if opts.VerifierRelation != nil {
		err = opts.VerifierRelation.Evaluate(doc, opts.Evidence)
	}
	res.Stages[StageVerifier] = err
	if err != nil {
		return res, err
	}

	err = ValidateRevocationCheckpoint(doc.TID0, opts.RevocationCheckpoint, opts)
	res.Stages[StageRevocation] = err
	if err != nil {
		return res, err
	}
	return res, nil
}

func payloadFromJWS(jws string) (*Payload, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid jws format")
	}
	payloadB, err := b64Decode(parts[1])
	if err != nil {
		return nil, err
	}
	var doc Payload
	if err := json.Unmarshal(payloadB, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func validateCommitmentEvidence(doc *Payload, evidence *Evidence, presentations map[int]*sd.Disclosure, relation VerifierRelation) error {
	if evidence != nil {
		if evidence.NodeOpenings == nil {
			return fmt.Errorf("evidence has no node openings")
		}
		required := evidenceRequiredNodes(doc, relation)
		for _, nodeIndex := range required {
			if _, ok := evidence.NodeOpenings[nodeIndex]; !ok {
				return fmt.Errorf("missing evidence for evaluated node %d", nodeIndex)
			}
		}
		for nodeIndex, openings := range evidence.NodeOpenings {
			nodePayload, err := payloadForNode(doc, nodeIndex)
			if err != nil {
				return err
			}
			root, ok := ExtractSDRootFromPayload(nodePayload)
			if !ok {
				return fmt.Errorf("node %d has no commitment root", nodeIndex)
			}
			if len(openings) == 0 {
				return fmt.Errorf("missing openings for node %d", nodeIndex)
			}
			commitments, err := sd.OpeningsToCommitments(openings)
			if err != nil {
				return err
			}
			gotRoot, err := sd.MerkleRoot(commitments)
			if err != nil {
				return err
			}
			if !bytes.Equal(root, gotRoot) {
				return fmt.Errorf("evidence root mismatch for node %d", nodeIndex)
			}
		}
	}
	if presentations != nil {
		return validatePresentationsOnly(doc, presentations)
	}
	return nil
}

func evidenceRequiredNodes(doc *Payload, relation VerifierRelation) []int {
	if rel, ok := relation.(EvaluatedNodeRelation); ok {
		return rel.EvaluatedNodes(doc)
	}
	nodes := []int{}
	if _, ok := ExtractSDRootFromPayload(doc); ok {
		nodes = append(nodes, 0)
	}
	for i, node := range doc.List {
		if node != nil && node.Payload != nil {
			if _, ok := ExtractSDRootFromPayload(node.Payload); ok {
				nodes = append(nodes, i+1)
			}
		}
	}
	return nodes
}

func payloadForNode(doc *Payload, nodeIndex int) (*Payload, error) {
	if nodeIndex == 0 {
		return doc, nil
	}
	idx := nodeIndex - 1
	if idx < 0 || idx >= len(doc.List) || doc.List[idx] == nil || doc.List[idx].Payload == nil {
		return nil, fmt.Errorf("node %d not found", nodeIndex)
	}
	return doc.List[idx].Payload, nil
}

func validatePresentationsOnly(doc *Payload, presentations map[int]*sd.Disclosure) error {
	verifyNode := func(nodePayload *Payload, pres *sd.Disclosure) error {
		if nodePayload == nil {
			return fmt.Errorf("nil node payload")
		}
		if pres == nil || len(pres.Openings) == 0 {
			return fmt.Errorf("target disclosure must contain salted field openings")
		}
		root, ok := ExtractSDRootFromPayload(nodePayload)
		if !ok {
			return fmt.Errorf("node payload has no SD root")
		}
		okv, err := sd.VerifyDisclosure(pres)
		if err != nil || !okv {
			return fmt.Errorf("disclosure verification failed: %v", err)
		}
		if !bytes.Equal(root, pres.Root) {
			return fmt.Errorf("disclosure root mismatch")
		}
		return nil
	}
	if pres, ok := presentations[0]; ok {
		if err := verifyNode(doc, pres); err != nil {
			return err
		}
	}
	for i, node := range doc.List {
		if node == nil || node.Payload == nil {
			continue
		}
		pres, ok := presentations[i+1]
		if !ok {
			if _, has := ExtractSDRootFromPayload(node.Payload); has {
				return fmt.Errorf("missing presentation for node %d", i+1)
			}
			continue
		}
		if err := verifyNode(node.Payload, pres); err != nil {
			return err
		}
	}
	return nil
}

func CreateRevocationCheckpoint(priv *ecdsa.PrivateKey, epoch uint64, issuedAt int64, revoked []string) (*RevocationCheckpoint, error) {
	if priv == nil {
		return nil, fmt.Errorf("nil issuer key")
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	rc := &RevocationCheckpoint{
		IssuerID:    "issuer",
		IssuerPK:    pubBytes,
		Epoch:       epoch,
		IssuedAt:    issuedAt,
		RevokedTIDs: append([]string(nil), revoked...),
		Alg:         "ECDSA-P256-SHA256",
	}
	if err := SignRevocationCheckpoint(priv, rc); err != nil {
		return nil, err
	}
	return rc, nil
}

func SignRevocationCheckpoint(priv *ecdsa.PrivateKey, rc *RevocationCheckpoint) error {
	if priv == nil {
		return fmt.Errorf("nil issuer key")
	}
	if rc == nil {
		return fmt.Errorf("nil checkpoint")
	}
	if len(rc.IssuerPK) == 0 {
		pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			return err
		}
		rc.IssuerPK = pubBytes
	}
	if rc.Alg == "" {
		rc.Alg = "ECDSA-P256-SHA256"
	}
	msg, err := rc.signingBytes()
	if err != nil {
		return err
	}
	h := sha256.Sum256(msg)
	sig, err := priv.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return err
	}
	rc.Signature = sig
	return nil
}

func (rc *RevocationCheckpoint) signingBytes() ([]byte, error) {
	if rc == nil {
		return nil, fmt.Errorf("nil checkpoint")
	}
	cp := *rc
	cp.Signature = nil
	cp.RevokedTIDs = append([]string(nil), rc.revokedTIDs()...)
	cp.Revoked = nil
	cp.Revoked = append([]string(nil), rc.Revoked...)
	sort.Strings(cp.RevokedTIDs)
	sort.Strings(cp.Revoked)
	return marshalCanonical(cp)
}

func (rc *RevocationCheckpoint) revokedTIDs() []string {
	if rc == nil {
		return nil
	}
	if len(rc.RevokedTIDs) > 0 {
		return rc.RevokedTIDs
	}
	return rc.Revoked
}

func ValidateRevocationCheckpoint(tid0 string, rc *RevocationCheckpoint, opts ValidationOptions) error {
	if rc == nil {
		if opts.RequireRevocation {
			return fmt.Errorf("missing required revocation checkpoint")
		}
		return nil
	}
	if len(opts.TrustedIssuerPK) == 0 {
		return fmt.Errorf("missing trusted issuer key")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	msg, err := rc.signingBytes()
	if err != nil {
		return err
	}
	if len(rc.IssuerPK) > 0 && !bytes.Equal(rc.IssuerPK, opts.TrustedIssuerPK) {
		return fmt.Errorf("revocation checkpoint issuer does not match trust anchor")
	}
	pubAny, err := x509.ParsePKIXPublicKey(opts.TrustedIssuerPK)
	if err != nil {
		return err
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("checkpoint issuer key is not ECDSA")
	}
	h := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(pub, h[:], rc.Signature) {
		return fmt.Errorf("revocation checkpoint signature failed")
	}
	issuedAt := time.Unix(rc.IssuedAt, 0)
	if opts.ClockSkew < 0 {
		return fmt.Errorf("negative clock skew")
	}
	if issuedAt.After(now.Add(opts.ClockSkew)) {
		return fmt.Errorf("revocation checkpoint issued in the future")
	}
	if rc.ExpiresAt > 0 && !now.Before(time.Unix(rc.ExpiresAt, 0)) {
		return fmt.Errorf("revocation checkpoint expired")
	}
	if opts.Tau > 0 && now.Sub(issuedAt) > opts.Tau {
		return fmt.Errorf("revocation checkpoint stale")
	}
	for _, revoked := range rc.revokedTIDs() {
		if revoked == tid0 {
			return fmt.Errorf("token revoked")
		}
	}
	return nil
}

/* ============================================================
   Presentation helpers
============================================================ */

// CreateDisclosureFromLeaves is legacy and should not be used by target PACT
// production paths.
func CreateDisclosureFromLeaves(leaves [][]byte, selectedIndices []int) (*sd.Disclosure, error) {
	return sd.CreateDisclosure(leaves, selectedIndices)
}

// CreatePresentationFromData is legacy and should not be used by target PACT
// production paths.
func CreatePresentationFromData(data map[string]interface{}, selectedKeys []string) (*sd.Disclosure, error) {
	keysOrder, leaves, err := DataToLeaves(data)
	if err != nil {
		return nil, err
	}
	keyToIndex := make(map[string]int, len(keysOrder))
	for i, k := range keysOrder {
		keyToIndex[k] = i
	}
	indices := make([]int, 0, len(selectedKeys))
	for _, sk := range selectedKeys {
		idx, ok := keyToIndex[sk]
		if !ok {
			return nil, fmt.Errorf("selected key not found in data: %s", sk)
		}
		indices = append(indices, idx)
	}
	return sd.CreateDisclosure(leaves, indices)
}

func CreatePresentationForNode(tid0 string, nodeIndex int, data map[string]interface{}, selectedKeys []string) (*sd.Disclosure, error) {
	keysOrder, openings, err := DataToFieldOpenings(tid0, nodeIndex, data)
	if err != nil {
		return nil, err
	}
	keyToIndex := make(map[string]int, len(keysOrder))
	for i, k := range keysOrder {
		keyToIndex[k] = i
	}
	indices := make([]int, 0, len(selectedKeys))
	for _, sk := range selectedKeys {
		idx, ok := keyToIndex[sk]
		if !ok {
			return nil, fmt.Errorf("selected key not found in data: %s", sk)
		}
		indices = append(indices, idx)
	}
	return sd.CreateDisclosureFromOpenings(openings, indices)
}

func CreateFullEvidenceForNode(tid0 string, nodeIndex int, data map[string]interface{}) (*Evidence, error) {
	_, openings, err := DataToFieldOpenings(tid0, nodeIndex, data)
	if err != nil {
		return nil, err
	}
	return &Evidence{NodeOpenings: map[int][]sd.FieldOpening{nodeIndex: openings}}, nil
}

func ValidateJWSWithPresentations(jws string, version int8, presentations map[int]*sd.Disclosure, bundle ...*Payload) (bool, error) {
	ok, err := ValidateJWS(jws, version, bundle...)
	if err != nil || !ok {
		return false, err
	}
	parts := strings.Split(jws, ".")
	payloadB, _ := b64Decode(parts[1])
	var doc Payload
	if err := json.Unmarshal(payloadB, &doc); err != nil {
		return false, fmt.Errorf("unmarshal payload: %v", err)
	}

	verifyNode := func(nodePayload *Payload, pres *sd.Disclosure) (bool, error) {
		if nodePayload == nil {
			return false, fmt.Errorf("nil node payload")
		}
		root, ok := ExtractSDRootFromPayload(nodePayload)
		if !ok {
			return false, fmt.Errorf("node payload has no SD root")
		}
		okv, err := sd.VerifyDisclosure(pres)
		if err != nil || !okv {
			return false, fmt.Errorf("disclosure verification failed: %v", err)
		}
		if !bytes.Equal(root, pres.Root) {
			return false, fmt.Errorf("disclosure root mismatch")
		}
		return true, nil
	}

	if pres, ok := presentations[0]; ok {
		if _, err := verifyNode(&doc, pres); err != nil {
			return false, err
		}
	}

	for i, node := range doc.List {
		if node == nil || node.Payload == nil {
			continue
		}
		pres, ok := presentations[i+1]
		if !ok {
			if _, has := ExtractSDRootFromPayload(node.Payload); has {
				return false, fmt.Errorf("missing presentation for node %d", i+1)
			}
			continue
		}
		if _, err := verifyNode(node.Payload, pres); err != nil {
			return false, err
		}
	}
	return true, nil
}
