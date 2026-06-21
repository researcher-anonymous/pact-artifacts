// sd/merkle.go
package sd

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// Node/hashes are raw bytes (32 bytes for SHA-256)

const DomainSelectiveDisclosure = "PACT-SD-v1"
const DefaultSaltSize = 32

// FieldOpening is the cleartext evidence needed to recompute a field
// commitment. It is intentionally independent from the Merkle proof layer so
// the same commitment can be used in full evidence and selective disclosures.
type FieldOpening struct {
	TID0       string          `json:"tid_0"`
	NodeIndex  int             `json:"node_index"`
	FieldIndex int             `json:"field_index"`
	Tag        string          `json:"tag"`
	Salt       []byte          `json:"salt"`
	Value      json.RawMessage `json:"value"`
}

func CanonicalFieldEncoding(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func NewRandomFieldOpening(tid0 string, nodeIndex, fieldIndex int, tag string, value interface{}) (FieldOpening, error) {
	salt := make([]byte, DefaultSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return FieldOpening{}, err
	}
	return NewFieldOpening(tid0, nodeIndex, fieldIndex, tag, salt, value)
}

func NewDeterministicFieldOpeningForTest(tid0 string, nodeIndex, fieldIndex int, tag string, value interface{}) (FieldOpening, error) {
	enc, err := CanonicalFieldEncoding(value)
	if err != nil {
		return FieldOpening{}, err
	}
	h := sha256.Sum256(lengthPrefixed(
		[]byte("PACT-SD-test-salt-v1"),
		[]byte(tid0),
		uint64Bytes(uint64(nodeIndex)),
		uint64Bytes(uint64(fieldIndex)),
		[]byte(tag),
		enc,
	))
	return NewFieldOpening(tid0, nodeIndex, fieldIndex, tag, h[:], value)
}

func NewFieldOpening(tid0 string, nodeIndex, fieldIndex int, tag string, salt []byte, value interface{}) (FieldOpening, error) {
	if tid0 == "" {
		return FieldOpening{}, errors.New("missing tid_0")
	}
	if tag == "" {
		return FieldOpening{}, errors.New("missing tag")
	}
	if len(salt) == 0 {
		return FieldOpening{}, errors.New("missing salt")
	}
	enc, err := CanonicalFieldEncoding(value)
	if err != nil {
		return FieldOpening{}, err
	}
	saltCopy := append([]byte(nil), salt...)
	return FieldOpening{
		TID0:       tid0,
		NodeIndex:  nodeIndex,
		FieldIndex: fieldIndex,
		Tag:        tag,
		Salt:       saltCopy,
		Value:      enc,
	}, nil
}

func CommitmentForOpening(o FieldOpening) ([]byte, error) {
	input, err := CommitmentInput(o)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(input)
	return h[:], nil
}

func CommitmentInput(o FieldOpening) ([]byte, error) {
	if o.TID0 == "" {
		return nil, fmt.Errorf("missing tid_0")
	}
	if o.NodeIndex < 0 {
		return nil, fmt.Errorf("negative node index")
	}
	if o.FieldIndex < 0 {
		return nil, fmt.Errorf("negative field index")
	}
	if o.Tag == "" {
		return nil, fmt.Errorf("missing tag")
	}
	if len(o.Salt) == 0 {
		return nil, fmt.Errorf("missing salt")
	}
	if len(o.Value) == 0 {
		return nil, fmt.Errorf("missing value")
	}
	return lengthPrefixed(
		[]byte(DomainSelectiveDisclosure),
		[]byte(o.TID0),
		uint64Bytes(uint64(o.NodeIndex)),
		uint64Bytes(uint64(o.FieldIndex)),
		[]byte(o.Tag),
		o.Salt,
		o.Value,
	), nil
}

func CommitmentHex(o FieldOpening) (string, error) {
	c, err := CommitmentForOpening(o)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(c), nil
}

func lengthPrefixed(parts ...[]byte) []byte {
	out := make([]byte, 0)
	for _, p := range parts {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(p)))
		out = append(out, l[:]...)
		out = append(out, p...)
	}
	return out
}

func uint64Bytes(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

func OpeningsToCommitments(openings []FieldOpening) ([][]byte, error) {
	commitments := make([][]byte, 0, len(openings))
	for _, opening := range openings {
		c, err := CommitmentForOpening(opening)
		if err != nil {
			return nil, err
		}
		commitments = append(commitments, c)
	}
	return commitments, nil
}

// domain-separated leaf and node hashing
func hashLeaf(data []byte) []byte {
	h := sha256.Sum256(append([]byte{0x00}, data...)) // domain-separate leaf
	return h[:]
}

func hashNode(left, right []byte) []byte {
	h := sha256.Sum256(append(append([]byte{0x01}, left...), right...))
	return h[:]
}

// MerkleRoot computes root of tree built from leaves. Leaves must be in canonical order.
// Empty tree -> error.
func MerkleRoot(leaves [][]byte) ([]byte, error) {
	n := len(leaves)
	if n == 0 {
		return nil, errors.New("no leaves")
	}
	// compute leaf hashes
	level := make([][]byte, n)
	for i := range leaves {
		level[i] = hashLeaf(leaves[i])
	}

	for len(level) > 1 {
		if len(level)%2 == 1 {
			// duplicate last for pairing (standard approach)
			level = append(level, level[len(level)-1])
		}
		next := make([][]byte, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next[i/2] = hashNode(level[i], level[i+1])
		}
		level = next
	}
	return level[0], nil
}

// ProofFor returns the sibling hashes from leaf index to root (left/right order preserved).
// The proof is an array of sibling hashes as []byte.
func ProofFor(leaves [][]byte, idx int) ([][]byte, error) {
	n := len(leaves)
	if n == 0 {
		return nil, errors.New("no leaves")
	}
	if idx < 0 || idx >= n {
		return nil, fmt.Errorf("index out of bounds")
	}

	// compute layer 0 hashes
	layer := make([][]byte, n)
	for i := range leaves {
		layer[i] = hashLeaf(leaves[i])
	}

	proof := make([][]byte, 0)
	i := idx
	for len(layer) > 1 {
		if len(layer)%2 == 1 {
			layer = append(layer, layer[len(layer)-1])
		}
		sibling := i ^ 1
		proof = append(proof, layer[sibling])
		// build next layer
		next := make([][]byte, len(layer)/2)
		for j := 0; j < len(layer); j += 2 {
			next[j/2] = hashNode(layer[j], layer[j+1])
		}
		i = i / 2
		layer = next
	}
	return proof, nil
}

// VerifyProof verifies that `leaf` with `proof` at index `idx` produces `root`.
func VerifyProof(root []byte, leaf []byte, idx int, proof [][]byte) bool {
	// compute leaf hash
	h := hashLeaf(leaf)
	i := idx
	for _, sib := range proof {
		if i%2 == 0 {
			h = hashNode(h, sib)
		} else {
			h = hashNode(sib, h)
		}
		i = i / 2
	}
	return bytes.Equal(h, root)
}

// Disclosure holds the subset of leaves plus the proofs needed to re-create the root.
// This type is intentionally signature-agnostic: the package does NOT perform any signature
// verification. Signing/authenticating the root is the responsibility of the caller.
type Disclosure struct {
	Root      []byte         `json:"root"`             // merkle root
	Indices   []int          `json:"indices"`          // indices of disclosed leaves (in canonical order)
	Leaves    [][]byte       `json:"leaves,omitempty"` // corresponding leaf bytes
	Proofs    [][][]byte     `json:"proofs"`           // proofs for each disclosed leaf
	Openings  []FieldOpening `json:"openings,omitempty"`
	Canonical bool           `json:"-"` // debug metadata; verification is defined by openings/leaves and proofs.
}

// CreateDisclosure creates a Disclosure for given leaves and selected indices.
// It computes proofs for each selected index and sets Root. It does not perform or store any signature.
// Selected indices are validated, deduplicated and returned in ascending order.
func CreateDisclosure(leaves [][]byte, selected []int) (*Disclosure, error) {
	if len(leaves) == 0 {
		return nil, errors.New("no leaves")
	}

	// copy and sort selected, then deduplicate and validate bounds
	idxs := append([]int{}, selected...)
	sort.Ints(idxs)
	unique := make([]int, 0, len(idxs))
	prev := -1
	for _, v := range idxs {
		if v < 0 || v >= len(leaves) {
			return nil, fmt.Errorf("selected index out of bounds: %d", v)
		}
		if v == prev {
			continue
		}
		unique = append(unique, v)
		prev = v
	}

	root, err := MerkleRoot(leaves)
	if err != nil {
		return nil, err
	}
	disc := &Disclosure{
		Root:      root,
		Indices:   unique,
		Leaves:    make([][]byte, 0, len(unique)),
		Proofs:    make([][][]byte, 0, len(unique)),
		Canonical: true,
	}
	for _, i := range unique {
		disc.Leaves = append(disc.Leaves, leaves[i])
		proof, err := ProofFor(leaves, i)
		if err != nil {
			return nil, err
		}
		disc.Proofs = append(disc.Proofs, proof)
	}
	return disc, nil
}

func CreateDisclosureFromOpenings(openings []FieldOpening, selected []int) (*Disclosure, error) {
	commitments, err := OpeningsToCommitments(openings)
	if err != nil {
		return nil, err
	}
	disc, err := CreateDisclosure(commitments, selected)
	if err != nil {
		return nil, err
	}
	disc.Openings = make([]FieldOpening, 0, len(disc.Indices))
	disc.Leaves = nil
	for _, i := range disc.Indices {
		disc.Openings = append(disc.Openings, openings[i])
	}
	return disc, nil
}

// VerifyDisclosure checks all proofs reconstruct the same Root. It does NOT verify signatures.
// Returns (true, nil) on success or (false, error) otherwise.
func VerifyDisclosure(d *Disclosure) (bool, error) {
	if d == nil {
		return false, errors.New("nil disclosure")
	}
	if len(d.Openings) > 0 {
		if len(d.Indices) != len(d.Openings) || len(d.Openings) != len(d.Proofs) {
			return false, errors.New("inconsistent disclosure lengths")
		}
		for k, idx := range d.Indices {
			commitment, err := CommitmentForOpening(d.Openings[k])
			if err != nil {
				return false, err
			}
			if !VerifyProof(d.Root, commitment, idx, d.Proofs[k]) {
				return false, fmt.Errorf("proof failed for index %d", idx)
			}
		}
		return true, nil
	}
	if len(d.Indices) != len(d.Leaves) || len(d.Leaves) != len(d.Proofs) {
		return false, errors.New("inconsistent disclosure lengths")
	}
	for k, idx := range d.Indices {
		if !VerifyProof(d.Root, d.Leaves[k], idx, d.Proofs[k]) {
			return false, fmt.Errorf("proof failed for index %d", idx)
		}
	}
	return true, nil
}

// Helpers to marshal / unmarshal disclosure JSON
func (d *Disclosure) ToJSON() ([]byte, error) {
	return json.Marshal(d)
}

func FromJSON(b []byte) (*Disclosure, error) {
	var d Disclosure
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return &d, nil
}
