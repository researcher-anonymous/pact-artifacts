package sd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// This file contains experimental compact presentation helpers. They are not
// used by ValidatePACT or by the default Disclosure JSON encoding unless a
// benchmark or test explicitly selects them. The helpers preserve PACT's
// selective-disclosure semantics: disclosed openings are still committed with
// CommitmentForOpening, Merkle nodes are still hashed with the same leaf/node
// domains, and verification still binds the disclosed fields to the same node
// commitment root.

// RootlessDisclosure is an experimental token-bound serialization view for
// Disclosure. It omits Root because the verifier is expected to obtain the
// authenticated node Merkle root from the validated PACT token payload.
type RootlessDisclosure struct {
	Indices  []int          `json:"indices"`
	Leaves   [][]byte       `json:"leaves,omitempty"`
	Proofs   [][][]byte     `json:"proofs"`
	Openings []FieldOpening `json:"openings,omitempty"`
}

// DisclosureWithoutRoot returns an experimental rootless view of the existing
// Disclosure. It is intended only for token-bound presentations where the node
// root is authenticated externally by the PACT token.
func DisclosureWithoutRoot(d *Disclosure) RootlessDisclosure {
	if d == nil {
		return RootlessDisclosure{}
	}
	return RootlessDisclosure{
		Indices:  append([]int(nil), d.Indices...),
		Leaves:   cloneBytes2D(d.Leaves),
		Proofs:   cloneBytes3D(d.Proofs),
		Openings: append([]FieldOpening(nil), d.Openings...),
	}
}

// DisclosureMapWithoutRoot returns an experimental rootless presentation map.
func DisclosureMapWithoutRoot(disclosures map[int]*Disclosure) map[int]RootlessDisclosure {
	out := make(map[int]RootlessDisclosure, len(disclosures))
	for nodeIndex, d := range disclosures {
		out[nodeIndex] = DisclosureWithoutRoot(d)
	}
	return out
}

// VerifyDisclosureAgainstRoot verifies a disclosure using a root supplied by
// the caller. It is intended for token-bound verification where the root is
// authenticated in the token payload and therefore need not be serialized in
// the disclosure object. Standalone VerifyDisclosure remains available and
// unchanged for compatibility and tests.
func VerifyDisclosureAgainstRoot(d *Disclosure, root []byte) error {
	if d == nil {
		return errors.New("nil disclosure")
	}
	if len(root) == 0 {
		return errors.New("missing root")
	}
	if len(d.Openings) > 0 {
		if len(d.Indices) != len(d.Openings) || len(d.Openings) != len(d.Proofs) {
			return errors.New("inconsistent disclosure lengths")
		}
		for k, idx := range d.Indices {
			commitment, err := CommitmentForOpening(d.Openings[k])
			if err != nil {
				return err
			}
			if !VerifyProof(root, commitment, idx, d.Proofs[k]) {
				return fmt.Errorf("proof failed for index %d", idx)
			}
		}
		return nil
	}
	if len(d.Indices) != len(d.Leaves) || len(d.Leaves) != len(d.Proofs) {
		return errors.New("inconsistent disclosure lengths")
	}
	for k, idx := range d.Indices {
		if !VerifyProof(root, d.Leaves[k], idx, d.Proofs[k]) {
			return fmt.Errorf("proof failed for index %d", idx)
		}
	}
	return nil
}

// MultiProofNode is a positioned sibling hash used by the experimental
// multiproof format. Level 0 is the leaf-hash layer; Index is the node index in
// that padded layer.
type MultiProofNode struct {
	Level int    `json:"level"`
	Index int    `json:"index"`
	Hash  []byte `json:"hash"`
}

// MerkleMultiProofDisclosure is an experimental per-node presentation that
// deduplicates sibling hashes shared by multiple disclosed field paths. It uses
// the same field openings and commitment computation as Disclosure.
//
// Implementation note: in PACT the commitment root is authenticated by the
// token node. Token-bound presentations can therefore supply that root
// externally and omit Root from the serialized disclosure. The disclosure does
// not need to be standalone in that mode. Standalone disclosures, including
// the default JSON Disclosure format, remain available for compatibility and
// testing.
type MerkleMultiProofDisclosure struct {
	Root       []byte           `json:"root,omitempty"`
	LeafCount  int              `json:"leaf_count"`
	Indices    []int            `json:"indices"`
	Openings   []FieldOpening   `json:"openings,omitempty"`
	Leaves     [][]byte         `json:"leaves,omitempty"`
	ProofNodes []MultiProofNode `json:"proof_nodes"`
}

// RootlessMerkleMultiProofDisclosure is the token-bound serialization view of
// the experimental multiproof. It omits Root because the PACT token node
// supplies the authenticated root to the verifier.
type RootlessMerkleMultiProofDisclosure struct {
	LeafCount  int              `json:"leaf_count"`
	Indices    []int            `json:"indices"`
	Openings   []FieldOpening   `json:"openings,omitempty"`
	Leaves     [][]byte         `json:"leaves,omitempty"`
	ProofNodes []MultiProofNode `json:"proof_nodes"`
}

// WithoutRoot returns the token-bound serialization view for the experimental
// multiproof.
func (d *MerkleMultiProofDisclosure) WithoutRoot() RootlessMerkleMultiProofDisclosure {
	if d == nil {
		return RootlessMerkleMultiProofDisclosure{}
	}
	return RootlessMerkleMultiProofDisclosure{
		LeafCount:  d.LeafCount,
		Indices:    append([]int(nil), d.Indices...),
		Openings:   append([]FieldOpening(nil), d.Openings...),
		Leaves:     cloneBytes2D(d.Leaves),
		ProofNodes: append([]MultiProofNode(nil), d.ProofNodes...),
	}
}

// MultiProofMapWithoutRoot returns token-bound serialization views for an
// experimental multiproof map.
func MultiProofMapWithoutRoot(disclosures map[int]*MerkleMultiProofDisclosure) map[int]RootlessMerkleMultiProofDisclosure {
	out := make(map[int]RootlessMerkleMultiProofDisclosure, len(disclosures))
	for nodeIndex, d := range disclosures {
		out[nodeIndex] = d.WithoutRoot()
	}
	return out
}

// CreateMerkleMultiProofDisclosureFromOpenings builds an experimental
// multiproof disclosure from salted openings. It does not alter the stable
// Disclosure constructor.
func CreateMerkleMultiProofDisclosureFromOpenings(openings []FieldOpening, selected []int) (*MerkleMultiProofDisclosure, error) {
	commitments, err := OpeningsToCommitments(openings)
	if err != nil {
		return nil, err
	}
	d, err := CreateMerkleMultiProofDisclosure(commitments, selected)
	if err != nil {
		return nil, err
	}
	d.Openings = make([]FieldOpening, 0, len(d.Indices))
	d.Leaves = nil
	for _, i := range d.Indices {
		d.Openings = append(d.Openings, openings[i])
	}
	return d, nil
}

// CreateMerkleMultiProofDisclosure builds an experimental multiproof over raw
// Merkle leaves. Production PACT target paths should continue to use salted
// openings.
func CreateMerkleMultiProofDisclosure(leaves [][]byte, selected []int) (*MerkleMultiProofDisclosure, error) {
	if len(leaves) == 0 {
		return nil, errors.New("no leaves")
	}
	indices, err := normalizeSelectedIndices(len(leaves), selected)
	if err != nil {
		return nil, err
	}
	layers := merkleHashLayers(leaves)
	root := layers[len(layers)-1][0]
	proofNodes := multiProofNodes(layers, indices)
	d := &MerkleMultiProofDisclosure{
		Root:       root,
		LeafCount:  len(leaves),
		Indices:    indices,
		Leaves:     make([][]byte, 0, len(indices)),
		ProofNodes: proofNodes,
	}
	for _, idx := range indices {
		d.Leaves = append(d.Leaves, append([]byte(nil), leaves[idx]...))
	}
	return d, nil
}

// VerifyMerkleMultiProofDisclosure verifies an experimental standalone
// multiproof using the Root carried in the object.
func VerifyMerkleMultiProofDisclosure(d *MerkleMultiProofDisclosure) (bool, error) {
	if d == nil {
		return false, errors.New("nil multiproof disclosure")
	}
	if err := VerifyMerkleMultiProofDisclosureAgainstRoot(d, d.Root); err != nil {
		return false, err
	}
	return true, nil
}

// VerifyMerkleMultiProofDisclosureAgainstRoot verifies an experimental
// token-bound multiproof against an externally authenticated root.
func VerifyMerkleMultiProofDisclosureAgainstRoot(d *MerkleMultiProofDisclosure, root []byte) error {
	if d == nil {
		return errors.New("nil multiproof disclosure")
	}
	if len(root) == 0 {
		return errors.New("missing root")
	}
	if d.LeafCount <= 0 {
		return errors.New("missing leaf count")
	}
	if len(d.Openings) > 0 {
		if len(d.Openings) != len(d.Indices) {
			return errors.New("inconsistent multiproof openings")
		}
		return verifyMultiProofAgainstRoot(d.LeafCount, d.Indices, d.Openings, nil, d.ProofNodes, root)
	}
	if len(d.Leaves) != len(d.Indices) {
		return errors.New("inconsistent multiproof leaves")
	}
	return verifyMultiProofAgainstRoot(d.LeafCount, d.Indices, nil, d.Leaves, d.ProofNodes, root)
}

func verifyMultiProofAgainstRoot(leafCount int, indices []int, openings []FieldOpening, leaves [][]byte, proofNodes []MultiProofNode, root []byte) error {
	widths := merkleLayerWidths(leafCount)
	known := map[merkleNodeKey][]byte{}
	for i, idx := range indices {
		if idx < 0 || idx >= leafCount {
			return fmt.Errorf("selected index out of bounds: %d", idx)
		}
		var leaf []byte
		if len(openings) > 0 {
			commitment, err := CommitmentForOpening(openings[i])
			if err != nil {
				return err
			}
			leaf = commitment
		} else {
			leaf = leaves[i]
		}
		if err := putKnownNode(known, merkleNodeKey{level: 0, index: idx}, hashLeaf(leaf)); err != nil {
			return err
		}
	}
	for _, node := range proofNodes {
		if node.Level < 0 || node.Level >= len(widths)-1 {
			return fmt.Errorf("proof node level out of bounds: %d", node.Level)
		}
		if node.Index < 0 || node.Index >= widths[node.Level] {
			return fmt.Errorf("proof node index out of bounds: level=%d index=%d", node.Level, node.Index)
		}
		if len(node.Hash) == 0 {
			return fmt.Errorf("empty proof node hash: level=%d index=%d", node.Level, node.Index)
		}
		if err := putKnownNode(known, merkleNodeKey{level: node.Level, index: node.Index}, node.Hash); err != nil {
			return err
		}
	}

	frontier := append([]int(nil), indices...)
	for level := 0; level < len(widths)-1; level++ {
		frontier = uniqueSortedInts(frontier)
		nextFrontier := make([]int, 0, len(frontier))
		for _, idx := range frontier {
			leftIndex := idx
			if leftIndex%2 == 1 {
				leftIndex--
			}
			rightIndex := leftIndex + 1
			left, ok := known[merkleNodeKey{level: level, index: leftIndex}]
			if !ok {
				return fmt.Errorf("missing left node: level=%d index=%d", level, leftIndex)
			}
			right, ok := known[merkleNodeKey{level: level, index: rightIndex}]
			if !ok {
				return fmt.Errorf("missing right node: level=%d index=%d", level, rightIndex)
			}
			parentIndex := leftIndex / 2
			parent := hashNode(left, right)
			if err := putKnownNode(known, merkleNodeKey{level: level + 1, index: parentIndex}, parent); err != nil {
				return err
			}
			nextFrontier = append(nextFrontier, parentIndex)
		}
		frontier = nextFrontier
	}
	got := known[merkleNodeKey{level: len(widths) - 1, index: 0}]
	if !bytes.Equal(got, root) {
		return errors.New("multiproof root mismatch")
	}
	return nil
}

func normalizeSelectedIndices(leafCount int, selected []int) ([]int, error) {
	idxs := append([]int(nil), selected...)
	sort.Ints(idxs)
	unique := make([]int, 0, len(idxs))
	prev := -1
	for _, idx := range idxs {
		if idx < 0 || idx >= leafCount {
			return nil, fmt.Errorf("selected index out of bounds: %d", idx)
		}
		if idx == prev {
			continue
		}
		unique = append(unique, idx)
		prev = idx
	}
	return unique, nil
}

func merkleHashLayers(leaves [][]byte) [][][]byte {
	layer := make([][]byte, len(leaves))
	for i := range leaves {
		layer[i] = hashLeaf(leaves[i])
	}
	layers := [][][]byte{cloneBytes2D(layer)}
	for len(layer) > 1 {
		if len(layer)%2 == 1 {
			layer = append(layer, layer[len(layer)-1])
		}
		padded := cloneBytes2D(layer)
		layers[len(layers)-1] = padded
		next := make([][]byte, len(layer)/2)
		for i := 0; i < len(layer); i += 2 {
			next[i/2] = hashNode(layer[i], layer[i+1])
		}
		layer = next
		layers = append(layers, cloneBytes2D(layer))
	}
	return layers
}

func merkleLayerWidths(leafCount int) []int {
	widths := []int{leafCount}
	width := leafCount
	for width > 1 {
		if width%2 == 1 {
			width++
			widths[len(widths)-1] = width
		}
		width /= 2
		widths = append(widths, width)
	}
	return widths
}

func multiProofNodes(layers [][][]byte, selected []int) []MultiProofNode {
	frontier := append([]int(nil), selected...)
	out := make([]MultiProofNode, 0)
	included := map[merkleNodeKey]struct{}{}
	for level := 0; level < len(layers)-1; level++ {
		frontier = uniqueSortedInts(frontier)
		selectedAtLevel := map[int]struct{}{}
		for _, idx := range frontier {
			selectedAtLevel[idx] = struct{}{}
		}
		nextFrontier := make([]int, 0, len(frontier))
		for _, idx := range frontier {
			sibling := idx ^ 1
			if _, ok := selectedAtLevel[sibling]; !ok {
				key := merkleNodeKey{level: level, index: sibling}
				if _, seen := included[key]; !seen {
					included[key] = struct{}{}
					out = append(out, MultiProofNode{
						Level: level,
						Index: sibling,
						Hash:  append([]byte(nil), layers[level][sibling]...),
					})
				}
			}
			nextFrontier = append(nextFrontier, idx/2)
		}
		frontier = nextFrontier
	}
	return out
}

type merkleNodeKey struct {
	level int
	index int
}

func putKnownNode(known map[merkleNodeKey][]byte, key merkleNodeKey, hash []byte) error {
	if existing, ok := known[key]; ok {
		if !bytes.Equal(existing, hash) {
			return fmt.Errorf("conflicting node hash: level=%d index=%d", key.level, key.index)
		}
		return nil
	}
	known[key] = append([]byte(nil), hash...)
	return nil
}

func uniqueSortedInts(values []int) []int {
	if len(values) == 0 {
		return nil
	}
	sort.Ints(values)
	out := values[:0]
	prev := -1
	for _, value := range values {
		if value == prev {
			continue
		}
		out = append(out, value)
		prev = value
	}
	return out
}

func cloneBytes2D(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = append([]byte(nil), in[i]...)
	}
	return out
}

func cloneBytes3D(in [][][]byte) [][][]byte {
	if in == nil {
		return nil
	}
	out := make([][][]byte, len(in))
	for i := range in {
		out[i] = cloneBytes2D(in[i])
	}
	return out
}

// RootlessDisclosureJSON serializes the experimental rootless view of a
// Disclosure. The default Disclosure.ToJSON remains standalone and unchanged.
func RootlessDisclosureJSON(d *Disclosure) ([]byte, error) {
	view := DisclosureWithoutRoot(d)
	return json.Marshal(view)
}
