package sd

import (
	"encoding/json"
	"testing"
)

func TestVerifyDisclosureAgainstRootAllowsRootlessSerialization(t *testing.T) {
	openings := deterministicOpeningsForExperimentalTest(t, 8)
	d, err := CreateDisclosureFromOpenings(openings, []int{0, 2, 5})
	if err != nil {
		t.Fatal(err)
	}
	root := append([]byte(nil), d.Root...)
	if err := VerifyDisclosureAgainstRoot(d, root); err != nil {
		t.Fatalf("verify against root: %v", err)
	}

	rootless := DisclosureWithoutRoot(d)
	encoded, err := json.Marshal(rootless)
	if err != nil {
		t.Fatal(err)
	}
	var decoded RootlessDisclosure
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	rehydrated := &Disclosure{
		Indices:  decoded.Indices,
		Leaves:   decoded.Leaves,
		Proofs:   decoded.Proofs,
		Openings: decoded.Openings,
	}
	if err := VerifyDisclosureAgainstRoot(rehydrated, root); err != nil {
		t.Fatalf("verify decoded rootless disclosure: %v", err)
	}
	if ok, err := VerifyDisclosure(rehydrated); err == nil || ok {
		t.Fatal("standalone verification unexpectedly accepted a rootless disclosure")
	}
}

func TestMerkleMultiProofDisclosureVerifiesSameRoot(t *testing.T) {
	openings := deterministicOpeningsForExperimentalTest(t, 13)
	selected := []int{0, 2, 3, 8, 12}
	regular, err := CreateDisclosureFromOpenings(openings, selected)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifyDisclosure(regular); err != nil || !ok {
		t.Fatalf("regular disclosure verify: ok=%v err=%v", ok, err)
	}
	mp, err := CreateMerkleMultiProofDisclosureFromOpenings(openings, selected)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMerkleMultiProofDisclosureAgainstRoot(mp, regular.Root); err != nil {
		t.Fatalf("multiproof verify against regular root: %v", err)
	}
	if !equalBytes(mp.Root, regular.Root) {
		t.Fatal("multiproof root differs from regular disclosure root")
	}
	if len(mp.ProofNodes) >= countIndividualProofNodes(regular) {
		t.Fatalf("multiproof did not deduplicate proof nodes: got %d individual %d", len(mp.ProofNodes), countIndividualProofNodes(regular))
	}
}

func TestMerkleMultiProofDisclosureRejectsTampering(t *testing.T) {
	openings := deterministicOpeningsForExperimentalTest(t, 8)
	mp, err := CreateMerkleMultiProofDisclosureFromOpenings(openings, []int{1, 2, 6})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMerkleMultiProofDisclosureAgainstRoot(mp, mp.Root); err != nil {
		t.Fatalf("verify before tamper: %v", err)
	}
	tampered := *mp
	tampered.Openings = append([]FieldOpening(nil), mp.Openings...)
	tampered.Openings[0].Value = json.RawMessage(`"other"`)
	if err := VerifyMerkleMultiProofDisclosureAgainstRoot(&tampered, mp.Root); err == nil {
		t.Fatal("tampered multiproof unexpectedly verified")
	}
}

func deterministicOpeningsForExperimentalTest(t *testing.T, n int) []FieldOpening {
	t.Helper()
	openings := make([]FieldOpening, 0, n)
	for i := 0; i < n; i++ {
		opening, err := NewDeterministicFieldOpeningForTest("tid-experimental", 0, i, "field_"+string(rune('a'+i)), map[string]interface{}{
			"value": i,
			"flag":  i%2 == 0,
		})
		if err != nil {
			t.Fatal(err)
		}
		openings = append(openings, opening)
	}
	return openings
}

func countIndividualProofNodes(d *Disclosure) int {
	total := 0
	for _, proof := range d.Proofs {
		total += len(proof)
	}
	return total
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
