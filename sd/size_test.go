package sd

import "testing"

func TestDisclosureJSONSizeBreakdownSaltedDisclosure(t *testing.T) {
	openings := make([]FieldOpening, 0, 4)
	for i, tag := range []string{"task_id", "dataset_id", "purpose", "audience"} {
		opening, err := NewDeterministicFieldOpeningForTest("tid-size-test", 0, i, tag, "value-"+tag)
		if err != nil {
			t.Fatal(err)
		}
		openings = append(openings, opening)
	}
	d, err := CreateDisclosureFromOpenings(openings, []int{0, 2})
	if err != nil {
		t.Fatal(err)
	}
	breakdown, err := DisclosureJSONSizeBreakdown(d)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := d.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	if breakdown.TotalJSONBytes != len(encoded) {
		t.Fatalf("total_json_bytes = %d, want %d", breakdown.TotalJSONBytes, len(encoded))
	}
	if breakdown.LeafRawBytes != 0 || breakdown.LeafJSONBytes != 0 {
		t.Fatalf("salted disclosure should not carry leaves, raw=%d json=%d", breakdown.LeafRawBytes, breakdown.LeafJSONBytes)
	}
	if breakdown.RevealedValueBytes == 0 || breakdown.SaltRawBytes == 0 || breakdown.MerkleProofRawBytes == 0 {
		t.Fatalf("missing expected value/salt/proof attribution: %+v", breakdown)
	}
	if breakdown.DuplicatedRootRawBytes != len(d.Root) {
		t.Fatalf("duplicated root bytes = %d, want %d", breakdown.DuplicatedRootRawBytes, len(d.Root))
	}
	if breakdown.HexInsteadOfCurrentBytesDelta <= 0 {
		t.Fatalf("expected hex estimate to be larger than current []byte JSON, got %d", breakdown.HexInsteadOfCurrentBytesDelta)
	}
}
