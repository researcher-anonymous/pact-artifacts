package sd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
)

// DisclosureSizeBreakdown describes where bytes go in the JSON encoding used by
// Disclosure.ToJSON/json.Marshal. JSON value byte counts include the encoded
// JSON value itself; structural byte counts cover object keys, colons, commas,
// braces, brackets, and opening field names.
type DisclosureSizeBreakdown struct {
	TotalJSONBytes int `json:"total_json_bytes"`

	RootRawBytes  int `json:"root_raw_bytes"`
	RootJSONBytes int `json:"root_json_bytes"`

	RevealedValueBytes     int `json:"revealed_value_bytes"`
	RevealedValueJSONBytes int `json:"revealed_value_json_bytes"`

	SaltRawBytes  int `json:"salt_raw_bytes"`
	SaltJSONBytes int `json:"salt_json_bytes"`

	MerkleProofRawBytes          int `json:"merkle_proof_raw_bytes"`
	MerkleProofJSONBytes         int `json:"merkle_proof_json_bytes"`
	MerkleProofUniqueRawBytes    int `json:"merkle_proof_unique_raw_bytes"`
	MerkleProofDuplicateRawBytes int `json:"merkle_proof_duplicate_raw_bytes"`

	LeafRawBytes  int `json:"leaf_raw_bytes"`
	LeafJSONBytes int `json:"leaf_json_bytes"`

	FieldNameBytes       int `json:"field_name_bytes"`
	FieldNameJSONBytes   int `json:"field_name_json_bytes"`
	OpeningMetaBytes     int `json:"opening_meta_bytes"`
	OpeningMetaJSONBytes int `json:"opening_meta_json_bytes"`
	IndicesJSONBytes     int `json:"indices_json_bytes"`
	CanonicalJSONBytes   int `json:"canonical_json_bytes"`

	TopLevelJSONOverhead int `json:"top_level_json_overhead"`
	OpeningsJSONOverhead int `json:"openings_json_overhead"`
	JSONOverheadBytes    int `json:"json_overhead_bytes"`

	DuplicatedRootRawBytes  int `json:"duplicated_root_raw_bytes"`
	DuplicatedRootJSONBytes int `json:"duplicated_root_json_bytes"`
	LeafHashRawBytes        int `json:"leaf_hash_raw_bytes"`
	CommitmentRawBytes      int `json:"commitment_raw_bytes"`

	BinaryBlobCurrentJSONBytes       int `json:"binary_blob_current_json_bytes"`
	BinaryBlobHexJSONBytesEstimate   int `json:"binary_blob_hex_json_bytes_estimate"`
	BinaryBlobBase64URLBytesEstimate int `json:"binary_blob_base64url_bytes_estimate"`
	HexInsteadOfCurrentBytesDelta    int `json:"hex_instead_of_current_bytes_delta"`
	Base64URLBytesSavingsEstimate    int `json:"base64url_bytes_savings_estimate"`

	CompactFieldIDBytesEstimate        int `json:"compact_field_id_bytes_estimate"`
	CompactFieldIDBytesSavingsEstimate int `json:"compact_field_id_bytes_savings_estimate"`
	MultiProofRawBytesSavingsEstimate  int `json:"multiproof_raw_bytes_savings_estimate"`
}

// DisclosureMapSizeBreakdown aggregates DisclosureSizeBreakdown values for a
// map of node-indexed disclosures, matching the presentation shape used by PACT
// benchmarks and PoC calls.
type DisclosureMapSizeBreakdown struct {
	DisclosureSizeBreakdown
	Objects              int `json:"objects"`
	MapTotalJSONBytes    int `json:"map_total_json_bytes"`
	MapJSONOverheadBytes int `json:"map_json_overhead_bytes"`
}

// DisclosureJSONSizeBreakdown returns a size attribution for the current JSON
// representation of a single disclosure.
func DisclosureJSONSizeBreakdown(d *Disclosure) (DisclosureSizeBreakdown, error) {
	if d == nil {
		return DisclosureSizeBreakdown{}, fmt.Errorf("nil disclosure")
	}
	encoded, err := json.Marshal(d)
	if err != nil {
		return DisclosureSizeBreakdown{}, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &top); err != nil {
		return DisclosureSizeBreakdown{}, err
	}

	out := DisclosureSizeBreakdown{
		TotalJSONBytes:          len(encoded),
		RootRawBytes:            len(d.Root),
		RootJSONBytes:           len(top["root"]),
		IndicesJSONBytes:        len(top["indices"]),
		MerkleProofJSONBytes:    len(top["proofs"]),
		LeafJSONBytes:           len(top["leaves"]),
		CanonicalJSONBytes:      len(top["canonical"]),
		DuplicatedRootRawBytes:  len(d.Root),
		DuplicatedRootJSONBytes: topFieldBytes("root", top["root"]),
	}

	for _, leaf := range d.Leaves {
		out.LeafRawBytes += len(leaf)
	}

	seenProofs := map[string]struct{}{}
	for _, proof := range d.Proofs {
		for _, sibling := range proof {
			out.MerkleProofRawBytes += len(sibling)
			seenProofs[string(sibling)] = struct{}{}
		}
	}
	for proof := range seenProofs {
		out.MerkleProofUniqueRawBytes += len(proof)
	}
	out.MerkleProofDuplicateRawBytes = out.MerkleProofRawBytes - out.MerkleProofUniqueRawBytes
	out.MultiProofRawBytesSavingsEstimate = out.MerkleProofDuplicateRawBytes

	var openingValuesJSON int
	if raw, ok := top["openings"]; ok {
		var openings []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &openings); err != nil {
			return DisclosureSizeBreakdown{}, err
		}
		for i, opening := range openings {
			if i < len(d.Openings) {
				out.RevealedValueBytes += len(d.Openings[i].Value)
				out.SaltRawBytes += len(d.Openings[i].Salt)
				out.FieldNameBytes += len(d.Openings[i].Tag)
				out.OpeningMetaBytes += len(d.Openings[i].TID0)
				out.OpeningMetaBytes += len(strconv.Itoa(d.Openings[i].NodeIndex))
				out.OpeningMetaBytes += len(strconv.Itoa(d.Openings[i].FieldIndex))
			}
			out.RevealedValueJSONBytes += len(opening["value"])
			out.SaltJSONBytes += len(opening["salt"])
			out.FieldNameJSONBytes += len(opening["tag"])
			out.OpeningMetaJSONBytes += len(opening["tid_0"])
			out.OpeningMetaJSONBytes += len(opening["node_index"])
			out.OpeningMetaJSONBytes += len(opening["field_index"])
			openingValuesJSON += len(opening["value"])
			openingValuesJSON += len(opening["salt"])
			openingValuesJSON += len(opening["tag"])
			openingValuesJSON += len(opening["tid_0"])
			openingValuesJSON += len(opening["node_index"])
			openingValuesJSON += len(opening["field_index"])
		}
		out.OpeningsJSONOverhead = len(raw) - openingValuesJSON
	}

	out.TopLevelJSONOverhead = objectOverhead(top)
	out.JSONOverheadBytes = out.TotalJSONBytes - out.rawPayloadBytes()

	addBlob := func(raw []byte) {
		current := jsonBytesValueLen(raw)
		out.BinaryBlobCurrentJSONBytes += current
		out.BinaryBlobHexJSONBytesEstimate += 2 + len(raw)*2
		out.BinaryBlobBase64URLBytesEstimate += 2 + len(base64.RawURLEncoding.EncodeToString(raw))
	}
	if len(d.Root) > 0 {
		addBlob(d.Root)
	}
	for _, leaf := range d.Leaves {
		addBlob(leaf)
	}
	for _, proof := range d.Proofs {
		for _, sibling := range proof {
			addBlob(sibling)
		}
	}
	for _, opening := range d.Openings {
		addBlob(opening.Salt)
		out.CompactFieldIDBytesEstimate += len(strconv.Itoa(opening.FieldIndex))
	}
	out.HexInsteadOfCurrentBytesDelta = out.BinaryBlobHexJSONBytesEstimate - out.BinaryBlobCurrentJSONBytes
	out.Base64URLBytesSavingsEstimate = out.BinaryBlobCurrentJSONBytes - out.BinaryBlobBase64URLBytesEstimate
	out.CompactFieldIDBytesSavingsEstimate = out.FieldNameJSONBytes - out.CompactFieldIDBytesEstimate

	// Salted disclosures recompute commitments and leaf hashes during
	// verification. These are kept explicit so accidental additions show up in
	// diagnostics without needing to inspect the struct by hand.
	out.LeafHashRawBytes = 0
	out.CommitmentRawBytes = out.LeafRawBytes

	return out, nil
}

// DisclosureMapJSONSizeBreakdown aggregates the per-object breakdown and also
// reports JSON overhead from the surrounding node-indexed map.
func DisclosureMapJSONSizeBreakdown(disclosures map[int]*Disclosure) (DisclosureMapSizeBreakdown, error) {
	encoded, err := json.Marshal(disclosures)
	if err != nil {
		return DisclosureMapSizeBreakdown{}, err
	}
	out := DisclosureMapSizeBreakdown{
		Objects:           len(disclosures),
		MapTotalJSONBytes: len(encoded),
	}
	for _, d := range disclosures {
		breakdown, err := DisclosureJSONSizeBreakdown(d)
		if err != nil {
			return DisclosureMapSizeBreakdown{}, err
		}
		out.DisclosureSizeBreakdown.add(breakdown)
	}
	out.MapJSONOverheadBytes = out.MapTotalJSONBytes - out.TotalJSONBytes
	return out, nil
}

func (b *DisclosureSizeBreakdown) add(other DisclosureSizeBreakdown) {
	b.TotalJSONBytes += other.TotalJSONBytes
	b.RootRawBytes += other.RootRawBytes
	b.RootJSONBytes += other.RootJSONBytes
	b.RevealedValueBytes += other.RevealedValueBytes
	b.RevealedValueJSONBytes += other.RevealedValueJSONBytes
	b.SaltRawBytes += other.SaltRawBytes
	b.SaltJSONBytes += other.SaltJSONBytes
	b.MerkleProofRawBytes += other.MerkleProofRawBytes
	b.MerkleProofJSONBytes += other.MerkleProofJSONBytes
	b.MerkleProofUniqueRawBytes += other.MerkleProofUniqueRawBytes
	b.MerkleProofDuplicateRawBytes += other.MerkleProofDuplicateRawBytes
	b.LeafRawBytes += other.LeafRawBytes
	b.LeafJSONBytes += other.LeafJSONBytes
	b.FieldNameBytes += other.FieldNameBytes
	b.FieldNameJSONBytes += other.FieldNameJSONBytes
	b.OpeningMetaBytes += other.OpeningMetaBytes
	b.OpeningMetaJSONBytes += other.OpeningMetaJSONBytes
	b.IndicesJSONBytes += other.IndicesJSONBytes
	b.CanonicalJSONBytes += other.CanonicalJSONBytes
	b.TopLevelJSONOverhead += other.TopLevelJSONOverhead
	b.OpeningsJSONOverhead += other.OpeningsJSONOverhead
	b.JSONOverheadBytes += other.JSONOverheadBytes
	b.DuplicatedRootRawBytes += other.DuplicatedRootRawBytes
	b.DuplicatedRootJSONBytes += other.DuplicatedRootJSONBytes
	b.LeafHashRawBytes += other.LeafHashRawBytes
	b.CommitmentRawBytes += other.CommitmentRawBytes
	b.BinaryBlobCurrentJSONBytes += other.BinaryBlobCurrentJSONBytes
	b.BinaryBlobHexJSONBytesEstimate += other.BinaryBlobHexJSONBytesEstimate
	b.BinaryBlobBase64URLBytesEstimate += other.BinaryBlobBase64URLBytesEstimate
	b.HexInsteadOfCurrentBytesDelta += other.HexInsteadOfCurrentBytesDelta
	b.Base64URLBytesSavingsEstimate += other.Base64URLBytesSavingsEstimate
	b.CompactFieldIDBytesEstimate += other.CompactFieldIDBytesEstimate
	b.CompactFieldIDBytesSavingsEstimate += other.CompactFieldIDBytesSavingsEstimate
	b.MultiProofRawBytesSavingsEstimate += other.MultiProofRawBytesSavingsEstimate
}

func (b DisclosureSizeBreakdown) rawPayloadBytes() int {
	return b.RootRawBytes +
		b.RevealedValueBytes +
		b.SaltRawBytes +
		b.MerkleProofRawBytes +
		b.LeafRawBytes +
		b.FieldNameBytes +
		b.OpeningMetaBytes
}

func objectOverhead(fields map[string]json.RawMessage) int {
	if len(fields) == 0 {
		return 2
	}
	total := 2 + len(fields) - 1
	for key, value := range fields {
		total += len(strconv.Quote(key)) + 1 + len(value)
	}
	valueBytes := 0
	for _, value := range fields {
		valueBytes += len(value)
	}
	return total - valueBytes
}

func topFieldBytes(key string, value json.RawMessage) int {
	if value == nil {
		return 0
	}
	return len(strconv.Quote(key)) + 1 + len(value)
}

func jsonBytesValueLen(raw []byte) int {
	b, err := json.Marshal(raw)
	if err != nil {
		return 0
	}
	return len(b)
}
