package sd_test

import (
	"encoding/json"
	"fmt"
	"testing"

	sd "flow-poc/sd"
)

// total number of claims in the committed set
var sdTotalClaims = []int{4, 8, 16, 32, 64, 128}

// number of disclosed claims
var sdRevealCounts = []int{1, 2, 4, 8}

func buildLeaves(n int) [][]byte {
	leaves := make([][]byte, n)
	for i := 0; i < n; i++ {
		leaves[i] = []byte(fmt.Sprintf("claim-%d=true", i))
	}
	return leaves
}

func selectIndices(total, reveal int) []int {
	if reveal > total {
		reveal = total
	}
	ids := make([]int, reveal)
	for i := 0; i < reveal; i++ {
		ids[i] = i
	}
	return ids
}

func Benchmark_DisclosureCreate(b *testing.B) {
	for _, total := range sdTotalClaims {
		leaves := buildLeaves(total)
		for _, reveal := range sdRevealCounts {
			if reveal > total {
				continue
			}
			indices := selectIndices(total, reveal)
			name := fmt.Sprintf("Claims_%d_Reveal_%d/Create", total, reveal)

			b.Run(name, func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, err := sd.CreateDisclosure(leaves, indices)
					if err != nil {
						b.Fatalf("create disclosure failed: %v", err)
					}
				}
			})
		}
	}
}

func Benchmark_DisclosureVerify(b *testing.B) {
	for _, total := range sdTotalClaims {
		leaves := buildLeaves(total)
		for _, reveal := range sdRevealCounts {
			if reveal > total {
				continue
			}
			indices := selectIndices(total, reveal)
			disc, err := sd.CreateDisclosure(leaves, indices)
			if err != nil {
				b.Fatalf("create disclosure failed: %v", err)
			}

			name := fmt.Sprintf("Claims_%d_Reveal_%d/Verify", total, reveal)
			b.Run(name, func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					ok, err := sd.VerifyDisclosure(disc)
					if err != nil {
						b.Fatalf("verify disclosure error: %v", err)
					}
					if !ok {
						b.Fatalf("verify disclosure failed")
					}
				}
			})
		}
	}
}

func Benchmark_DisclosureSize(b *testing.B) {
	for _, total := range sdTotalClaims {
		leaves := buildLeaves(total)
		for _, reveal := range sdRevealCounts {
			if reveal > total {
				continue
			}
			indices := selectIndices(total, reveal)
			disc, err := sd.CreateDisclosure(leaves, indices)
			if err != nil {
				b.Fatalf("create disclosure failed: %v", err)
			}

			size := disclosureSize(disc)
			name := fmt.Sprintf("Claims_%d_Reveal_%d/Size", total, reveal)

			b.Run(name, func(b *testing.B) {
				b.ReportMetric(float64(size), "bytes")
				breakdown, err := sd.DisclosureJSONSizeBreakdown(disc)
				if err != nil {
					b.Fatalf("break down disclosure size: %v", err)
				}
				b.ReportMetric(float64(breakdown.RootJSONBytes), "root_json_bytes")
				b.ReportMetric(float64(breakdown.LeafJSONBytes), "leaf_json_bytes")
				b.ReportMetric(float64(breakdown.MerkleProofJSONBytes), "merkle_proof_json_bytes")
				b.ReportMetric(float64(breakdown.MerkleProofDuplicateRawBytes), "merkle_proof_duplicate_raw_bytes")
				b.ReportMetric(float64(breakdown.JSONOverheadBytes), "json_overhead_bytes")
				b.ReportMetric(float64(breakdown.HexInsteadOfCurrentBytesDelta), "hex_instead_of_current_bytes_delta")
				b.ReportMetric(float64(breakdown.Base64URLBytesSavingsEstimate), "base64url_savings_estimate")
			})
		}
	}
}

func disclosureSize(d *sd.Disclosure) int {
	b, err := json.Marshal(d)
	if err != nil {
		panic(err)
	}
	return len(b)
}
