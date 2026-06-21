package pact_test

import (
	"encoding/json"
	"fmt"
	"testing"

	sd "flow-poc/sd"
)

var (
	sdFieldCounts  = []int{4, 8, 16, 32, 64}
	sdRevealCounts = []int{1, 2, 4, 8}
)

func buildSDOpenings(fields int) []sd.FieldOpening {
	openings := make([]sd.FieldOpening, 0, fields)
	for i := 0; i < fields; i++ {
		opening, err := sd.NewRandomFieldOpening(
			"tid-bench-sd",
			0,
			i,
			fmt.Sprintf("field_%02d", i),
			map[string]interface{}{
				"value": fmt.Sprintf("value-%02d", i),
				"flag":  i%2 == 0,
			},
		)
		if err != nil {
			panic(err)
		}
		openings = append(openings, opening)
	}
	return openings
}

func firstIndexes(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

func BenchmarkSD(b *testing.B) {
	b.Run("CreateRoot", func(b *testing.B) {
		for _, fields := range sdFieldCounts {
			fields := fields
			b.Run(fmt.Sprintf("fields=%d", fields), func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					openings := buildSDOpenings(fields)
					commitments, err := sd.OpeningsToCommitments(openings)
					if err != nil {
						b.Fatal(err)
					}
					root, err := sd.MerkleRoot(commitments)
					if err != nil {
						b.Fatal(err)
					}
					benchSink = root
				}
			})
		}
	})

	b.Run("CreateDisclosure", func(b *testing.B) {
		for _, fields := range sdFieldCounts {
			for _, reveal := range sdRevealCounts {
				fields, reveal := fields, reveal
				if reveal > fields {
					continue
				}
				b.Run(fmt.Sprintf("fields=%d/reveal=%d", fields, reveal), func(b *testing.B) {
					openings := buildSDOpenings(fields)
					selected := firstIndexes(reveal)
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						disc, err := sd.CreateDisclosureFromOpenings(openings, selected)
						if err != nil {
							b.Fatal(err)
						}
						benchSink = disc
					}
				})
			}
		}
	})

	b.Run("VerifyDisclosure", func(b *testing.B) {
		for _, fields := range sdFieldCounts {
			for _, reveal := range sdRevealCounts {
				fields, reveal := fields, reveal
				if reveal > fields {
					continue
				}
				b.Run(fmt.Sprintf("fields=%d/reveal=%d", fields, reveal), func(b *testing.B) {
					openings := buildSDOpenings(fields)
					disc, err := sd.CreateDisclosureFromOpenings(openings, firstIndexes(reveal))
					if err != nil {
						b.Fatal(err)
					}
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						ok, err := sd.VerifyDisclosure(disc)
						if err != nil || !ok {
							b.Fatalf("verify failed: ok=%v err=%v", ok, err)
						}
					}
				})
			}
		}
	})

	b.Run("SizeDisclosure", func(b *testing.B) {
		for _, fields := range sdFieldCounts {
			for _, reveal := range sdRevealCounts {
				fields, reveal := fields, reveal
				if reveal > fields {
					continue
				}
				b.Run(fmt.Sprintf("fields=%d/reveal=%d", fields, reveal), func(b *testing.B) {
					openings := buildSDOpenings(fields)
					disc, err := sd.CreateDisclosureFromOpenings(openings, firstIndexes(reveal))
					if err != nil {
						b.Fatal(err)
					}
					encoded, err := json.Marshal(disc)
					if err != nil {
						b.Fatal(err)
					}
					b.ReportMetric(float64(len(encoded)), "disclosure_bytes")
					for i := 0; i < b.N; i++ {
						benchSink = len(encoded)
					}
				})
			}
		}
	})
}
