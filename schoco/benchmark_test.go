package schoco_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"anonymous-artifact/schoco"
	"filippo.io/edwards25519"
)

type BenchmarkResult struct {
	Hops               int64 `json:"hops"`
	SignIndividualNS   int64 `json:"sign_individual_ns"`
	SignAggregateNS    int64 `json:"sign_aggregate_ns"`
	VerifyIndividualNS int64 `json:"verify_individual_ns"`
	VerifyAggregateNS  int64 `json:"verify_aggregate_ns"`
}

func TestCompareAggregation(t *testing.T) {
	var results []BenchmarkResult

	for hops := int64(1); hops <= 40; hops += 5 {

		// --- Key generation ---
		sk, pk, err := schoco.KeyPair()
		if err != nil {
			t.Fatal(err)
		}

		var (
			msgs        [][]byte
			sigs        []*schoco.Signature
			aggSig      *schoco.Signature
			aggMsgs     [][]byte
			aggPartSigs []*edwards25519.Point
		)

		// --- Generate Messages ---
		for i := int64(0); i < hops; i++ {
			msgs = append(msgs, []byte(fmt.Sprintf("msg-%d", i)))
		}

		// =====================================================
		// Sign Individually
		// =====================================================
		start := time.Now()
		for _, m := range msgs {
			sig, err := schoco.StdSign(m, sk)
			if err != nil {
				t.Fatal(err)
			}
			sigs = append(sigs, sig)
		}
		signIndividualNS := time.Since(start).Nanoseconds()

		// =====================================================
		// Sign Aggregated
		// =====================================================
		start = time.Now()

		aggSig, err = schoco.StdSign(msgs[0], sk)
		if err != nil {
			t.Fatal(err)
		}

		aggMsgs = [][]byte{msgs[0]}

		for i := 1; i < len(msgs); i++ {
			partSig, newSig, err := schoco.Aggregate(msgs[i], aggSig)
			if err != nil {
				t.Fatal(err)
			}

			aggSig = newSig

			// prepend (ordem importa para Verify)
			aggPartSigs = append([]*edwards25519.Point{partSig}, aggPartSigs...)
			aggMsgs = append([][]byte{msgs[i]}, aggMsgs...)
		}

		signAggregateNS := time.Since(start).Nanoseconds()

		// =====================================================
		// Verify Individually usando StdVerify
		// =====================================================
		start = time.Now()
		for i := range sigs {
			if !schoco.StdVerify(msgs[i], sigs[i], pk) {
				t.Fatal("StdVerify failed for individual message")
			}
		}
		verifyIndividualNS := time.Since(start).Nanoseconds()

		// =====================================================
		// Verify Aggregated
		// =====================================================
		start = time.Now()
		if !schoco.Verify(pk, aggMsgs, aggPartSigs, aggSig) {
			t.Fatal("aggregate verify failed")
		}
		verifyAggregateNS := time.Since(start).Nanoseconds()

		// --- Store result ---
		results = append(results, BenchmarkResult{
			Hops:               hops,
			SignIndividualNS:   signIndividualNS,
			SignAggregateNS:    signAggregateNS,
			VerifyIndividualNS: verifyIndividualNS,
			VerifyAggregateNS:  verifyAggregateNS,
		})
	}

	// =====================================================
	// Output JSON
	// =====================================================
	jsonOut, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(jsonOut))
}
