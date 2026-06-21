package pact

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"anonymous-artifact/schoco"
	sd "flow-poc/sd"
)

func mustECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustPKIX(t *testing.T, pub any) []byte {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func replacePayloadPart(t *testing.T, jws string, p *Payload) string {
	t.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatal("bad jws")
	}
	b, err := marshalCanonical(p)
	if err != nil {
		t.Fatal(err)
	}
	parts[1] = b64Encode(b)
	return strings.Join(parts, ".")
}

func Test_TargetSD_CanonicalEncodingDeterministic(t *testing.T) {
	v := map[string]interface{}{"b": float64(2), "a": "x"}
	a, err := sd.CanonicalFieldEncoding(v)
	if err != nil {
		t.Fatal(err)
	}
	b, err := sd.CanonicalFieldEncoding(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("canonical encoding changed: %q != %q", a, b)
	}
}

func Test_TargetSD_SaltAndTamperingAffectCommitment(t *testing.T) {
	opening, err := sd.NewFieldOpening("tid", 0, 0, "repo.read", []byte("salt-1"), true)
	if err != nil {
		t.Fatal(err)
	}
	base, err := sd.CommitmentForOpening(opening)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(sd.FieldOpening) sd.FieldOpening{
		"salt": func(o sd.FieldOpening) sd.FieldOpening { o.Salt = []byte("salt-2"); return o },
		"tid0": func(o sd.FieldOpening) sd.FieldOpening { o.TID0 = "tid-other"; return o },
		"value": func(o sd.FieldOpening) sd.FieldOpening {
			o.Value = json.RawMessage(`false`)
			return o
		},
		"tag":         func(o sd.FieldOpening) sd.FieldOpening { o.Tag = "repo.write"; return o },
		"field_index": func(o sd.FieldOpening) sd.FieldOpening { o.FieldIndex = 1; return o },
		"node_index":  func(o sd.FieldOpening) sd.FieldOpening { o.NodeIndex = 1; return o },
	} {
		next, err := sd.CommitmentForOpening(mutate(opening))
		if err != nil {
			t.Fatal(err)
		}
		if string(base) == string(next) {
			t.Fatalf("%s tamper did not change commitment", name)
		}
	}
}

func Test_TargetSD_RandomSaltAndDeterministicTestHelper(t *testing.T) {
	a, err := sd.NewRandomFieldOpening("tid", 0, 0, "repo.read", true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := sd.NewRandomFieldOpening("tid", 0, 0, "repo.read", true)
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Salt) == string(b.Salt) {
		t.Fatal("normal constructor reused salt")
	}
	c, err := sd.NewDeterministicFieldOpeningForTest("tid", 0, 0, "repo.read", true)
	if err != nil {
		t.Fatal(err)
	}
	d, err := sd.NewDeterministicFieldOpeningForTest("tid", 0, 0, "repo.read", true)
	if err != nil {
		t.Fatal(err)
	}
	if string(c.Salt) != string(d.Salt) {
		t.Fatal("deterministic test helper did not produce stable salt")
	}
}

func Test_TargetSD_CommitmentEncodingVectorAndAmbiguity(t *testing.T) {
	opening := mustOpening(t, "tid", 2, 3, "repo.read", "salt", map[string]interface{}{"a": "b"})
	input, err := sd.CommitmentInput(opening)
	if err != nil {
		t.Fatal(err)
	}
	gotInput := hex.EncodeToString(input)
	wantInput := "000000000000000a504143542d53442d76310000000000000003746964000000000000000800000000000000020000000000000008000000000000000300000000000000097265706f2e72656164000000000000000473616c7400000000000000097b2261223a2262227d"
	if gotInput != wantInput {
		t.Fatalf("commitment input changed\n got %s\nwant %s", gotInput, wantInput)
	}
	commitment, err := sd.CommitmentForOpening(opening)
	if err != nil {
		t.Fatal(err)
	}
	gotCommitment := hex.EncodeToString(commitment)
	wantCommitment := "9cbdb2b2c36205ba4b6b08f95edf211498868a8ce9263642ab85d462c976081e"
	if gotCommitment != wantCommitment {
		t.Fatalf("commitment vector changed\n got %s\nwant %s", gotCommitment, wantCommitment)
	}
	naiveA := mustOpening(t, "ab", 0, 0, "c", "d", "e")
	naiveB := mustOpening(t, "a", 0, 0, "bc", "d", "e")
	inA, err := sd.CommitmentInput(naiveA)
	if err != nil {
		t.Fatal(err)
	}
	inB, err := sd.CommitmentInput(naiveB)
	if err != nil {
		t.Fatal(err)
	}
	if string(inA) == string(inB) {
		t.Fatal("length-prefixed encodings collided")
	}
	cA, _ := sd.CommitmentForOpening(naiveA)
	cB, _ := sd.CommitmentForOpening(naiveB)
	if string(cA) == string(cB) {
		t.Fatal("ambiguous tuple commitments collided")
	}
}

func Test_TargetSD_SameOpeningRecomputesSameRootAndTamperFails(t *testing.T) {
	openings := []sd.FieldOpening{
		mustOpening(t, "tid", 0, 0, "repo.read", "s1", true),
		mustOpening(t, "tid", 0, 1, "repo.write", "s2", true),
	}
	disc, err := sd.CreateDisclosureFromOpenings(openings, []int{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	ok, err := sd.VerifyDisclosure(disc)
	if err != nil || !ok {
		t.Fatalf("verify disclosure: %v", err)
	}
	commitments, err := sd.OpeningsToCommitments(openings)
	if err != nil {
		t.Fatal(err)
	}
	root, err := sd.MerkleRoot(commitments)
	if err != nil {
		t.Fatal(err)
	}
	if string(root) != string(disc.Root) {
		t.Fatal("same opening did not recompute same root")
	}
	for name, mutate := range map[string]func(*sd.Disclosure){
		"salt":        func(d *sd.Disclosure) { d.Openings[0].Salt = []byte("other") },
		"value":       func(d *sd.Disclosure) { d.Openings[0].Value = json.RawMessage(`false`) },
		"tag":         func(d *sd.Disclosure) { d.Openings[0].Tag = "repo.admin" },
		"node_index":  func(d *sd.Disclosure) { d.Openings[0].NodeIndex = 7 },
		"field_index": func(d *sd.Disclosure) { d.Openings[0].FieldIndex = 7 },
		"tid_0":       func(d *sd.Disclosure) { d.Openings[0].TID0 = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			cp := *disc
			cp.Openings = append([]sd.FieldOpening(nil), disc.Openings...)
			mutate(&cp)
			ok, err := sd.VerifyDisclosure(&cp)
			if err == nil || ok {
				t.Fatal("tampered disclosure unexpectedly verified")
			}
		})
	}
}

func mustOpening(t *testing.T, tid string, node, field int, tag, salt string, value interface{}) sd.FieldOpening {
	t.Helper()
	o, err := sd.NewFieldOpening(tid, node, field, tag, []byte(salt), value)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func Test_TargetFullEvidence_ValidMissingTamperedAndFailedRelation(t *testing.T) {
	key := mustECDSAKey(t)
	root := &Payload{Ver: VerECDSA, TID0: "tid-full", Iat: 1, Iss: &IDClaim{PK: mustPKIX(t, &key.PublicKey)}}
	data := map[string]interface{}{"repo.read": true, "repo.write": true}
	_, openings, err := AttachCommitmentRootToPayload(root, root.TID0, 0, data)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := CreateJWS(root, VerECDSA, key)
	if err != nil {
		t.Fatal(err)
	}
	evidence := &Evidence{NodeOpenings: map[int][]sd.FieldOpening{0: openings}}
	requireRead := testRelation{nodes: []int{0}, fn: func(_ *Payload, e *Evidence) error {
		for _, o := range e.NodeOpenings[0] {
			if o.Tag == "repo.read" && string(o.Value) == "true" {
				return nil
			}
		}
		return errRelationFailed
	}}
	trusted := mustPKIX(t, &key.PublicKey)
	if _, err := ValidatePACT(jws, VerECDSA, ValidationOptions{TrustedIssuerPK: trusted, Evidence: evidence, VerifierRelation: requireRead}); err != nil {
		t.Fatalf("valid evidence failed: %v", err)
	}
	if _, err := ValidatePACT(jws, VerECDSA, ValidationOptions{TrustedIssuerPK: trusted, Evidence: &Evidence{NodeOpenings: map[int][]sd.FieldOpening{0: openings[:1]}}}); err == nil {
		t.Fatal("missing opening unexpectedly accepted")
	}
	tampered := append([]sd.FieldOpening(nil), openings...)
	tampered[0].Value = json.RawMessage(`false`)
	if _, err := ValidatePACT(jws, VerECDSA, ValidationOptions{TrustedIssuerPK: trusted, Evidence: &Evidence{NodeOpenings: map[int][]sd.FieldOpening{0: tampered}}}); err == nil {
		t.Fatal("tampered opening unexpectedly accepted")
	}
	if _, err := ValidatePACT(jws, VerECDSA, ValidationOptions{
		TrustedIssuerPK: trusted,
		Evidence:        evidence,
		VerifierRelation: VerifierRelationFunc(func(*Payload, *Evidence) error {
			return errRelationFailed
		}),
	}); err == nil {
		t.Fatal("failed R_V unexpectedly accepted")
	}
	if _, err := ValidatePACT(jws, VerECDSA, ValidationOptions{
		TrustedIssuerPK: trusted,
		Evidence:        &Evidence{NodeOpenings: map[int][]sd.FieldOpening{}},
		VerifierRelation: testRelation{nodes: []int{0}, fn: func(*Payload, *Evidence) error {
			return nil
		}},
	}); err == nil {
		t.Fatal("missing evaluated node evidence unexpectedly accepted")
	}
	disc, err := sd.CreateDisclosureFromOpenings(openings, []int{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	commitments, err := sd.OpeningsToCommitments(openings)
	if err != nil {
		t.Fatal(err)
	}
	fullRoot, err := sd.MerkleRoot(commitments)
	if err != nil {
		t.Fatal(err)
	}
	if string(fullRoot) != string(disc.Root) {
		t.Fatal("full evidence and selective disclosure roots differ")
	}
}

func Test_TargetValidatePACT_DisclosureRequiresSaltedOpenings(t *testing.T) {
	key := mustECDSAKey(t)
	trusted := mustPKIX(t, &key.PublicKey)
	root := &Payload{Ver: VerECDSA, TID0: "tid-target-disclosure", Iat: 1, Iss: &IDClaim{PK: trusted}}
	data := map[string]interface{}{"repo.read": true, "repo": "example/api-service"}
	_, openings, err := AttachCommitmentRootToPayload(root, root.TID0, 0, data)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := CreateJWS(root, VerECDSA, key)
	if err != nil {
		t.Fatal(err)
	}
	target, err := sd.CreateDisclosureFromOpenings(openings, []int{0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidatePACT(jws, VerECDSA, ValidationOptions{TrustedIssuerPK: trusted, Presentations: map[int]*sd.Disclosure{0: target}}); err != nil {
		t.Fatalf("target salted disclosure rejected: %v", err)
	}

	legacyRoot := &Payload{Ver: VerECDSA, TID0: "tid-legacy-disclosure", Iat: 1, Iss: &IDClaim{PK: trusted}}
	_, leaves, err := AttachSDRootToPayload(legacyRoot, data)
	if err != nil {
		t.Fatal(err)
	}
	legacyJWS, err := CreateJWS(legacyRoot, VerECDSA, key)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := sd.CreateDisclosure(leaves, []int{0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidatePACT(legacyJWS, VerECDSA, ValidationOptions{TrustedIssuerPK: trusted, Presentations: map[int]*sd.Disclosure{0: legacy}}); err == nil {
		t.Fatal("ValidatePACT accepted legacy leaf-only disclosure")
	}
	if ok, err := ValidateJWSWithPresentations(legacyJWS, VerECDSA, map[int]*sd.Disclosure{0: legacy}); err != nil || !ok {
		t.Fatalf("legacy presentation API behavior changed: ok=%v err=%v", ok, err)
	}
}

var errRelationFailed = relationError("relation failed")

type relationError string

func (e relationError) Error() string { return string(e) }

type testRelation struct {
	nodes []int
	fn    func(*Payload, *Evidence) error
}

func (r testRelation) Evaluate(p *Payload, e *Evidence) error { return r.fn(p, e) }
func (r testRelation) EvaluatedNodes(*Payload) []int          { return r.nodes }

func Test_TargetIDMode_AuthorizedExtensionSigner(t *testing.T) {
	issuer := mustECDSAKey(t)
	authorized := mustECDSAKey(t)
	attacker := mustECDSAKey(t)
	now := time.Unix(1000, 0)
	issuerPK := mustPKIX(t, &issuer.PublicKey)
	root := &Payload{
		Ver:           VerECDSA,
		TID0:          "tid-id",
		Iat:           1,
		Iss:           &IDClaim{PK: issuerPK},
		NextSignerPK:  mustPKIX(t, &authorized.PublicKey),
		NextNotBefore: now.Add(-time.Minute).Unix(),
		NextNotAfter:  now.Add(time.Minute).Unix(),
	}
	jws, err := CreateJWS(root, VerECDSA, issuer)
	if err != nil {
		t.Fatal(err)
	}
	validNode := &LDNode{Payload: &Payload{Ver: VerECDSA, Iss: &IDClaim{PK: mustPKIX(t, &authorized.PublicKey)}}}
	validJWS, err := ExtendJWS(jws, validNode, VerECDSA, authorized)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidatePACT(validJWS, VerECDSA, ValidationOptions{TrustedIssuerPK: issuerPK, Now: now, IDKeyResolver: LocalIDKeyResolver{}}); err != nil {
		t.Fatalf("authorized signer rejected: %v", err)
	}
	if _, err := ValidatePACT(validJWS, VerECDSA, ValidationOptions{TrustedIssuerPK: issuerPK, Now: now}); err == nil {
		t.Fatal("extension-bearing ID token accepted without IDKeyResolver")
	}
	badNode := &LDNode{Payload: &Payload{Ver: VerECDSA, Iss: &IDClaim{PK: mustPKIX(t, &issuer.PublicKey)}}}
	badJWS, err := ExtendJWS(jws, badNode, VerECDSA, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidatePACT(badJWS, VerECDSA, ValidationOptions{TrustedIssuerPK: issuerPK, Now: now, IDKeyResolver: LocalIDKeyResolver{}}); err == nil {
		t.Fatal("unauthorized signer unexpectedly accepted")
	}
	attackerNode := &LDNode{Payload: &Payload{Ver: VerECDSA, Iss: &IDClaim{PK: mustPKIX(t, &attacker.PublicKey)}}}
	attackerJWS, err := ExtendJWS(jws, attackerNode, VerECDSA, attacker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidatePACT(attackerJWS, VerECDSA, ValidationOptions{TrustedIssuerPK: issuerPK, Now: now, IDKeyResolver: LocalIDKeyResolver{}}); err == nil {
		t.Fatal("attacker signer unexpectedly accepted")
	}
}

func Test_TargetIDMode_RootSignatureAndTamper(t *testing.T) {
	issuer := mustECDSAKey(t)
	issuerPK := mustPKIX(t, &issuer.PublicKey)
	root := &Payload{Ver: VerECDSA, TID0: "tid-root", Iat: 1, Iss: &IDClaim{PK: issuerPK}}
	jws, err := CreateJWS(root, VerECDSA, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidatePACT(jws, VerECDSA, ValidationOptions{TrustedIssuerPK: issuerPK}); err != nil {
		t.Fatalf("root-only token rejected: %v", err)
	}
	other := mustECDSAKey(t)
	if _, err := ValidatePACT(jws, VerECDSA, ValidationOptions{TrustedIssuerPK: mustPKIX(t, &other.PublicKey)}); err == nil {
		t.Fatal("root-only token accepted under wrong issuer key")
	}
	doc, err := payloadFromJWS(jws)
	if err != nil {
		t.Fatal(err)
	}
	doc.TID0 = "tampered"
	if _, err := ValidatePACT(replacePayloadPart(t, jws, doc), VerECDSA, ValidationOptions{TrustedIssuerPK: issuerPK}); err == nil {
		t.Fatal("tampered root payload accepted")
	}
}

func Test_TargetIDMode_BearerMaterialFailures(t *testing.T) {
	issuer := mustECDSAKey(t)
	authorized := mustECDSAKey(t)
	now := time.Unix(1000, 0)
	issuerPK := mustPKIX(t, &issuer.PublicKey)
	base := &Payload{Ver: VerECDSA, TID0: "tid-bearer", Iat: 1, Iss: &IDClaim{PK: issuerPK}}
	cases := []struct {
		name   string
		mutate func(*Payload)
	}{
		{"missing", func(*Payload) {}},
		{"malformed", func(p *Payload) { p.NextSignerPK = []byte("not-pkix") }},
		{"wrong", func(p *Payload) { p.NextSignerPK = mustPKIX(t, &issuer.PublicKey) }},
		{"expired", func(p *Payload) {
			p.NextSignerPK = mustPKIX(t, &authorized.PublicKey)
			p.NextNotAfter = now.Add(-time.Second).Unix()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := *base
			tc.mutate(&root)
			jws, err := CreateJWS(&root, VerECDSA, issuer)
			if err != nil {
				t.Fatal(err)
			}
			jws, err = ExtendJWS(jws, &LDNode{Payload: &Payload{Ver: VerECDSA, Iss: &IDClaim{PK: mustPKIX(t, &authorized.PublicKey)}}}, VerECDSA, authorized)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ValidatePACT(jws, VerECDSA, ValidationOptions{TrustedIssuerPK: issuerPK, Now: now, IDKeyResolver: LocalIDKeyResolver{}}); err == nil {
				t.Fatal("invalid bearer material accepted")
			}
		})
	}
}

func Test_TargetSchoCo_SlotMappingRejectsReorderedOrReindexedPrefixes(t *testing.T) {
	sk, pk, err := schoco.KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	root := &Payload{Ver: VerSchoCo, TID0: "tid-schoco", Iat: 1, Iss: &IDClaim{PK: pk.Bytes()}}
	jws, err := CreateJWS(root, VerSchoCo, sk)
	if err != nil {
		t.Fatal(err)
	}
	jws, err = ExtendJWS(jws, &LDNode{Payload: &Payload{Ver: VerSchoCo}}, VerSchoCo)
	if err != nil {
		t.Fatal(err)
	}
	jws, err = ExtendJWS(jws, &LDNode{Payload: &Payload{Ver: VerSchoCo}}, VerSchoCo)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := ValidateJWS(jws, VerSchoCo); err != nil || !ok {
		t.Fatalf("valid schoco chain failed: %v", err)
	}
	doc, err := payloadFromJWS(jws)
	if err != nil {
		t.Fatal(err)
	}
	doc.List[0], doc.List[1] = doc.List[1], doc.List[0]
	if ok, err := ValidateJWS(replacePayloadPart(t, jws, doc), VerSchoCo); err == nil && ok {
		t.Fatal("reordered prefixes unexpectedly accepted")
	}
	doc, err = payloadFromJWS(jws)
	if err != nil {
		t.Fatal(err)
	}
	doc.List[0].Payload.NodeIndex = 99
	if ok, err := ValidateJWS(replacePayloadPart(t, jws, doc), VerSchoCo); err == nil && ok {
		t.Fatal("reindexed prefix unexpectedly accepted")
	}
}

func Test_TargetSchoCo_MessageSequenceSlots(t *testing.T) {
	doc := &Payload{
		Ver:  VerSchoCo,
		TID0: "tid-schoco-seq",
		Iat:  1,
		List: []*LDNode{
			{ID: "a", Payload: &Payload{Ver: VerSchoCo, NodeIndex: 1}},
			{ID: "b", Payload: &Payload{Ver: VerSchoCo, NodeIndex: 2}},
		},
	}
	finalBytes, err := marshalCanonical(doc)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := SchoCoMessageSequenceForTest(doc, finalBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 3 {
		t.Fatalf("got %d messages, want 3", len(messages))
	}
	p0 := prefixPayload(doc, 0)
	p0Bytes, _ := marshalCanonical(p0)
	p1 := prefixPayload(doc, 1)
	p1Bytes, _ := marshalCanonical(p1)
	want := [][]byte{
		SchoCoSlotMessageForTest(2, finalBytes),
		SchoCoSlotMessageForTest(1, p1Bytes),
		SchoCoSlotMessageForTest(0, p0Bytes),
	}
	for i := range want {
		if string(messages[i]) != string(want[i]) {
			t.Fatalf("message %d slot mapping mismatch", i)
		}
	}
	if string(SchoCoSlotMessageForTest(0, p0Bytes)) == string(p0Bytes) {
		t.Fatal("slot/index bytes were not included")
	}
	if string(SchoCoSlotMessageForTest(0, p0Bytes)) == string(SchoCoSlotMessageForTest(1, p0Bytes)) {
		t.Fatal("different slots produced identical signed bytes")
	}
}

func Test_TargetSchoCo_RejectsRawMessagesWithoutSlotIndex(t *testing.T) {
	sk, pk, err := schoco.KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	root := &Payload{Ver: VerSchoCo, TID0: "tid-raw-schoco", Iat: 1, Iss: &IDClaim{PK: pk.Bytes()}}
	payloadBytes, err := marshalCanonical(root)
	if err != nil {
		t.Fatal(err)
	}
	headerBytes, err := json.Marshal(map[string]interface{}{"version": VerSchoCo})
	if err != nil {
		t.Fatal(err)
	}
	rawSig, err := schoco.StdSign(payloadBytes, sk)
	if err != nil {
		t.Fatal(err)
	}
	rawSigBytes, err := rawSig.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	rawJWS := strings.Join([]string{b64Encode(headerBytes), b64Encode(payloadBytes), b64Encode(rawSigBytes)}, ".")

	if schoco.StdVerify(payloadBytes, rawSig, pk) != true {
		t.Fatal("test setup error: raw SchoCo signature did not verify with low-level API")
	}
	if ok, err := ValidateJWS(rawJWS, VerSchoCo); err == nil && ok {
		t.Fatal("PACT validation accepted raw SchoCo message without slot/index")
	}
}

func Test_TargetRevocationCheckpoint(t *testing.T) {
	key := mustECDSAKey(t)
	attacker := mustECDSAKey(t)
	now := time.Unix(1000, 0)
	trusted := mustPKIX(t, &key.PublicKey)
	opts := ValidationOptions{TrustedIssuerPK: trusted, RequireRevocation: true, Tau: time.Minute, ClockSkew: time.Second, Now: now}
	valid, err := CreateRevocationCheckpoint(key, 1, now.Unix(), []string{"other"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRevocationCheckpoint("tid", valid, opts); err != nil {
		t.Fatalf("valid checkpoint rejected: %v", err)
	}
	revoked, err := CreateRevocationCheckpoint(key, 2, now.Unix(), []string{"tid"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRevocationCheckpoint("tid", revoked, opts); err == nil {
		t.Fatal("revoked tid unexpectedly accepted")
	}
	staleOpts := opts
	staleOpts.Tau = time.Second
	staleOpts.Now = now.Add(2 * time.Second)
	if err := ValidateRevocationCheckpoint("tid", valid, staleOpts); err == nil {
		t.Fatal("stale checkpoint unexpectedly accepted")
	}
	future, err := CreateRevocationCheckpoint(key, 3, now.Add(2*time.Second).Unix(), []string{"other"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRevocationCheckpoint("tid", future, opts); err == nil {
		t.Fatal("future checkpoint unexpectedly accepted")
	}
	forged := *valid
	forged.Epoch++
	if err := ValidateRevocationCheckpoint("tid", &forged, opts); err == nil {
		t.Fatal("forged checkpoint unexpectedly accepted")
	}
	attackerRC, err := CreateRevocationCheckpoint(attacker, 4, now.Unix(), []string{"other"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRevocationCheckpoint("tid", attackerRC, opts); err == nil {
		t.Fatal("attacker-signed checkpoint unexpectedly accepted")
	}
	if err := ValidateRevocationCheckpoint("tid", nil, opts); err == nil {
		t.Fatal("missing required checkpoint accepted")
	}
}

func Test_TargetRevocationCheckpointSignatureStableAcrossRevokedOrder(t *testing.T) {
	key := mustECDSAKey(t)
	rc, err := CreateRevocationCheckpoint(key, 1, 1, []string{"b", "a"})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := rc.signingBytes()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(msg)
	pubAny, err := x509.ParsePKIXPublicKey(rc.IssuerPK)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(pubAny.(*ecdsa.PublicKey), hash[:], rc.Signature) {
		t.Fatal("checkpoint signature did not verify")
	}
}
