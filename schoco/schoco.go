package schoco

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

/* ============================================================
   Types
============================================================ */

type Signature struct {
	R *edwards25519.Point
	S *edwards25519.Scalar
}

const (
	challengeDomain = "SCHOCO-CHALLENGE-V1"
	pactSlotDomain  = "PACT-SCHOCO-SLOT-V1"
)

/* ============================================================
   Hash utilities
============================================================ */

func hashToScalar(parts ...[]byte) *edwards25519.Scalar {
	h := sha512.New()
	writeBytes(h, []byte(challengeDomain))
	for _, p := range parts {
		writeBytes(h, p)
	}
	digest := h.Sum(nil) // 64 bytes SHA-512
	s, err := new(edwards25519.Scalar).SetUniformBytes(digest)
	if err != nil {
		panic("edwards25519 SetUniformBytes rejected SHA-512 output")
	}
	return s
}

type byteWriter interface {
	Write([]byte) (int, error)
}

func writeBytes(w byteWriter, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	_, _ = w.Write(n[:])
	_, _ = w.Write(b)
}

func appendBytes(out []byte, b []byte) []byte {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	out = append(out, n[:]...)
	return append(out, b...)
}

/* ============================================================
   Key generation
============================================================ */

func KeyPair() (*edwards25519.Scalar, *edwards25519.Point, error) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, nil, err
	}

	sk := new(edwards25519.Scalar)
	sk.SetBytesWithClamping(seed[:])
	pk := new(edwards25519.Point).ScalarBaseMult(sk)
	return sk, pk, nil
}

/* ============================================================
   Standard Schnorr signature
============================================================ */

func StdSign(msg []byte, sk *edwards25519.Scalar) (*Signature, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	k := new(edwards25519.Scalar)
	k.SetBytesWithClamping(nonce[:])

	R := new(edwards25519.Point).ScalarBaseMult(k)
	pk := new(edwards25519.Point).ScalarBaseMult(sk)

	Rb := R.Bytes()
	PKb := pk.Bytes()

	h := hashToScalar(Rb[:], msg, PKb[:])

	S := new(edwards25519.Scalar)
	S.Multiply(h, sk)
	S.Negate(S)
	S.Add(S, k)

	return &Signature{R, S}, nil
}

/* ============================================================
   Standard Schnorr signature verification
============================================================ */

func StdVerify(msg []byte, sig *Signature, pk *edwards25519.Point) bool {
	if sig == nil || sig.R == nil || sig.S == nil || pk == nil {
		return false
	}

	// h = H(R || msg || pk)
	h := hashToScalar(sig.R.Bytes(), msg, pk.Bytes())

	// left = S*B
	left := new(edwards25519.Point).ScalarBaseMult(sig.S)

	// right = R - h*pk => R - h*pk = R + (-h*pk)
	hpk := new(edwards25519.Point).ScalarMult(h, pk)
	right := new(edwards25519.Point).Subtract(sig.R, hpk)

	return left.Equal(right) == 1
}

/* ============================================================
   PACT/SchoCo integration helpers
============================================================ */

// PACTSlotMessage returns the canonical bytes signed by SchoCo for a PACT
// prefix. PACT prefix P_i is signed in SchoCo slot i+1, so slot is one-based.
//
// Encoding is injective: variable-length fields are length-prefixed and the
// integer slot is fixed-width big-endian.
func PACTSlotMessage(slot uint64, prefix []byte) []byte {
	out := make([]byte, 0, 8+len(pactSlotDomain)+8+8+len(prefix))
	out = appendBytes(out, []byte(pactSlotDomain))
	var slotBytes [8]byte
	binary.BigEndian.PutUint64(slotBytes[:], slot)
	out = append(out, slotBytes[:]...)
	out = appendBytes(out, prefix)
	return out
}

// StdSignPACT signs a one-based PACT/SchoCo slot message. Prefer this over
// StdSign for PACT integrations so the slot cannot be omitted accidentally.
func StdSignPACT(slot uint64, prefix []byte, sk *edwards25519.Scalar) (*Signature, error) {
	if slot == 0 {
		return nil, fmt.Errorf("PACT SchoCo slot must be one-based")
	}
	return StdSign(PACTSlotMessage(slot, prefix), sk)
}

/* ============================================================
   SchoCo aggregation
============================================================ */

func Aggregate(
	msg []byte,
	prev *Signature,
) (*edwards25519.Point, *Signature, error) {
	if prev == nil || prev.R == nil || prev.S == nil {
		return nil, nil, errors.New("nil previous signature")
	}

	var nonce [64]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nil, err
	}

	k, err := new(edwards25519.Scalar).SetUniformBytes(nonce[:])
	if err != nil {
		return nil, nil, err
	}

	R := new(edwards25519.Point).ScalarBaseMult(k)

	aggKey := prev.S
	partSig := prev.R

	pk := new(edwards25519.Point).ScalarBaseMult(aggKey)

	Rb := R.Bytes()
	PKb := pk.Bytes()

	h := hashToScalar(Rb[:], msg, PKb[:])

	S := new(edwards25519.Scalar)
	S.Multiply(h, aggKey)
	S.Negate(S)
	S.Add(S, k)

	return partSig, &Signature{R, S}, nil
}

// AggregatePACT signs a one-based PACT/SchoCo slot message using the
// aggregation key carried by prev. It returns the partial signature that
// authenticates the predecessor prefix and the new aggregate signature.
func AggregatePACT(slot uint64, prefix []byte, prev *Signature) (*edwards25519.Point, *Signature, error) {
	if slot == 0 {
		return nil, nil, fmt.Errorf("PACT SchoCo slot must be one-based")
	}
	return Aggregate(PACTSlotMessage(slot, prefix), prev)
}

/* ============================================================
   Verification
============================================================ */

// Verify is the low-level SchoCo verifier. messages must be passed in reverse
// aggregate verification order: latest message first, then its predecessor,
// ending with the root message. PACT callers should use VerifyPACT.
func Verify(
	rootPK *edwards25519.Point,
	messages [][]byte,
	partSigs []*edwards25519.Point,
	lastSig *Signature,
) bool {

	if rootPK == nil || lastSig == nil || lastSig.R == nil || lastSig.S == nil {
		return false
	}
	if len(messages) == 0 {
		return false
	}
	if len(partSigs) != len(messages)-1 {
		return false
	}
	for _, part := range partSigs {
		if part == nil {
			return false
		}
	}

	y := new(edwards25519.Point).Set(rootPK)

	for i := len(partSigs) - 1; i >= 0; i-- {
		Rb := partSigs[i].Bytes()
		Yb := y.Bytes()

		h := hashToScalar(Rb[:], messages[i+1], Yb[:])

		hy := new(edwards25519.Point).ScalarMult(h, y)
		y.Subtract(partSigs[i], hy)
	}

	Rb := lastSig.R.Bytes()
	Yb := y.Bytes()

	h := hashToScalar(Rb[:], messages[0], Yb[:])

	left := new(edwards25519.Point).ScalarBaseMult(lastSig.S)
	right := new(edwards25519.Point).ScalarMult(h, y)
	right.Subtract(lastSig.R, right)

	return left.Equal(right) == 1
}

// VerifyPACT verifies SchoCo signatures for PACT prefixes in natural PACT
// order: prefixes[0] = P_0, prefixes[1] = P_1, ..., prefixes[k] = P_k.
// partSigs is also natural link order: partSigs[0] = R_0, ..., partSigs[k-1]
// = R_{k-1}. The function maps P_i to SchoCo slot i+1 internally and adapts
// to SchoCo's reverse aggregate verification order.
func VerifyPACT(
	rootPK *edwards25519.Point,
	prefixes [][]byte,
	partSigs []*edwards25519.Point,
	lastSig *Signature,
) bool {
	if len(prefixes) == 0 {
		return false
	}
	if len(partSigs) != len(prefixes)-1 {
		return false
	}

	messages := make([][]byte, 0, len(prefixes))
	for i := len(prefixes) - 1; i >= 0; i-- {
		messages = append(messages, PACTSlotMessage(uint64(i+1), prefixes[i]))
	}

	reversedPartSigs := make([]*edwards25519.Point, 0, len(partSigs))
	for i := len(partSigs) - 1; i >= 0; i-- {
		reversedPartSigs = append(reversedPartSigs, partSigs[i])
	}

	return Verify(rootPK, messages, reversedPartSigs, lastSig)
}

/* ============================================================
   Serialization
============================================================ */

func (s *Signature) MarshalBinary() ([]byte, error) {
	if s == nil || s.R == nil || s.S == nil {
		return nil, errors.New("nil signature")
	}

	out := make([]byte, 64)
	copy(out[:32], s.R.Bytes()[:])
	copy(out[32:], s.S.Bytes()[:])
	return out, nil
}

func UnmarshalSignature(data []byte) (*Signature, error) {
	if len(data) != 64 {
		return nil, errors.New("invalid signature length")
	}

	R, err := new(edwards25519.Point).SetBytes(data[:32])
	if err != nil {
		return nil, err
	}

	S := new(edwards25519.Scalar)
	if _, err := S.SetCanonicalBytes(data[32:]); err != nil {
		return nil, err
	}

	return &Signature{R, S}, nil
}
