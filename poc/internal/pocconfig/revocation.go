package pocconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
)

const (
	RevocationIssuerID     = "spiffe://example.org/AS"
	RevocationCheckpointAS = "http://poc-as:8080/revocationCheckpoint"
)

func RevocationIssuerKey() *ecdsa.PrivateKey {
	curve := elliptic.P256()
	digest := sha256.Sum256([]byte("pact-poc-revocation-issuer-key"))
	n := new(big.Int).Sub(curve.Params().N, big.NewInt(1))
	d := new(big.Int).SetBytes(digest[:])
	d.Mod(d, n)
	d.Add(d, big.NewInt(1))
	x, y := curve.ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}
}

func RevocationIssuerPublicKey() []byte {
	b, err := x509.MarshalPKIXPublicKey(&RevocationIssuerKey().PublicKey)
	if err != nil {
		panic(err)
	}
	return b
}
