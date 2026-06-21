package pact

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func cacheTestKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k, pk
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func checkpointClient(rcFn func() *RevocationCheckpoint) (*http.Client, *atomic.Int32) {
	var hits atomic.Int32
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		hits.Add(1)
		if rc := rcFn(); rc != nil {
			b, _ := json.Marshal(rc)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(string(b))),
				Header:     make(http.Header),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body:       io.NopCloser(strings.NewReader("unavailable")),
			Header:     make(http.Header),
		}, nil
	})}, &hits
}

func TestRevocationCacheFreshCachedCheckpointAccepts(t *testing.T) {
	key, trusted := cacheTestKey(t)
	now := time.Unix(1000, 0)
	rc, err := CreateRevocationCheckpoint(key, 1, now.Unix(), []string{"other"})
	if err != nil {
		t.Fatal(err)
	}
	client, hits := checkpointClient(func() *RevocationCheckpoint { return rc })

	cache := &RevocationCache{URL: "http://as.local/rc", Client: client}
	got, err := cache.Get(context.Background(), now, time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRevocationCheckpoint("tid", got, ValidationOptions{TrustedIssuerPK: trusted, RequireRevocation: true, Tau: time.Minute, Now: now}); err != nil {
		t.Fatal(err)
	}
	got, err = cache.Get(context.Background(), now.Add(10*time.Second), time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	if got != rc && got.Epoch != rc.Epoch {
		t.Fatal("unexpected checkpoint")
	}
	if hits.Load() != 1 {
		t.Fatalf("expected one fetch, got %d", hits.Load())
	}
}

func TestRevocationCacheStaleCachedCheckpointRefreshes(t *testing.T) {
	key, trusted := cacheTestKey(t)
	now := time.Unix(1000, 0)
	oldRC, err := CreateRevocationCheckpoint(key, 1, now.Add(-2*time.Minute).Unix(), nil)
	if err != nil {
		t.Fatal(err)
	}
	newRC, err := CreateRevocationCheckpoint(key, 2, now.Unix(), nil)
	if err != nil {
		t.Fatal(err)
	}
	client, hits := checkpointClient(func() *RevocationCheckpoint { return newRC })

	cache := &RevocationCache{URL: "http://as.local/rc", Client: client, cached: oldRC}
	got, err := cache.Get(context.Background(), now, time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Epoch != 2 {
		t.Fatalf("expected refreshed epoch 2, got %d", got.Epoch)
	}
	if err := ValidateRevocationCheckpoint("tid", got, ValidationOptions{TrustedIssuerPK: trusted, RequireRevocation: true, Tau: time.Minute, Now: now}); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("expected one refresh, got %d", hits.Load())
	}
}

func TestRevocationCacheStaleCheckpointUnavailableRejects(t *testing.T) {
	key, _ := cacheTestKey(t)
	now := time.Unix(1000, 0)
	oldRC, err := CreateRevocationCheckpoint(key, 1, now.Add(-2*time.Minute).Unix(), nil)
	if err != nil {
		t.Fatal(err)
	}
	client, _ := checkpointClient(func() *RevocationCheckpoint { return nil })
	cache := &RevocationCache{URL: "http://as.local/rc", Client: client, cached: oldRC}
	if _, err := cache.Get(context.Background(), now, time.Minute, true); err == nil {
		t.Fatal("stale checkpoint with unavailable AS accepted")
	}
}

func TestRevocationCacheRevokedAndWrongKeyReject(t *testing.T) {
	key, trusted := cacheTestKey(t)
	attacker, _ := cacheTestKey(t)
	now := time.Unix(1000, 0)
	revoked, err := CreateRevocationCheckpoint(key, 1, now.Unix(), []string{"tid"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRevocationCheckpoint("tid", revoked, ValidationOptions{TrustedIssuerPK: trusted, RequireRevocation: true, Tau: time.Minute, Now: now}); err == nil {
		t.Fatal("revoked tid accepted")
	}
	wrong, err := CreateRevocationCheckpoint(attacker, 1, now.Unix(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRevocationCheckpoint("tid", wrong, ValidationOptions{TrustedIssuerPK: trusted, RequireRevocation: true, Tau: time.Minute, Now: now}); err == nil {
		t.Fatal("attacker checkpoint accepted")
	}
}

func TestRevocationOptionalBehaviorIsExplicit(t *testing.T) {
	client, _ := checkpointClient(func() *RevocationCheckpoint { return nil })
	cache := &RevocationCache{URL: "http://as.local/rc", Client: client}
	if rc, err := cache.Get(context.Background(), time.Unix(1000, 0), time.Minute, false); err != nil || rc != nil {
		t.Fatalf("optional cache fetch got rc=%v err=%v", rc, err)
	}
	if err := ValidateRevocationCheckpoint("tid", nil, ValidationOptions{RequireRevocation: false}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRevocationCheckpoint("tid", nil, ValidationOptions{RequireRevocation: true}); err == nil {
		t.Fatal("missing required checkpoint accepted")
	}
}
