package pact

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type RevocationCache struct {
	URL    string
	Client *http.Client

	mu     sync.Mutex
	cached *RevocationCheckpoint
}

func (c *RevocationCache) Get(ctx context.Context, now time.Time, tau time.Duration, require bool) (*RevocationCheckpoint, error) {
	if c == nil {
		if require {
			return nil, fmt.Errorf("nil revocation cache")
		}
		return nil, nil
	}
	if now.IsZero() {
		now = time.Now()
	}

	c.mu.Lock()
	if checkpointFresh(c.cached, now, tau) {
		rc := c.cached
		c.mu.Unlock()
		return rc, nil
	}
	c.mu.Unlock()

	rc, err := c.fetch(ctx)
	if err != nil {
		if require {
			return nil, err
		}
		return nil, nil
	}
	if !checkpointFresh(rc, now, tau) {
		if require {
			return nil, fmt.Errorf("fetched revocation checkpoint is stale")
		}
		return nil, nil
	}

	c.mu.Lock()
	c.cached = rc
	c.mu.Unlock()
	return rc, nil
}

func (c *RevocationCache) fetch(ctx context.Context) (*RevocationCheckpoint, error) {
	if c.URL == "" {
		return nil, fmt.Errorf("missing revocation checkpoint URL")
	}
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch revocation checkpoint: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch revocation checkpoint: status %d", resp.StatusCode)
	}
	var rc RevocationCheckpoint
	if err := json.NewDecoder(resp.Body).Decode(&rc); err != nil {
		return nil, err
	}
	return &rc, nil
}

func checkpointFresh(rc *RevocationCheckpoint, now time.Time, tau time.Duration) bool {
	if rc == nil || rc.IssuedAt == 0 {
		return false
	}
	issuedAt := time.Unix(rc.IssuedAt, 0)
	if now.Before(issuedAt) {
		return false
	}
	if tau > 0 && now.Sub(issuedAt) > tau {
		return false
	}
	if rc.ExpiresAt > 0 && !now.Before(time.Unix(rc.ExpiresAt, 0)) {
		return false
	}
	return true
}
