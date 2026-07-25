package broker

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

type nonceCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	maximum int
	entries map[string]time.Time
}

func newNonceCache(ttl time.Duration, maximum int) *nonceCache {
	return &nonceCache{
		ttl:     ttl,
		maximum: maximum,
		entries: make(map[string]time.Time),
	}
}

func (cache *nonceCache) use(hostUUID, nonce string, now time.Time) bool {
	digest := sha256.Sum256([]byte(hostUUID + "\x00" + nonce))
	key := hex.EncodeToString(digest[:])
	cache.mu.Lock()
	defer cache.mu.Unlock()
	for entry, expires := range cache.entries {
		if !expires.After(now) {
			delete(cache.entries, entry)
		}
	}
	if _, exists := cache.entries[key]; exists || len(cache.entries) >= cache.maximum {
		return false
	}
	cache.entries[key] = now.Add(cache.ttl)
	return true
}
