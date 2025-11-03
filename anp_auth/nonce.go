package anp_auth

import (
	"context"
	"sync"
	"time"
)

// NonceValidator validates nonces to prevent replay attacks.
type NonceValidator interface {
	// Validate checks if a nonce is valid for the given DID.
	// Returns false if the nonce has already been used or is invalid.
	Validate(ctx context.Context, did, nonce string) (bool, error)
}

// MemoryNonceValidator provides an in-memory nonce validation implementation.
// WARNING: This implementation is NOT safe for production use in distributed
// systems as it only stores nonces locally. Use a distributed cache (Redis, etc.)
// for production deployments.
type MemoryNonceValidator struct {
	used       map[string]time.Time
	mu         sync.Mutex
	expiration time.Duration
}

// NewMemoryNonceValidator creates a new in-memory nonce validator.
func NewMemoryNonceValidator(expiration time.Duration) *MemoryNonceValidator {
	return &MemoryNonceValidator{
		used:       make(map[string]time.Time),
		expiration: expiration,
	}
}

// Validate checks if the nonce has been used before.
func (v *MemoryNonceValidator) Validate(ctx context.Context, did, nonce string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	key := did + ":" + nonce
	now := time.Now().UTC()

	// Clean expired nonces
	for k, t := range v.used {
		if now.Sub(t) > v.expiration {
			delete(v.used, k)
		}
	}

	// Check if nonce was already used
	if _, exists := v.used[key]; exists {
		return false, nil
	}

	v.used[key] = now
	return true, nil
}
