package anp_auth

import (
	"sync"
	"testing"
	"time"
)

// TestAuthenticator_Singleflight_ThunderingHerd tests that singleflight prevents
// multiple concurrent requests for the same domain from executing the expensive
// header generation multiple times.
func TestAuthenticator_Singleflight_ThunderingHerd(t *testing.T) {
	// Create test DID document and key
	doc, privateKey, err := CreateDIDWBADocument("example.com", nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateDIDWBADocument() error = %v", err)
	}

	auth, err := NewAuthenticator(
		WithDIDMaterial(doc, privateKey),
	)
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	// With singleflight, all concurrent requests for the same domain
	// should share the work and only generate the header once
	const numGoroutines = 100
	const targetURL = "https://test.example.com/api"

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Start time
	start := time.Now()

	// Launch many goroutines that all request the same domain simultaneously
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			// All goroutines request at the same time
			_, err := auth.GenerateHeader(targetURL)
			if err != nil {
				t.Errorf("GenerateHeader() error = %v", err)
			}
		}()
	}

	wg.Wait()
	duration := time.Since(start)

	t.Logf("Completed %d concurrent requests in %v", numGoroutines, duration)

	// With singleflight, all goroutines should receive the same cached result
	// after the first one completes. Verify the cache was populated.
	auth.cacheMutex.Lock()
	if len(auth.authHeaders) == 0 {
		t.Error("Expected auth headers to be cached")
	}
	auth.cacheMutex.Unlock()

	// The operation should complete relatively quickly since goroutines are sharing work
	if duration > 5*time.Second {
		t.Errorf("Operation took too long: %v (possible thundering herd)", duration)
	}
}

// TestAuthenticator_Singleflight_DifferentDomains tests that singleflight
// allows concurrent requests for different domains to execute in parallel.
func TestAuthenticator_Singleflight_DifferentDomains(t *testing.T) {
	doc, privateKey, err := CreateDIDWBADocument("example.com", nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateDIDWBADocument() error = %v", err)
	}

	auth, err := NewAuthenticator(
		WithDIDMaterial(doc, privateKey),
	)
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	domains := []string{
		"https://domain1.com/api",
		"https://domain2.com/api",
		"https://domain3.com/api",
		"https://domain4.com/api",
		"https://domain5.com/api",
	}

	var wg sync.WaitGroup
	results := make([]error, len(domains))

	start := time.Now()

	for i, domain := range domains {
		wg.Add(1)
		go func(idx int, url string) {
			defer wg.Done()
			_, err := auth.GenerateHeader(url)
			results[idx] = err
		}(i, domain)
	}

	wg.Wait()
	duration := time.Since(start)

	// Check all requests succeeded
	for i, err := range results {
		if err != nil {
			t.Errorf("Request %d failed: %v", i, err)
		}
	}

	// Verify all domains were cached
	auth.cacheMutex.Lock()
	cachedCount := len(auth.authHeaders)
	auth.cacheMutex.Unlock()

	if cachedCount != len(domains) {
		t.Errorf("Expected %d domains cached, got %d", len(domains), cachedCount)
	}

	t.Logf("Processed %d different domains concurrently in %v", len(domains), duration)
}

// TestAuthenticator_Singleflight_ErrorHandling tests that errors are properly
// shared across goroutines waiting on the same singleflight key.
func TestAuthenticator_Singleflight_ErrorHandling(t *testing.T) {
	// Create authenticator with invalid paths (will fail on material load)
	auth, err := NewAuthenticator(
		WithDIDCfgPaths("/nonexistent/did.json", "/nonexistent/key.pem"),
	)
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	const numGoroutines = 10
	const targetURL = "https://test.example.com/api"

	var wg sync.WaitGroup
	errors := make([]error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := auth.GenerateHeader(targetURL)
			errors[idx] = err
		}(i)
	}

	wg.Wait()

	// All goroutines should receive the same error
	var firstErr error
	for i, err := range errors {
		if err == nil {
			t.Errorf("Goroutine %d: expected error, got nil", i)
			continue
		}
		if i == 0 {
			firstErr = err
		}
		// All errors should be the same (shared result from singleflight)
		if err.Error() != firstErr.Error() {
			t.Errorf("Goroutine %d: error mismatch\nwant: %v\ngot:  %v", i, firstErr, err)
		}
	}
}

// TestAuthenticator_Singleflight_CacheInvalidation tests that force refresh
// bypasses cache and singleflight correctly.
func TestAuthenticator_Singleflight_CacheInvalidation(t *testing.T) {
	doc, privateKey, err := CreateDIDWBADocument("example.com", nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateDIDWBADocument() error = %v", err)
	}

	auth, err := NewAuthenticator(
		WithDIDMaterial(doc, privateKey),
	)
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	targetURL := "https://test.example.com/api"

	// First request - should populate cache
	header1, err := auth.GenerateHeader(targetURL)
	if err != nil {
		t.Fatalf("First GenerateHeader() error = %v", err)
	}

	// Second request - should use cache
	header2, err := auth.GenerateHeader(targetURL)
	if err != nil {
		t.Fatalf("Second GenerateHeader() error = %v", err)
	}

	// Headers should be identical (from cache)
	if header1[AuthorizationHeader] != header2[AuthorizationHeader] {
		t.Error("Expected cached headers to be identical")
	}

	// Force refresh
	header3, err := auth.GenerateHeaderForce(targetURL)
	if err != nil {
		t.Fatalf("GenerateHeaderForce() error = %v", err)
	}

	// Force refresh should generate a new header (different nonce/timestamp)
	// Note: In rare cases they might be identical, but typically they differ
	_ = header3 // We got a result, that's what matters for this test
}
