package anp_auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type mockVerifier struct {
	result map[string]any
	err    error
}

func (m *mockVerifier) VerifyAuthHeaderContext(ctx context.Context, authorization, domain string) (map[string]any, error) {
	return m.result, m.err
}

func TestMiddleware_MissingAuthHeader(t *testing.T) {
	verifier := &DidWbaVerifier{
		config: DidWbaVerifierConfig{
			NonceValidator: NewMemoryNonceValidator(5 * time.Minute),
		},
	}

	handler := Middleware(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestDIDFromContext(t *testing.T) {
	ctx := context.Background()

	_, ok := DIDFromContext(ctx)
	if ok {
		t.Error("Expected no DID in empty context")
	}

	ctx = context.WithValue(ctx, ContextKeyDID, "did:wba:example.com")
	did, ok := DIDFromContext(ctx)
	if !ok {
		t.Error("Expected DID in context")
	}
	if did != "did:wba:example.com" {
		t.Errorf("Expected did:wba:example.com, got %s", did)
	}
}

func TestAccessTokenFromContext(t *testing.T) {
	ctx := context.Background()

	_, ok := AccessTokenFromContext(ctx)
	if ok {
		t.Error("Expected no token in empty context")
	}

	ctx = context.WithValue(ctx, ContextKeyAccessToken, "test-token")
	token, ok := AccessTokenFromContext(ctx)
	if !ok {
		t.Error("Expected token in context")
	}
	if token != "test-token" {
		t.Errorf("Expected test-token, got %s", token)
	}
}

func TestRequireDID(t *testing.T) {
	tests := []struct {
		name       string
		hasDID     bool
		wantStatus int
	}{
		{
			name:       "request with DID should pass",
			hasDID:     true,
			wantStatus: http.StatusOK,
		},
		{
			name:       "request without DID should fail",
			hasDID:     false,
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := RequireDID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.hasDID {
				ctx := context.WithValue(req.Context(), ContextKeyDID, "did:wba:example.com")
				req = req.WithContext(ctx)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, rec.Code)
			}
		})
	}
}

func TestRequireSpecificDID(t *testing.T) {
	allowedDIDs := []string{"did:wba:example.com", "did:wba:test.com"}
	handler := RequireSpecificDID(allowedDIDs...)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		did        string
		wantStatus int
	}{
		{
			name:       "allowed DID should pass",
			did:        "did:wba:example.com",
			wantStatus: http.StatusOK,
		},
		{
			name:       "different allowed DID should pass",
			did:        "did:wba:test.com",
			wantStatus: http.StatusOK,
		},
		{
			name:       "disallowed DID should fail",
			did:        "did:wba:other.com",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			ctx := context.WithValue(req.Context(), ContextKeyDID, tt.did)
			req = req.WithContext(ctx)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, rec.Code)
			}
		})
	}
}
