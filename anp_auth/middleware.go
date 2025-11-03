package anp_auth

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

const (
	// ContextKeyDID is the context key for storing the authenticated DID
	ContextKeyDID contextKey = "authenticated_did"
	// ContextKeyAccessToken is the context key for storing the access token
	ContextKeyAccessToken contextKey = "access_token"
)

// Middleware returns an HTTP middleware that authenticates requests using DID-WBA.
// Successful authentication injects the DID and access token into the request context.
// Failed authentication returns an appropriate HTTP error response.
func Middleware(verifier *DidWbaVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get(AuthorizationHeader)
			if authHeader == "" {
				http.Error(w, "missing authorization header", StatusUnauthorized)
				return
			}

			domain := r.Host
			if domain == "" {
				domain = r.URL.Host
			}

			result, err := verifier.VerifyAuthHeaderContext(r.Context(), authHeader, domain)
			if err != nil {
				handleAuthError(w, err)
				return
			}

			ctx := r.Context()
			if did, ok := result["did"].(string); ok {
				ctx = context.WithValue(ctx, ContextKeyDID, did)
			}
			if token, ok := result["access_token"].(string); ok {
				ctx = context.WithValue(ctx, ContextKeyAccessToken, token)
				w.Header().Set(AuthorizationHeader, BearerScheme+token)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func handleAuthError(w http.ResponseWriter, err error) {
	statusCode := GetStatusCode(err, StatusUnauthorized)
	http.Error(w, err.Error(), statusCode)
}

// DIDFromContext extracts the authenticated DID from the request context.
func DIDFromContext(ctx context.Context) (string, bool) {
	did, ok := ctx.Value(ContextKeyDID).(string)
	return did, ok
}

// AccessTokenFromContext extracts the access token from the request context.
func AccessTokenFromContext(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(ContextKeyAccessToken).(string)
	return token, ok
}

// RequireDID is a middleware that ensures the request has an authenticated DID.
// It should be used after the main Middleware.
func RequireDID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := DIDFromContext(r.Context()); !ok {
			http.Error(w, "authentication required", StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireSpecificDID returns a middleware that ensures the authenticated DID
// matches one of the provided DIDs.
func RequireSpecificDID(allowedDIDs ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(allowedDIDs))
	for _, did := range allowedDIDs {
		allowed[strings.TrimSpace(did)] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			did, ok := DIDFromContext(r.Context())
			if !ok {
				http.Error(w, "authentication required", StatusUnauthorized)
				return
			}

			if !allowed[did] {
				http.Error(w, "access denied", StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
