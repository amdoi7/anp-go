package anp_auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DidWbaVerifierError represents a domain error with an HTTP-like status code.
type DidWbaVerifierError struct {
	Message    string
	StatusCode int
}

func (e *DidWbaVerifierError) Error() string {
	return e.Message
}

// DidWbaVerifierConfig holds the configuration for the DidWbaVerifier.
type DidWbaVerifierConfig struct {
	JWTPrivateKey              any
	JWTPublicKey               any
	JWTPrivateKeyPEM           []byte
	JWTPublicKeyPEM            []byte
	JWTAlgorithm               string
	AccessTokenExpireMinutes   time.Duration
	NonceExpirationMinutes     time.Duration
	TimestampExpirationMinutes time.Duration
	DIDCacheExpireMinutes      time.Duration
	AllowedDomains             []string
	ExternalNonceValidator     NonceValidatorFunc
	ResolveDIDDocumentFunc     ResolveDIDDocumentFunc
	NowFunc                    func() time.Time
	HTTPClient                 *http.Client
}

// ResolveDIDDocumentFunc resolves a DID document for a given DID identifier.
type ResolveDIDDocumentFunc func(ctx context.Context, did string) (*DIDWBADocument, error)

// NonceValidatorFunc allows plugging in custom nonce validation logic.
// Returning (false, nil) indicates the nonce is invalid. Any non-nil error
// will be surfaced to the caller.
type NonceValidatorFunc func(ctx context.Context, did, nonce string) (bool, error)

// didCacheEntry stores a cached DID document with its expiration time.
type didCacheEntry struct {
	doc       *DIDWBADocument
	expiresAt time.Time
}

// DidWbaVerifier verifies Authorization headers for DID WBA and Bearer JWT.
type DidWbaVerifier struct {
	config            DidWbaVerifierConfig
	validServerNonces map[string]time.Time
	nonceMutex        sync.Mutex
	didCache          map[string]didCacheEntry
	didCacheMutex     sync.Mutex
	now               func() time.Time
}

// NewDidWbaVerifier creates a new verifier with the given configuration.
// It applies sensible defaults if some config fields are omitted.
func NewDidWbaVerifier(config DidWbaVerifierConfig) (*DidWbaVerifier, error) {
	if config.JWTAlgorithm == "" {
		config.JWTAlgorithm = "RS256"
	}
	if config.AccessTokenExpireMinutes == 0 {
		config.AccessTokenExpireMinutes = 60
	}
	if config.NonceExpirationMinutes == 0 {
		config.NonceExpirationMinutes = 6
	}
	if config.TimestampExpirationMinutes == 0 {
		config.TimestampExpirationMinutes = 5
	}
	if config.DIDCacheExpireMinutes == 0 {
		config.DIDCacheExpireMinutes = 15
	}

	if config.JWTPrivateKey == nil && len(config.JWTPrivateKeyPEM) > 0 {
		key, err := LoadJWTPrivateKeyFromPEM(config.JWTPrivateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to load JWT private key: %w", err)
		}
		config.JWTPrivateKey = key
	}

	if config.JWTPublicKey == nil && len(config.JWTPublicKeyPEM) > 0 {
		key, err := LoadJWTPublicKeyFromPEM(config.JWTPublicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to load JWT public key: %w", err)
		}
		config.JWTPublicKey = key
	}

	nowFunc := config.NowFunc
	if nowFunc == nil {
		nowFunc = time.Now
	}

	return &DidWbaVerifier{
		config:            config,
		validServerNonces: make(map[string]time.Time),
		didCache:          make(map[string]didCacheEntry),
		now:               nowFunc,
	}, nil
}

func (v *DidWbaVerifier) ensureDomainAllowed(domain string) error {
	if len(v.config.AllowedDomains) == 0 {
		return nil
	}

	for _, allowed := range v.config.AllowedDomains {
		if strings.EqualFold(strings.TrimSpace(allowed), domain) {
			return nil
		}
	}

	return &DidWbaVerifierError{fmt.Sprintf("Domain not allowed: %s", domain), 403}
}

// VerifyAuthHeader verifies an HTTP Authorization header.
// It handles both "Bearer" JWT tokens and "DIDWba" headers.
func (v *DidWbaVerifier) VerifyAuthHeader(authorization, domain string) (map[string]any, error) {
	return v.VerifyAuthHeaderContext(context.Background(), authorization, domain)
}

// VerifyAuthHeaderContext is the context-aware variant of VerifyAuthHeader.
func (v *DidWbaVerifier) VerifyAuthHeaderContext(ctx context.Context, authorization, domain string) (map[string]any, error) {
	if authorization == "" {
		return nil, &DidWbaVerifierError{"Missing authorization header", 401}
	}

	if strings.HasPrefix(authorization, "Bearer ") {
		return v.handleBearerAuth(authorization)
	}

	return v.handleDidAuth(ctx, authorization, domain)
}

func (v *DidWbaVerifier) handleBearerAuth(authorization string) (map[string]any, error) {
	tokenString := strings.TrimPrefix(authorization, "Bearer ")
	if v.config.JWTPublicKey == nil {
		return nil, &DidWbaVerifierError{"JWT public key not configured", 500}
	}

	did, err := VerifyAccessToken(tokenString, v.config.JWTPublicKey, v.config.JWTAlgorithm)
	if err != nil {
		return nil, &DidWbaVerifierError{fmt.Sprintf("Invalid token: %v", err), 401}
	}

	return map[string]any{"did": did}, nil
}

func (v *DidWbaVerifier) handleDidAuth(ctx context.Context, authorization, domain string) (map[string]any, error) {
	if err := v.ensureDomainAllowed(domain); err != nil {
		return nil, err
	}

	headerParts, err := parseAuthHeader(authorization)
	if err != nil {
		return nil, &DidWbaVerifierError{fmt.Sprintf("Invalid authorization header: %v", err), 401}
	}

	if err := v.verifyTimestamp(headerParts.Timestamp); err != nil {
		return nil, err
	}

	if err := v.verifyNonce(ctx, headerParts.DID, headerParts.Nonce); err != nil {
		return nil, err
	}

	didDocument, err := v.resolveAndCacheDID(ctx, headerParts.DID)
	if err != nil {
		return nil, err // Error is already wrapped by the resolver
	}

	isValid, message := v.verifySignature(authorization, didDocument, domain)
	if !isValid {
		return nil, &DidWbaVerifierError{fmt.Sprintf("Invalid signature: %s", message), 403}
	}

	if v.config.JWTPrivateKey == nil {
		return nil, &DidWbaVerifierError{"JWT private key not configured for token issuance", 500}
	}

	accessToken, err := CreateAccessToken(headerParts.DID, v.config.JWTPrivateKey, v.config.JWTAlgorithm, v.config.AccessTokenExpireMinutes*time.Minute)
	if err != nil {
		return nil, &DidWbaVerifierError{fmt.Sprintf("Failed to create access token: %v", err), 500}
	}

	return map[string]any{
		"access_token": accessToken,
		"token_type":   "bearer",
		"did":          headerParts.DID,
	}, nil
}

// resolveAndCacheDID retrieves a DID document, using a cache to avoid repeated lookups.
func (v *DidWbaVerifier) resolveAndCacheDID(ctx context.Context, did string) (*DIDWBADocument, error) {
	v.didCacheMutex.Lock()
	if entry, exists := v.didCache[did]; exists && v.now().UTC().Before(entry.expiresAt) {
		v.didCacheMutex.Unlock()
		return entry.doc, nil
	}
	v.didCacheMutex.Unlock()

	// Resolve outside the lock to prevent blocking during network I/O.
	resolver := v.config.ResolveDIDDocumentFunc
	var doc *DIDWBADocument
	var err error
	if resolver != nil {
		doc, err = resolver(ctx, did)
	} else {
		doc, err = ResolveDIDWBADocument(did, v.config.HTTPClient)
	}
	if err != nil {
		return nil, &DidWbaVerifierError{fmt.Sprintf("Failed to resolve DID document: %v", err), 401}
	}

	// Lock again to update the cache.
	v.didCacheMutex.Lock()
	defer v.didCacheMutex.Unlock()

	// Re-check in case another goroutine resolved it while we were working.
	if entry, exists := v.didCache[did]; exists && v.now().UTC().Before(entry.expiresAt) {
		return entry.doc, nil
	}

	v.didCache[did] = didCacheEntry{
		doc:       doc,
		expiresAt: v.now().UTC().Add(v.config.DIDCacheExpireMinutes * time.Minute),
	}

	return doc, nil
}

func (v *DidWbaVerifier) verifyTimestamp(timestampStr string) error {
	requestTime, err := time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		return &DidWbaVerifierError{fmt.Sprintf("Invalid timestamp format: %v", err), 400}
	}

	currentTime := v.now().UTC()
	if requestTime.After(currentTime.Add(1 * time.Minute)) {
		return &DidWbaVerifierError{"Timestamp is in the future", 400}
	}

	if currentTime.Sub(requestTime) > v.config.TimestampExpirationMinutes*time.Minute {
		return &DidWbaVerifierError{"Timestamp expired", 401}
	}

	return nil
}

func (v *DidWbaVerifier) verifyNonce(ctx context.Context, did, nonce string) error {
	if v.config.ExternalNonceValidator != nil {
		ok, err := v.config.ExternalNonceValidator(ctx, did, nonce)
		if err != nil {
			return &DidWbaVerifierError{fmt.Sprintf("Nonce validator error: %v", err), 500}
		}
		if !ok {
			return &DidWbaVerifierError{"Invalid or expired nonce", 401}
		}
		return nil
	}

	v.nonceMutex.Lock()
	defer v.nonceMutex.Unlock()

	currentTime := v.now().UTC()
	// Clean up expired nonces
	for n, t := range v.validServerNonces {
		if currentTime.Sub(t) > v.config.NonceExpirationMinutes*time.Minute {
			delete(v.validServerNonces, n)
		}
	}

	if _, exists := v.validServerNonces[nonce]; exists {
		return &DidWbaVerifierError{"Nonce already used", 401}
	}

	v.validServerNonces[nonce] = currentTime
	return nil
}

func (v *DidWbaVerifier) verifySignature(authHeader string, doc *DIDWBADocument, serviceDomain string) (bool, string) {
	parts, err := parseAuthHeader(authHeader)
	if err != nil {
		return false, err.Error()
	}

	if parts.DID != doc.ID {
		return false, "DID mismatch"
	}

	// Find the specific verification method from the document
	methodMap, _, err := selectVerificationMethodForFragment(doc, parts.VerificationMethod)
	if err != nil {
		return false, fmt.Sprintf("Verification method not found: %v", err)
	}

	// Use the factory to create the correct verifier
	verifier, err := CreateVerificationMethod(methodMap)
	if err != nil {
		return false, fmt.Sprintf("Failed to create verifier: %v", err)
	}

	// Prepare the payload to be verified
	payload := authPayload{
		Nonce:   parts.Nonce,
		Time:    parts.Timestamp,
		Service: serviceDomain,
		DID:     parts.DID,
	}
	payloadBytes, err := payload.marshal()
	if err != nil {
		return false, fmt.Sprintf("Failed to marshal payload: %v", err)
	}

	if verifier.VerifySignature(payloadBytes, parts.Signature) {
		return true, "Verification successful"
	}

	return false, "Signature verification failed"
}
