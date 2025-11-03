package anp_auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Removed: DidWbaVerifierError (use ErrorWithStatus and sentinel errors instead)

// DidWbaVerifierConfig holds the configuration for the DidWbaVerifier.
type DidWbaVerifierConfig struct {
	JWTPrivateKey         any
	JWTPublicKey          any
	JWTPrivateKeyPEM      []byte
	JWTPublicKeyPEM       []byte
	JWTAlgorithm          string
	AccessTokenExpiration time.Duration
	TimestampExpiration   time.Duration
	DIDCacheExpiration    time.Duration
	AllowedDomains        []string
	NonceValidator        NonceValidator
	ResolveDIDDocument    ResolveDIDDocumentFunc
	Now                   func() time.Time
	HTTPClient            *http.Client
}

// ResolveDIDDocumentFunc resolves a DID document for a given DID identifier.
type ResolveDIDDocumentFunc func(ctx context.Context, did string) (*DIDWBADocument, error)

// didCacheEntry stores a cached DID document with its expiration time.
type didCacheEntry struct {
	doc       *DIDWBADocument
	expiresAt time.Time
}

// DidWbaVerifier verifies Authorization headers for DID WBA and Bearer JWT.
type DidWbaVerifier struct {
	config        DidWbaVerifierConfig
	didCache      map[string]didCacheEntry
	didCacheMutex sync.Mutex
	now           func() time.Time
}

// NewDidWbaVerifier creates a new verifier with the given configuration.
// NonceValidator is required to prevent replay attacks.
func NewDidWbaVerifier(config DidWbaVerifierConfig) (*DidWbaVerifier, error) {
	if config.NonceValidator == nil {
		return nil, ErrNonceValidatorMissing
	}

	if config.JWTAlgorithm == "" {
		config.JWTAlgorithm = DefaultJWTAlgorithm
	}
	if config.AccessTokenExpiration == 0 {
		config.AccessTokenExpiration = DefaultAccessTokenExpiration
	}
	if config.TimestampExpiration == 0 {
		config.TimestampExpiration = DefaultTimestampExpiration
	}
	if config.DIDCacheExpiration == 0 {
		config.DIDCacheExpiration = DefaultDIDCacheExpiration
	}

	if config.JWTPrivateKey == nil && len(config.JWTPrivateKeyPEM) > 0 {
		key, err := LoadJWTPrivateKeyFromPEM(config.JWTPrivateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("loading JWT private key: %w", err)
		}
		config.JWTPrivateKey = key
	}

	if config.JWTPublicKey == nil && len(config.JWTPublicKeyPEM) > 0 {
		key, err := LoadJWTPublicKeyFromPEM(config.JWTPublicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("loading JWT public key: %w", err)
		}
		config.JWTPublicKey = key
	}

	if config.Now == nil {
		config.Now = time.Now
	}

	return &DidWbaVerifier{
		config:   config,
		didCache: make(map[string]didCacheEntry),
		now:      config.Now,
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

	return NewErrorWithStatus(fmt.Errorf("%w: %s", ErrDomainNotAllowed, domain), StatusForbidden)
}

// VerifyAuthHeader verifies an HTTP Authorization header.
// It handles both "Bearer" JWT tokens and "DIDWba" headers.
func (v *DidWbaVerifier) VerifyAuthHeader(authorization, domain string) (map[string]any, error) {
	return v.VerifyAuthHeaderContext(context.Background(), authorization, domain)
}

// VerifyAuthHeaderContext is the context-aware variant of VerifyAuthHeader.
func (v *DidWbaVerifier) VerifyAuthHeaderContext(ctx context.Context, authorization, domain string) (map[string]any, error) {
	if authorization == "" {
		return nil, NewErrorWithStatus(ErrMissingAuthHeader, StatusUnauthorized)
	}

	if strings.HasPrefix(authorization, BearerScheme) {
		return v.handleBearerAuth(authorization)
	}

	return v.handleDidAuth(ctx, authorization, domain)
}

func (v *DidWbaVerifier) handleBearerAuth(authorization string) (map[string]any, error) {
	tokenString := strings.TrimPrefix(authorization, BearerScheme)
	if v.config.JWTPublicKey == nil {
		return nil, NewErrorWithStatus(ErrJWTConfigMissing, StatusInternalServerError)
	}

	did, err := VerifyAccessToken(tokenString, v.config.JWTPublicKey, v.config.JWTAlgorithm)
	if err != nil {
		return nil, NewErrorWithStatus(WrapAuthError(ErrInvalidToken, "verify access token", err), StatusUnauthorized)
	}

	return map[string]any{"did": did}, nil
}

func (v *DidWbaVerifier) handleDidAuth(ctx context.Context, authorization, domain string) (map[string]any, error) {
	if err := v.ensureDomainAllowed(domain); err != nil {
		return nil, err
	}

	headerParts, err := parseAuthHeader(authorization)
	if err != nil {
		return nil, NewErrorWithStatus(WrapAuthError(ErrInvalidAuthHeader, "parse auth header", err), StatusUnauthorized)
	}

	if err := v.verifyTimestamp(headerParts.Timestamp); err != nil {
		return nil, err
	}

	if err := v.verifyNonce(ctx, headerParts.DID, headerParts.Nonce); err != nil {
		return nil, err
	}

	didDocument, err := v.resolveAndCacheDID(ctx, headerParts.DID)
	if err != nil {
		return nil, err
	}

	isValid, message := v.verifySignature(authorization, didDocument, domain)
	if !isValid {
		return nil, NewErrorWithStatus(fmt.Errorf("%w: %s", ErrInvalidSignature, message), StatusForbidden)
	}

	if v.config.JWTPrivateKey == nil {
		return nil, NewErrorWithStatus(ErrJWTConfigMissing, StatusInternalServerError)
	}

	accessToken, err := CreateAccessToken(headerParts.DID, v.config.JWTPrivateKey, v.config.JWTAlgorithm, v.config.AccessTokenExpiration)
	if err != nil {
		return nil, NewErrorWithStatus(WrapAuthError(ErrTokenCreation, "create access token", err), StatusInternalServerError)
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

	resolver := v.config.ResolveDIDDocument
	var doc *DIDWBADocument
	var err error
	if resolver != nil {
		doc, err = resolver(ctx, did)
	} else {
		doc, err = ResolveDIDWBADocument(did, v.config.HTTPClient)
	}
	if err != nil {
		return nil, NewErrorWithStatus(WrapAuthError(ErrDIDResolution, "resolve DID document", err), StatusUnauthorized)
	}

	v.didCacheMutex.Lock()
	defer v.didCacheMutex.Unlock()

	if entry, exists := v.didCache[did]; exists && v.now().UTC().Before(entry.expiresAt) {
		return entry.doc, nil
	}

	v.didCache[did] = didCacheEntry{
		doc:       doc,
		expiresAt: v.now().UTC().Add(v.config.DIDCacheExpiration),
	}

	return doc, nil
}

func (v *DidWbaVerifier) verifyTimestamp(timestampStr string) error {
	requestTime, err := time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		return NewErrorWithStatus(WrapAuthError(ErrTimestampInvalid, "parse timestamp", err), StatusBadRequest)
	}

	currentTime := v.now().UTC()
	if requestTime.After(currentTime.Add(DefaultTimestampTolerance)) {
		return NewErrorWithStatus(ErrTimestampFuture, StatusBadRequest)
	}

	if currentTime.Sub(requestTime) > v.config.TimestampExpiration {
		return NewErrorWithStatus(ErrTimestampExpired, StatusUnauthorized)
	}

	return nil
}

func (v *DidWbaVerifier) verifyNonce(ctx context.Context, did, nonce string) error {
	ok, err := v.config.NonceValidator.Validate(ctx, did, nonce)
	if err != nil {
		return NewErrorWithStatus(WrapAuthError(ErrNonceValidatorFailure, "validate nonce", err), StatusInternalServerError)
	}
	if !ok {
		return NewErrorWithStatus(ErrNonceInvalid, StatusUnauthorized)
	}
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
