package anp_auth

import "time"

// DID and Authentication Constants
const (
	// DIDPrefix is the standard prefix for DID-WBA identifiers
	DIDPrefix = "did:wba:"

	// DIDWbaScheme is the authentication scheme name
	DIDWbaScheme = "DIDWba"

	// BearerScheme is the bearer token authentication scheme
	BearerScheme = "Bearer "

	// AuthorizationHeader is the HTTP header name for authentication
	AuthorizationHeader = "Authorization"
)

// Verification Method Types
const (
	// VerificationMethodEcdsaSecp256k1 is the ECDSA secp256k1 verification method type
	VerificationMethodEcdsaSecp256k1 = "EcdsaSecp256k1VerificationKey2019"
)

// DID Document Contexts
const (
	// ContextDIDV1 is the W3C DID v1 context URL
	ContextDIDV1 = "https://www.w3.org/ns/did/v1"

	// ContextJWS2020 is the JWS 2020 suite context URL
	ContextJWS2020 = "https://w3id.org/security/suites/jws-2020/v1"

	// ContextSecp256k12019 is the secp256k1 2019 suite context URL
	ContextSecp256k12019 = "https://w3id.org/security/suites/secp256k1-2019/v1"
)

// Service Types
const (
	// ServiceTypeAgentDescription is the service type for agent descriptions
	ServiceTypeAgentDescription = "AgentDescription"
)

// JWK Constants
const (
	// JWKTypeEC is the elliptic curve key type
	JWKTypeEC = "EC"

	// JWKCurveSecp256k1 is the secp256k1 curve name
	JWKCurveSecp256k1 = "secp256k1"
)

// Default Configuration Values
const (
	// DefaultJWTAlgorithm is the default JWT signing algorithm
	DefaultJWTAlgorithm = "RS256"

	// DefaultAccessTokenExpiration is the default access token expiration
	DefaultAccessTokenExpiration = 60 * time.Minute

	// DefaultTimestampExpiration is the default timestamp expiration
	DefaultTimestampExpiration = 5 * time.Minute

	// DefaultDIDCacheExpiration is the default DID document cache expiration
	DefaultDIDCacheExpiration = 15 * time.Minute

	// DefaultNonceExpiration is the default nonce expiration
	DefaultNonceExpiration = 6 * time.Minute

	// DefaultTimestampTolerance is the tolerance for future timestamps
	DefaultTimestampTolerance = 1 * time.Minute
)

// Well-Known Paths
const (
	// WellKnownDIDPath is the path for DID documents at domain root
	WellKnownDIDPath = "/.well-known/did.json"

	// DIDDocumentFilename is the filename for DID documents
	DIDDocumentFilename = "did.json"
)

// Verification Method ID Patterns
const (
	// DefaultVerificationMethodFragment is the default key fragment
	DefaultVerificationMethodFragment = "key-1"

	// AgentDescriptionFragment is the fragment for agent description services
	AgentDescriptionFragment = "ad"
)

// HTTP Status Codes (for clarity in error handling)
const (
	// StatusUnauthorized represents 401 status
	StatusUnauthorized = 401

	// StatusForbidden represents 403 status
	StatusForbidden = 403

	// StatusBadRequest represents 400 status
	StatusBadRequest = 400

	// StatusInternalServerError represents 500 status
	StatusInternalServerError = 500
)
