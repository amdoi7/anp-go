package anp_auth

import "errors"

// Sentinel errors for common authentication failures.
// These errors can be checked using errors.Is() for programmatic error handling.

var (
	// ErrMissingAuthHeader is returned when the Authorization header is missing
	ErrMissingAuthHeader = errors.New("missing authorization header")

	// ErrInvalidAuthHeader is returned when the Authorization header format is invalid
	ErrInvalidAuthHeader = errors.New("invalid authorization header")

	// ErrInvalidToken is returned when the JWT token is invalid or expired
	ErrInvalidToken = errors.New("invalid token")

	// ErrTokenExpired is returned when the JWT token has expired
	ErrTokenExpired = errors.New("token expired")

	// ErrInvalidSignature is returned when the DID-WBA signature verification fails
	ErrInvalidSignature = errors.New("signature verification failed")

	// ErrNonceReused is returned when a nonce has already been used (replay attack)
	ErrNonceReused = errors.New("nonce already used")

	// ErrNonceInvalid is returned when the nonce is invalid or expired
	ErrNonceInvalid = errors.New("invalid or expired nonce")

	// ErrTimestampExpired is returned when the request timestamp is too old
	ErrTimestampExpired = errors.New("timestamp expired")

	// ErrTimestampFuture is returned when the request timestamp is in the future
	ErrTimestampFuture = errors.New("timestamp is in the future")

	// ErrTimestampInvalid is returned when the timestamp format is invalid
	ErrTimestampInvalid = errors.New("invalid timestamp format")

	// ErrDomainNotAllowed is returned when the request domain is not in the allowed list
	ErrDomainNotAllowed = errors.New("domain not allowed")

	// ErrDIDMismatch is returned when the DID in the signature doesn't match the document
	ErrDIDMismatch = errors.New("DID mismatch")

	// ErrDIDResolution is returned when DID document resolution fails
	ErrDIDResolution = errors.New("failed to resolve DID document")

	// ErrVerificationMethodNotFound is returned when the verification method is not found
	ErrVerificationMethodNotFound = errors.New("verification method not found")

	// ErrUnsupportedVerificationMethod is returned when the verification method type is not supported
	ErrUnsupportedVerificationMethod = errors.New("unsupported verification method type")

	// ErrJWTConfigMissing is returned when required JWT configuration is missing
	ErrJWTConfigMissing = errors.New("JWT key not configured")

	// ErrNonceValidatorMissing is returned when NonceValidator is not provided
	ErrNonceValidatorMissing = errors.New("nonce validator is required")

	// ErrNonceValidatorFailure is returned when the nonce validator encounters an error
	ErrNonceValidatorFailure = errors.New("nonce validator error")

	// ErrInvalidDIDFormat is returned when the DID format is invalid
	ErrInvalidDIDFormat = errors.New("invalid DID format")

	// ErrInvalidHostname is returned when the hostname is invalid
	ErrInvalidHostname = errors.New("invalid hostname")

	// ErrKeyGeneration is returned when key pair generation fails
	ErrKeyGeneration = errors.New("failed to generate key pair")

	// ErrPayloadMarshal is returned when payload marshaling fails
	ErrPayloadMarshal = errors.New("failed to marshal payload")

	// ErrSigningFailure is returned when signature creation fails
	ErrSigningFailure = errors.New("failed to sign payload")

	// ErrInvalidJWK is returned when JWK parameters are invalid
	ErrInvalidJWK = errors.New("invalid JWK parameters")

	// ErrTokenCreation is returned when access token creation fails
	ErrTokenCreation = errors.New("failed to create access token")
)

// Common error wrapping helpers

// WrapAuthError wraps an error with additional context and associates it with a sentinel error
func WrapAuthError(sentinel error, message string, err error) error {
	if err == nil {
		return sentinel
	}
	return &wrappedAuthError{
		sentinel: sentinel,
		message:  message,
		cause:    err,
	}
}

type wrappedAuthError struct {
	sentinel error
	message  string
	cause    error
}

func (e *wrappedAuthError) Error() string {
	if e.message != "" {
		return e.message + ": " + e.cause.Error()
	}
	return e.cause.Error()
}

func (e *wrappedAuthError) Unwrap() error {
	return e.sentinel
}

func (e *wrappedAuthError) Is(target error) bool {
	return errors.Is(e.sentinel, target)
}

// ErrorWithStatus combines an error with an HTTP status code
type ErrorWithStatus struct {
	Err        error
	StatusCode int
}

func (e *ErrorWithStatus) Error() string {
	return e.Err.Error()
}

func (e *ErrorWithStatus) Unwrap() error {
	return e.Err
}

// NewErrorWithStatus creates an error with an associated HTTP status code
func NewErrorWithStatus(err error, statusCode int) *ErrorWithStatus {
	return &ErrorWithStatus{
		Err:        err,
		StatusCode: statusCode,
	}
}

// GetStatusCode extracts the HTTP status code from an error.
// It checks for ErrorWithStatus or uses the default.
func GetStatusCode(err error, defaultCode int) int {
	var statusErr *ErrorWithStatus
	if errors.As(err, &statusErr) {
		return statusErr.StatusCode
	}

	return defaultCode
}
