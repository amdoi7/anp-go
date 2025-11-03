package anp_auth

import (
	"errors"
	"fmt"
	"testing"
)

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		expectedIs  error
		shouldMatch bool
	}{
		{
			name:        "direct sentinel error",
			err:         ErrMissingAuthHeader,
			expectedIs:  ErrMissingAuthHeader,
			shouldMatch: true,
		},
		{
			name:        "wrapped sentinel error",
			err:         WrapAuthError(ErrInvalidToken, "token validation failed", fmt.Errorf("expired")),
			expectedIs:  ErrInvalidToken,
			shouldMatch: true,
		},
		{
			name:        "different sentinel error",
			err:         ErrNonceInvalid,
			expectedIs:  ErrInvalidToken,
			shouldMatch: false,
		},
		{
			name:        "error with status wrapping sentinel",
			err:         NewErrorWithStatus(ErrTimestampExpired, StatusUnauthorized),
			expectedIs:  ErrTimestampExpired,
			shouldMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if errors.Is(tt.err, tt.expectedIs) != tt.shouldMatch {
				t.Errorf("errors.Is() = %v, want %v", !tt.shouldMatch, tt.shouldMatch)
			}
		})
	}
}

func TestWrapAuthError(t *testing.T) {
	baseErr := fmt.Errorf("base error")
	wrapped := WrapAuthError(ErrInvalidSignature, "signature check failed", baseErr)

	if !errors.Is(wrapped, ErrInvalidSignature) {
		t.Error("wrapped error should match sentinel")
	}

	if wrapped.Error() == "" {
		t.Error("wrapped error should have non-empty message")
	}
}

func TestErrorWithStatus(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		statusCode   int
		defaultCode  int
		expectedCode int
	}{
		{
			name:         "error with status",
			err:          NewErrorWithStatus(ErrInvalidToken, StatusUnauthorized),
			defaultCode:  StatusInternalServerError,
			expectedCode: StatusUnauthorized,
		},
		{
			name:         "regular error uses default",
			err:          fmt.Errorf("regular error"),
			defaultCode:  StatusBadRequest,
			expectedCode: StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := GetStatusCode(tt.err, tt.defaultCode)
			if code != tt.expectedCode {
				t.Errorf("GetStatusCode() = %d, want %d", code, tt.expectedCode)
			}
		})
	}
}

func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"missing auth header", ErrMissingAuthHeader},
		{"invalid token", ErrInvalidToken},
		{"nonce reused", ErrNonceReused},
		{"timestamp expired", ErrTimestampExpired},
		{"domain not allowed", ErrDomainNotAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() == "" {
				t.Errorf("error %s should have non-empty message", tt.name)
			}
		})
	}
}

func TestWrappedErrorUnwrap(t *testing.T) {
	baseErr := fmt.Errorf("underlying cause")
	wrapped := WrapAuthError(ErrDIDResolution, "failed to resolve", baseErr)

	// Should unwrap to sentinel error
	if !errors.Is(wrapped, ErrDIDResolution) {
		t.Error("Should unwrap to sentinel error")
	}

	// Check error message contains context
	if wrapped.Error() == "" {
		t.Error("Wrapped error should have message")
	}
}
