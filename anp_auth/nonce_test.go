package anp_auth

import (
	"context"
	"testing"
	"time"
)

func TestMemoryNonceValidator_Validate(t *testing.T) {
	validator := NewMemoryNonceValidator(5 * time.Minute)
	ctx := context.Background()

	tests := []struct {
		name      string
		did       string
		nonce     string
		wantValid bool
		wantErr   bool
	}{
		{
			name:      "first use of nonce should succeed",
			did:       "did:wba:example.com",
			nonce:     "nonce-1",
			wantValid: true,
			wantErr:   false,
		},
		{
			name:      "reuse of same nonce should fail",
			did:       "did:wba:example.com",
			nonce:     "nonce-1",
			wantValid: false,
			wantErr:   false,
		},
		{
			name:      "different nonce for same DID should succeed",
			did:       "did:wba:example.com",
			nonce:     "nonce-2",
			wantValid: true,
			wantErr:   false,
		},
		{
			name:      "same nonce for different DID should succeed",
			did:       "did:wba:other.com",
			nonce:     "nonce-1",
			wantValid: true,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := validator.Validate(ctx, tt.did, tt.nonce)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if valid != tt.wantValid {
				t.Errorf("Validate() valid = %v, wantValid %v", valid, tt.wantValid)
			}
		})
	}
}

func TestMemoryNonceValidator_Expiration(t *testing.T) {
	validator := NewMemoryNonceValidator(100 * time.Millisecond)
	ctx := context.Background()

	valid, err := validator.Validate(ctx, "did:wba:example.com", "nonce-expiry")
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !valid {
		t.Fatal("First validation should succeed")
	}

	time.Sleep(150 * time.Millisecond)

	valid, err = validator.Validate(ctx, "did:wba:example.com", "nonce-expiry")
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !valid {
		t.Error("Nonce should be valid again after expiration")
	}
}
