package anp_auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	anpcrypto "anp/crypto"

	"github.com/golang-jwt/jwt/v5"
)

// LoadJWTPrivateKeyFromPEM parses a PEM-encoded private key for JWT signing.
// It supports RSA, ECDSA (including secp256k1 via the ANP crypto helpers), and Ed25519 keys.
func LoadJWTPrivateKeyFromPEM(pemBytes []byte) (any, error) {
	if key, err := jwt.ParseRSAPrivateKeyFromPEM(pemBytes); err == nil {
		return key, nil
	}
	if key, err := jwt.ParseECPrivateKeyFromPEM(pemBytes); err == nil {
		return key, nil
	}
	if key, err := jwt.ParseEdPrivateKeyFromPEM(pemBytes); err == nil {
		return key, nil
	}

	if key, err := anpcrypto.PrivateKeyFromPEM(pemBytes); err == nil {
		return key, nil
	} else {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
}

// LoadJWTPublicKeyFromPEM parses a PEM-encoded public key for JWT verification.
// It supports RSA, ECDSA (including secp256k1), and Ed25519 keys.
func LoadJWTPublicKeyFromPEM(pemBytes []byte) (any, error) {
	if key, err := jwt.ParseRSAPublicKeyFromPEM(pemBytes); err == nil {
		return key, nil
	}
	if key, err := jwt.ParseECPublicKeyFromPEM(pemBytes); err == nil {
		return key, nil
	}
	if key, err := jwt.ParseEdPublicKeyFromPEM(pemBytes); err == nil {
		return key, nil
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Attempt to parse generic SubjectPublicKeyInfo structure.
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	switch pk := parsed.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		return pk, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pk)
	}
}

// DiagnoseKeyType returns a string describing the concrete key type.
func DiagnoseKeyType(key any) string {
	switch key.(type) {
	case *rsa.PrivateKey:
		return "rsa-private"
	case *rsa.PublicKey:
		return "rsa-public"
	case *ecdsa.PrivateKey:
		return "ecdsa-private"
	case *ecdsa.PublicKey:
		return "ecdsa-public"
	case ed25519.PrivateKey:
		return "ed25519-private"
	case ed25519.PublicKey:
		return "ed25519-public"
	default:
		return fmt.Sprintf("unknown(%T)", key)
	}
}
