package anp_auth

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/openanp/anp-go/crypto"

	"github.com/bytedance/sonic"
)

// VerificationMethod is an interface for verifying signatures based on a DID document's verification method.
type VerificationMethod interface {
	// VerifySignature checks if the given signature is valid for the content.
	VerifySignature(content []byte, signature string) bool
	// GetPublicKey returns the public key.
	GetPublicKey() any
}

// EcdsaSecp256k1VerificationKey2019 implements VerificationMethod for the EcdsaSecp256k1VerificationKey2019 type.
type EcdsaSecp256k1VerificationKey2019 struct {
	PublicKey *ecdsa.PublicKey
}

// GetPublicKey returns the public key.
func (v *EcdsaSecp256k1VerificationKey2019) GetPublicKey() any {
	return v.PublicKey
}

// VerifySignature verifies a SHA-256 digest of the content against the provided signature.
// The signature is expected to be in base64url format, representing the R and S values concatenated.
func (v *EcdsaSecp256k1VerificationKey2019) VerifySignature(content []byte, signature string) bool {
	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		// Signature decode failed, verification fails
		return false
	}

	r, s, err := unmarshalSignature(v.PublicKey.Curve, sigBytes)
	if err != nil {
		// Signature unmarshal failed, verification fails
		return false
	}

	digest := sha256.Sum256(content)
	return ecdsa.Verify(v.PublicKey, digest[:], r, s)
}

// NewEcdsaSecp256k1VerificationKey2019 creates an instance from a verification method map.
func NewEcdsaSecp256k1VerificationKey2019(methodMap map[string]any) (VerificationMethod, error) {
	jwkMap, ok := methodMap["publicKeyJwk"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("publicKeyJwk not found or not a map")
	}

	var jwk JWK
	jwkBytes, err := sonic.Marshal(jwkMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal publicKeyJwk: %w", err)
	}
	if err := sonic.Unmarshal(jwkBytes, &jwk); err != nil {
		return nil, fmt.Errorf("failed to unmarshal publicKeyJwk: %w", err)
	}

	if jwk.Kty != JWKTypeEC || jwk.Crv != JWKCurveSecp256k1 {
		return nil, fmt.Errorf("unsupported JWK parameters for secp256k1: kty=%s, crv=%s", jwk.Kty, jwk.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("invalid JWK 'x' coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("invalid JWK 'y' coordinate: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	curve := crypto.Secp256k1()
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("public key is not on the secp256k1 curve")
	}

	publicKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	return &EcdsaSecp256k1VerificationKey2019{PublicKey: publicKey}, nil
}

// VerificationMethodFactory is a map of verification method types to their constructor functions.
var VerificationMethodFactory = map[string]func(map[string]any) (VerificationMethod, error){
	VerificationMethodEcdsaSecp256k1: NewEcdsaSecp256k1VerificationKey2019,
}

// CreateVerificationMethod creates a VerificationMethod instance based on the method type.
func CreateVerificationMethod(methodMap map[string]any) (VerificationMethod, error) {
	methodType, ok := methodMap["type"].(string)
	if !ok {
		return nil, fmt.Errorf("verification method 'type' not found or not a string")
	}

	factory, ok := VerificationMethodFactory[methodType]
	if !ok {
		return nil, fmt.Errorf("unsupported verification method type: %s", methodType)
	}

	return factory(methodMap)
}
