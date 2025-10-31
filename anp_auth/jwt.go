package anp_auth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// CreateAccessToken creates a new JWT access token.
func CreateAccessToken(did string, privateKey any, algorithm string, expiration time.Duration) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": did,
		"iat": now.Unix(),
		"exp": now.Add(expiration).Unix(),
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod(algorithm), claims)

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

// VerifyAccessToken verifies a JWT access token and returns the DID (subject).
func VerifyAccessToken(tokenString string, publicKey any, algorithm string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(algorithm) != token.Method {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return "", fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("token is invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}

	did, ok := claims["sub"].(string)
	if !ok {
		return "", fmt.Errorf("'sub' claim is missing or not a string")
	}

	return did, nil
}

// Utility function to parse RSA private key from PEM bytes (example)
// You would have similar functions for other key types
func ParseRSAPrivateKeyFromPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	return jwt.ParseRSAPrivateKeyFromPEM(pemBytes)
}

// Utility function to parse RSA public key from PEM bytes (example)
func ParseRSAPublicKeyFromPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	return jwt.ParseRSAPublicKeyFromPEM(pemBytes)
}

// Utility function to parse ECDSA private key from PEM bytes (example)
func ParseECPrivateKeyFromPEM(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	return jwt.ParseECPrivateKeyFromPEM(pemBytes)
}

// Utility function to parse ECDSA public key from PEM bytes (example)
func ParseECPublicKeyFromPEM(pemBytes []byte) (*ecdsa.PublicKey, error) {
	return jwt.ParseECPublicKeyFromPEM(pemBytes)
}
