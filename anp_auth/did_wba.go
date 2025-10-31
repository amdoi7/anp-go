// Package anp_auth implements DID-WBA (Decentralized Identifier - Web-Based Authentication).
// It provides functionality for creating and resolving DID documents and for generating
// and verifying authentication headers.
package anp_auth

import (
	"anp/crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/google/uuid"
)

// DIDWBADocument represents a DID-WBA document.
type DIDWBADocument struct {
	Context            []string         `json:"@context"`
	ID                 string           `json:"id"`
	VerificationMethod []map[string]any `json:"verificationMethod"`
	Authentication     []string         `json:"authentication"`
	Service            []Service        `json:"service,omitempty"`
}

// JWK represents a JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
}

// Service represents a service in a DID document.
type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// CreateDIDWBADocument generates a DID document and the corresponding private key.
func CreateDIDWBADocument(hostname string, port *int, pathSegments []string, agentDescriptionURL *string) (*DIDWBADocument, *ecdsa.PrivateKey, error) {
	if err := validateHostname(hostname); err != nil {
		return nil, nil, err
	}

	did, err := buildDID(hostname, port, pathSegments)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := crypto.GenerateECKeyPair(crypto.Secp256k1())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	verificationMethodID := fmt.Sprintf("%s#key-1", did)

	doc := &DIDWBADocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
			"https://w3id.org/security/suites/secp256k1-2019/v1",
		},
		ID: did,
		VerificationMethod: []map[string]any{
			{
				"id":           verificationMethodID,
				"type":         "EcdsaSecp256k1VerificationKey2019",
				"controller":   did,
				"publicKeyJwk": buildPublicKeyJWK(&privateKey.PublicKey),
			},
		},
		Authentication: []string{verificationMethodID},
	}

	if agentDescriptionURL != nil {
		doc.Service = []Service{{
			ID:              fmt.Sprintf("%s#ad", did),
			Type:            "AgentDescription",
			ServiceEndpoint: *agentDescriptionURL,
		}}
	}

	return doc, privateKey, nil
}

func buildDID(hostname string, port *int, pathSegments []string) (string, error) {
	if hostname == "" {
		return "", fmt.Errorf("hostname cannot be empty")
	}

	didBase := fmt.Sprintf("did:wba:%s", hostname)
	if port != nil {
		encodedPort := url.PathEscape(fmt.Sprintf(":%d", *port))
		didBase += encodedPort
	}

	did := didBase
	if len(pathSegments) > 0 {
		cleaned := make([]string, 0, len(pathSegments))
		for _, segment := range pathSegments {
			trimmed := strings.TrimSpace(segment)
			if trimmed == "" {
				continue
			}
			cleaned = append(cleaned, url.PathEscape(trimmed))
		}
		if len(cleaned) > 0 {
			did = fmt.Sprintf("%s:%s", didBase, strings.Join(cleaned, ":"))
		}
	}

	return did, nil
}

var defaultHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
}

// ResolveDIDWBADocument resolves a DID document from a DID URL.
func ResolveDIDWBADocument(did string, httpClient ...*http.Client) (*DIDWBADocument, error) {
	url, err := didToURL(did)
	if err != nil {
		return nil, err
	}

	client := defaultHTTPClient
	if len(httpClient) > 0 && httpClient[0] != nil {
		client = httpClient[0]
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get DID document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get DID document: status code %d", resp.StatusCode)
	}

	var doc DIDWBADocument
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	if err := sonic.Unmarshal(bodyBytes, &doc); err != nil {
		return nil, fmt.Errorf("failed to decode DID document: %w", err)
	}

	if doc.ID != did {
		return nil, fmt.Errorf("DID document ID mismatch")
	}

	return &doc, nil
}

var didToURL = func(did string) (string, error) {
	if !strings.HasPrefix(did, "did:wba:") {
		return "", fmt.Errorf("invalid DID format: must start with 'did:wba:'")
	}

	parts := strings.SplitN(did, ":", 4)
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid DID format: missing domain")
	}

	domain, err := url.PathUnescape(parts[2])
	if err != nil {
		return "", fmt.Errorf("failed to unescape domain: %w", err)
	}

	path := "/.well-known/did.json"
	if len(parts) > 3 {
		path = "/" + strings.ReplaceAll(parts[3], ":", "/") + "/did.json"
	}

	return fmt.Sprintf("https://%s%s", domain, path), nil
}

// AuthHeader represents the components of a DID-WBA Authorization header.
type AuthHeader struct {
	DID                string
	Nonce              string
	Timestamp          string
	VerificationMethod string
	Signature          string
}

// AuthJSON represents the JSON form of DID-WBA authentication payloads.
type AuthJSON struct {
	DID                string `json:"did"`
	Nonce              string `json:"nonce"`
	Timestamp          string `json:"timestamp"`
	VerificationMethod string `json:"verification_method"`
	Signature          string `json:"signature"`
}

// String returns the string representation of the AuthHeader.
func (h *AuthHeader) String() string {
	return fmt.Sprintf(
		`DIDWba did="%s", nonce="%s", timestamp="%s", verification_method="%s", signature="%s"`,
		h.DID, h.Nonce, h.Timestamp, h.VerificationMethod, h.Signature,
	)
}

// GenerateAuthHeader generates the Authorization header for DID authentication.
func GenerateAuthHeader(privateKey *ecdsa.PrivateKey, doc *DIDWBADocument, serviceDomain string) (*AuthHeader, error) {
	if doc == nil {
		return nil, errors.New("DID document is required")
	}

	// Select the first authentication method from the document
	methodMap, fragment, err := selectVerificationMethod(doc)
	if err != nil {
		return nil, err
	}

	// Ensure the selected method is appropriate
	methodType, _ := methodMap["type"].(string)
	if methodType != "EcdsaSecp256k1VerificationKey2019" {
		return nil, fmt.Errorf("unsupported verification method type for signing: %s", methodType)
	}

	nonce := newNonce()
	timestamp := time.Now().UTC().Format(time.RFC3339)

	payload := authPayload{
		Nonce:   nonce,
		Time:    timestamp,
		Service: serviceDomain,
		DID:     doc.ID,
	}

	signature, err := signPayload(privateKey, &payload)
	if err != nil {
		return nil, err
	}

	return &AuthHeader{
		DID:                doc.ID,
		Nonce:              nonce,
		Timestamp:          timestamp,
		VerificationMethod: fragment,
		Signature:          signature,
	}, nil
}

// GenerateAuthJSON produces a JSON authentication payload equivalent to the DIDWba
// Authorization header flow. The returned AuthJSON can be marshaled and transported
// over arbitrary channels (REST body、消息队列等).
func GenerateAuthJSON(privateKey *ecdsa.PrivateKey, doc *DIDWBADocument, serviceDomain string) (*AuthJSON, error) {
	if doc == nil {
		return nil, errors.New("DID document is required")
	}
	if privateKey == nil {
		return nil, errors.New("private key is required")
	}

	methodMap, fragment, err := selectVerificationMethod(doc)
	if err != nil {
		return nil, err
	}

	methodType, _ := methodMap["type"].(string)
	if methodType != "EcdsaSecp256k1VerificationKey2019" {
		return nil, fmt.Errorf("unsupported verification method type for signing: %s", methodType)
	}

	nonce := newNonce()
	timestamp := time.Now().UTC().Format(time.RFC3339)

	payload := authPayload{
		Nonce:   nonce,
		Time:    timestamp,
		Service: serviceDomain,
		DID:     doc.ID,
	}

	signature, err := signPayload(privateKey, &payload)
	if err != nil {
		return nil, err
	}

	return &AuthJSON{
		DID:                doc.ID,
		Nonce:              nonce,
		Timestamp:          timestamp,
		VerificationMethod: fragment,
		Signature:          signature,
	}, nil
}

// Marshal converts the AuthJSON to JSON bytes.
func (a *AuthJSON) Marshal() ([]byte, error) {
	if a == nil {
		return nil, errors.New("AuthJSON is nil")
	}
	return sonic.Marshal(a)
}

// ParseAuthJSON decodes JSON bytes into an AuthJSON structure.
func ParseAuthJSON(data []byte) (*AuthJSON, error) {
	if len(data) == 0 {
		return nil, errors.New("auth JSON payload is empty")
	}
	var authJSON AuthJSON
	if err := sonic.Unmarshal(data, &authJSON); err != nil {
		return nil, fmt.Errorf("failed to decode auth JSON: %w", err)
	}
	if authJSON.DID == "" || authJSON.Nonce == "" || authJSON.Timestamp == "" || authJSON.VerificationMethod == "" || authJSON.Signature == "" {
		return nil, errors.New("auth JSON missing required fields")
	}
	return &authJSON, nil
}

// VerifyAuthJSON checks the signature in an AuthJSON payload.
func VerifyAuthJSON(authJSON *AuthJSON, doc *DIDWBADocument, serviceDomain string) (bool, string) {
	if authJSON == nil {
		return false, "auth JSON payload is nil"
	}
	if doc == nil {
		return false, "DID document is required"
	}

	if authJSON.DID != doc.ID {
		return false, "DID mismatch"
	}

	methodMap, _, err := selectVerificationMethodForFragment(doc, authJSON.VerificationMethod)
	if err != nil {
		return false, fmt.Sprintf("Verification method not found: %v", err)
	}

	verifier, err := CreateVerificationMethod(methodMap)
	if err != nil {
		return false, fmt.Sprintf("Failed to create verifier: %v", err)
	}

	payload := authPayload{
		Nonce:   authJSON.Nonce,
		Time:    authJSON.Timestamp,
		Service: serviceDomain,
		DID:     authJSON.DID,
	}

	payloadBytes, err := payload.marshal()
	if err != nil {
		return false, fmt.Sprintf("Failed to marshal payload: %v", err)
	}

	if verifier.VerifySignature(payloadBytes, authJSON.Signature) {
		return true, "Verification successful"
	}

	return false, "Signature verification failed"
}

// VerifyAuthJSONBytes parses raw JSON bytes and validates the signature.
func VerifyAuthJSONBytes(data []byte, doc *DIDWBADocument, serviceDomain string) (bool, string, error) {
	authJSON, err := ParseAuthJSON(data)
	if err != nil {
		return false, "", err
	}
	ok, msg := VerifyAuthJSON(authJSON, doc, serviceDomain)
	return ok, msg, nil
}

func parseAuthHeader(header string) (*AuthHeader, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil, errors.New("authorization header cannot be empty")
	}

	if !strings.HasPrefix(header, "DIDWba") {
		return nil, fmt.Errorf("authorization header must start with 'DIDWba'")
	}

	header = strings.TrimPrefix(header, "DIDWba")
	header = strings.TrimSpace(header)

	parts := &AuthHeader{}
	re := regexp.MustCompile(`(did|nonce|timestamp|verification_method|signature)="([^"]*)"`)
	matches := re.FindAllStringSubmatch(header, -1)
	if len(matches) == 0 {
		return nil, fmt.Errorf("invalid auth header format")
	}

	for _, match := range matches {
		switch match[1] {
		case "did":
			parts.DID = match[2]
		case "nonce":
			parts.Nonce = match[2]
		case "timestamp":
			parts.Timestamp = match[2]
		case "verification_method":
			parts.VerificationMethod = match[2]
		case "signature":
			parts.Signature = match[2]
		}
	}

	if parts.DID == "" || parts.Nonce == "" || parts.Timestamp == "" || parts.VerificationMethod == "" || parts.Signature == "" {
		return nil, fmt.Errorf("invalid auth header format")
	}

	return parts, nil
}

type authPayload struct {
	Nonce   string `json:"nonce"`
	Time    string `json:"timestamp"`
	Service string `json:"service"`
	DID     string `json:"did"`
}

func (p *authPayload) marshal() ([]byte, error) {
	// Marshal to JSON first, then canonicalize
	jsonBytes, err := sonic.Marshal(p)
	if err != nil {
		return nil, err
	}
	// Canonicalize using JCS
	return jsoncanonicalizer.Transform(jsonBytes)
}

func newNonce() string {
	return uuid.NewString()
}

func signPayload(privateKey *ecdsa.PrivateKey, payload *authPayload) (string, error) {
	if privateKey == nil {
		return "", errors.New("private key is required")
	}

	data, err := payload.marshal()
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Python implementation passes a SHA-256 digest into ECDSA(SHA256).
	// cryptography re-hashes the provided digest internally, so the effective
	// signing input becomes SHA256(SHA256(payload)). Mirror that here to remain
	// interoperable with the Python SDK.
	digest := sha256.Sum256(data)
	finalDigest := sha256.Sum256(digest[:])
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, finalDigest[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign payload: %w", err)
	}

	return marshalSignature(privateKey.Curve, r, s)
}

func marshalSignature(curve elliptic.Curve, r, s *big.Int) (string, error) {
	if curve == nil {
		return "", errors.New("elliptic curve is required")
	}

	params := curve.Params()
	size := (params.BitSize + 7) / 8
	rb := r.Bytes()
	sb := s.Bytes()
	if len(rb) > size || len(sb) > size {
		return "", fmt.Errorf("signature component larger than curve size")
	}

	sig := make([]byte, size*2)
	copy(sig[size-len(rb):size], rb)
	copy(sig[2*size-len(sb):], sb)

	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func unmarshalSignature(curve elliptic.Curve, sig []byte) (*big.Int, *big.Int, error) {
	size := (curve.Params().BitSize + 7) / 8
	if len(sig) != size*2 {
		return nil, nil, fmt.Errorf("invalid signature length: got %d want %d", len(sig), size*2)
	}

	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])

	return r, s, nil
}

func buildPublicKeyJWK(publicKey *ecdsa.PublicKey) JWK {
	params := publicKey.Curve.Params()
	coordSize := (params.BitSize + 7) / 8
	x := padAndEncode(publicKey.X, coordSize)
	y := padAndEncode(publicKey.Y, coordSize)

	compressed := compressPoint(publicKey)
	kid := base64.RawURLEncoding.EncodeToString(hashSHA256(compressed))

	return JWK{
		Kty: "EC",
		Crv: "secp256k1",
		X:   x,
		Y:   y,
		Kid: kid,
	}
}

func padAndEncode(value *big.Int, size int) string {
	buf := value.Bytes()
	padded := make([]byte, size)
	copy(padded[size-len(buf):], buf)
	return base64.RawURLEncoding.EncodeToString(padded)
}

func compressPoint(publicKey *ecdsa.PublicKey) []byte {
	size := (publicKey.Curve.Params().BitSize + 7) / 8
	buf := make([]byte, size+1)
	if publicKey.Y.Bit(0) == 0 {
		buf[0] = 0x02
	} else {
		buf[0] = 0x03
	}
	xBytes := publicKey.X.Bytes()
	copy(buf[1+size-len(xBytes):], xBytes)
	return buf
}

func hashSHA256(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func selectVerificationMethod(doc *DIDWBADocument) (map[string]any, string, error) {
	if len(doc.Authentication) == 0 {
		return nil, "", errors.New("did document missing authentication methods")
	}

	reference := doc.Authentication[0]
	fragment := reference

	if idx := strings.Index(reference, "#"); idx >= 0 {
		fragment = reference[idx+1:]
	}

	return selectVerificationMethodForFragment(doc, fragment)
}

func selectVerificationMethodForFragment(doc *DIDWBADocument, fragment string) (map[string]any, string, error) {
	if fragment == "" {
		return nil, "", errors.New("verification method fragment cannot be empty")
	}

	verificationMethodID := fmt.Sprintf("%s#%s", doc.ID, fragment)
	for _, method := range doc.VerificationMethod {
		if id, ok := method["id"].(string); ok && id == verificationMethodID {
			return method, fragment, nil
		}
	}
	return nil, "", fmt.Errorf("verification method not found: %s", fragment)
}

func validateHostname(hostname string) error {
	if hostname == "" {
		return fmt.Errorf("hostname cannot be empty")
	}

	if ip := net.ParseIP(hostname); ip != nil {
		return fmt.Errorf("hostname cannot be an IP address")
	}

	return nil
}
