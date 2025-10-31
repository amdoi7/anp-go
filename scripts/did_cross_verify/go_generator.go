package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"anp/anp_auth"
	"anp/crypto"

	"github.com/bytedance/sonic"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/google/uuid"
)

type step1Params struct {
	DID                  string `json:"did"`
	Nonce                string `json:"nonce"`
	Timestamp            string `json:"timestamp"`
	VerificationMethod   string `json:"verification_method"`
	VerificationMethodID string `json:"verification_method_id"`
	ServiceDomain        string `json:"service_domain"`
}

type step4Header struct {
	AuthHeader string `json:"auth_header"`
}

type authPayload struct {
	Nonce   string `json:"nonce"`
	Time    string `json:"timestamp"`
	Service string `json:"service"`
	DID     string `json:"did"`
}

func main() {
	var (
		didDocPath     string
		privateKeyPath string
		targetURL      string
		outputDir      string
		fixedNonce     string
		fixedTimestamp string
	)

	flag.StringVar(&didDocPath, "did-doc", "../../examples/did_public/public-did-doc.json", "DID document path")
	flag.StringVar(&privateKeyPath, "private-key", "../../examples/did_public/public-private-key.pem", "Private key path")
	flag.StringVar(&targetURL, "target", "https://test.example.com/api", "Target URL")
	flag.StringVar(&outputDir, "output", "artifacts", "Output directory")
	flag.StringVar(&fixedNonce, "nonce", "", "Fixed nonce (for reproducible tests)")
	flag.StringVar(&fixedTimestamp, "timestamp", "", "Fixed timestamp (for reproducible tests)")
	flag.Parse()

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		log.Fatalf("failed to create output directory: %v", err)
	}

	didDoc, err := loadDIDDocument(didDocPath)
	if err != nil {
		log.Fatalf("failed to load DID document: %v", err)
	}

	privateKey, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		log.Fatalf("failed to load private key: %v", err)
	}

	serviceDomain := extractDomain(targetURL)
	verificationFragment, err := selectVerificationFragment(didDoc)
	if err != nil {
		log.Fatalf("failed to determine verification method fragment: %v", err)
	}

	nonce := fixedNonce
	if nonce == "" {
		nonce = uuid.NewString()
	}

	timestamp := fixedTimestamp
	if timestamp == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	step1 := step1Params{
		DID:                  didDoc.ID,
		Nonce:                nonce,
		Timestamp:            timestamp,
		VerificationMethod:   verificationFragment,
		VerificationMethodID: fmt.Sprintf("%s#%s", didDoc.ID, verificationFragment),
		ServiceDomain:        serviceDomain,
	}

	saveJSON(filepath.Join(outputDir, "go_step1_params.json"), step1)
	fmt.Println("✓ Step 1: Parameters generated")

	payload := authPayload{
		Nonce:   step1.Nonce,
		Time:    step1.Timestamp,
		Service: step1.ServiceDomain,
		DID:     step1.DID,
	}

	payloadBytes, err := marshalCanonicalPayload(&payload)
	if err != nil {
		log.Fatalf("failed to marshal payload: %v", err)
	}
	fmt.Println("✓ Step 2: Payload canonicalized in memory")

	signature, err := signPayload(privateKey, payloadBytes)
	if err != nil {
		log.Fatalf("failed to sign payload: %v", err)
	}
	fmt.Println("✓ Step 3: Signature calculated in memory")

	authHeader := fmt.Sprintf(
		`DIDWba did="%s", nonce="%s", timestamp="%s", verification_method="%s", signature="%s"`,
		step1.DID,
		step1.Nonce,
		step1.Timestamp,
		step1.VerificationMethod,
		signature,
	)

	saveJSON(filepath.Join(outputDir, "go_step4_header.json"), step4Header{
		AuthHeader: authHeader,
	})
	fmt.Println("✓ Step 4: Auth header assembled")

	fmt.Println("\n✅ Go artifacts generated successfully")
}

func loadDIDDocument(path string) (*anp_auth.DIDWBADocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc anp_auth.DIDWBADocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return crypto.PrivateKeyFromPEM(data)
}

func selectVerificationFragment(doc *anp_auth.DIDWBADocument) (string, error) {
	if len(doc.Authentication) == 0 {
		return "", fmt.Errorf("DID document missing authentication methods")
	}
	reference := doc.Authentication[0]
	fragment := reference
	if idx := strings.Index(reference, "#"); idx >= 0 && idx+1 < len(reference) {
		fragment = reference[idx+1:]
	}
	if fragment == "" {
		return "", fmt.Errorf("invalid authentication reference: %s", reference)
	}
	return fragment, nil
}

func marshalCanonicalPayload(payload *authPayload) ([]byte, error) {
	jsonBytes, err := sonic.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(jsonBytes)
}

func signPayload(privateKey *ecdsa.PrivateKey, canonical []byte) (string, error) {
	digest := sha256.Sum256(canonical)
	finalDigest := sha256.Sum256(digest[:])

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, finalDigest[:])
	if err != nil {
		return "", err
	}

	sigBytes, err := marshalSignature(privateKey.Curve, r, s)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(sigBytes), nil
}

func marshalSignature(curve elliptic.Curve, r, s *big.Int) ([]byte, error) {
	if curve == nil {
		return nil, fmt.Errorf("elliptic curve is required")
	}

	size := (curve.Params().BitSize + 7) / 8
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	if len(rBytes) > size || len(sBytes) > size {
		return nil, fmt.Errorf("signature component larger than curve size")
	}

	sig := make([]byte, size*2)
	copy(sig[size-len(rBytes):size], rBytes)
	copy(sig[2*size-len(sBytes):], sBytes)
	return sig, nil
}

func saveJSON(path string, data any) {
	file, err := os.Create(path)
	if err != nil {
		log.Fatalf("failed to create file %s: %v", path, err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		log.Fatalf("failed to encode JSON to %s: %v", path, err)
	}
}

func extractDomain(url string) string {
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	for i, c := range url {
		if c == '/' || c == ':' {
			return url[:i]
		}
	}
	return url
}
