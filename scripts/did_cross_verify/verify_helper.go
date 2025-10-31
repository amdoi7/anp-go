package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"

	"anp/anp_auth"
)

type headerArtifact struct {
	AuthHeader string `json:"auth_header"`
}

type paramsArtifact struct {
	ServiceDomain      string `json:"service_domain"`
	DID                string `json:"did"`
	VerificationMethod string `json:"verification_method"`
}

var headerPattern = regexp.MustCompile(`(did|nonce|timestamp|verification_method|signature)="([^"]*)"`)

type parsedHeader struct {
	DID                string
	Nonce              string
	Timestamp          string
	VerificationMethod string
	Signature          string
}

func main() {
	log.SetFlags(0)

	headerPath := flag.String("header", "", "Path to header JSON artifact")
	paramsPath := flag.String("params", "", "Path to step1 parameters JSON")
	didDocPath := flag.String("did-doc", "", "Path to DID document JSON")
	overrideDomain := flag.String("service-domain", "", "Override service domain (optional)")
	flag.Parse()

	if *headerPath == "" || *paramsPath == "" || *didDocPath == "" {
		log.Fatalf("header, params, and did-doc arguments are required")
	}

	headerData, err := loadHeader(*headerPath)
	if err != nil {
		log.Fatalf("failed to load header artifact: %v", err)
	}

	params, err := loadParams(*paramsPath)
	if err != nil {
		log.Fatalf("failed to load parameter artifact: %v", err)
	}

	serviceDomain := params.ServiceDomain
	if *overrideDomain != "" {
		serviceDomain = *overrideDomain
	}
	if serviceDomain == "" {
		log.Fatalf("service domain not provided in params and no override specified")
	}

	doc, err := loadDidDocument(*didDocPath)
	if err != nil {
		log.Fatalf("failed to load DID document: %v", err)
	}

	headerParts, err := parseHeader(headerData.AuthHeader)
	if err != nil {
		log.Fatalf("invalid auth header: %v", err)
	}

	authJSON := anp_auth.AuthJSON{
		DID:                headerParts.DID,
		Nonce:              headerParts.Nonce,
		Timestamp:          headerParts.Timestamp,
		VerificationMethod: headerParts.VerificationMethod,
		Signature:          headerParts.Signature,
	}

	ok, message := anp_auth.VerifyAuthJSON(&authJSON, doc, serviceDomain)
	if !ok {
		log.Fatalf("verification failed: %s", message)
	}

	if message != "" {
		fmt.Println(message)
	} else {
		fmt.Println("Verification succeeded")
	}
}

func loadHeader(path string) (*headerArtifact, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var artifact headerArtifact
	if err := json.Unmarshal(data, &artifact); err != nil {
		return nil, err
	}
	if artifact.AuthHeader == "" {
		return nil, fmt.Errorf("auth_header is empty")
	}
	return &artifact, nil
}

func loadParams(path string) (*paramsArtifact, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var params paramsArtifact
	if err := json.Unmarshal(data, &params); err != nil {
		return nil, err
	}
	return &params, nil
}

func loadDidDocument(path string) (*anp_auth.DIDWBADocument, error) {
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

func parseHeader(header string) (*parsedHeader, error) {
	if header == "" {
		return nil, fmt.Errorf("authorization header cannot be empty")
	}

	if len(header) < 7 || header[:6] != "DIDWba" {
		return nil, fmt.Errorf("authorization header must start with 'DIDWba'")
	}

	matches := headerPattern.FindAllStringSubmatch(header, -1)
	if len(matches) == 0 {
		return nil, fmt.Errorf("authorization header has unexpected format")
	}

	result := &parsedHeader{}
	for _, match := range matches {
		switch match[1] {
		case "did":
			result.DID = match[2]
		case "nonce":
			result.Nonce = match[2]
		case "timestamp":
			result.Timestamp = match[2]
		case "verification_method":
			result.VerificationMethod = match[2]
		case "signature":
			result.Signature = match[2]
		}
	}

	if result.DID == "" || result.Nonce == "" || result.Timestamp == "" || result.VerificationMethod == "" || result.Signature == "" {
		return nil, fmt.Errorf("authorization header missing required fields")
	}

	return result, nil
}
