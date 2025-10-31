package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"anp/anp_auth"
	"anp/crypto"
)

func main() {
	var (
		docPath       string
		keyPath       string
		serviceDomain string
		outputFormat  string
	)

	flag.StringVar(&docPath, "doc", "public-did-doc.json", "Path to DID document JSON")
	flag.StringVar(&keyPath, "key", "public-private-key.pem", "Path to PEM encoded private key")
	flag.StringVar(&serviceDomain, "domain", "didhost.cc", "Service domain used in signature payload")
	flag.StringVar(&outputFormat, "format", "header", "Output format: header or json")
	flag.Parse()

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("failed to get working directory: %v", err)
	}

	if !filepath.IsAbs(docPath) {
		docPath = filepath.Join(cwd, docPath)
	}
	if !filepath.IsAbs(keyPath) {
		keyPath = filepath.Join(cwd, keyPath)
	}

	docBytes, err := os.ReadFile(docPath)
	if err != nil {
		log.Fatalf("failed to read DID document: %v", err)
	}

	var doc anp_auth.DIDWBADocument
	if err := json.Unmarshal(docBytes, &doc); err != nil {
		log.Fatalf("failed to parse DID document: %v", err)
	}

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		log.Fatalf("failed to read private key: %v", err)
	}

	privateKey, err := crypto.PrivateKeyFromPEM(keyBytes)
	if err != nil {
		log.Fatalf("failed to decode private key: %v", err)
	}

	switch strings.ToLower(outputFormat) {
	case "header":
		header, err := anp_auth.GenerateAuthHeader(privateKey, &doc, serviceDomain)
		if err != nil {
			log.Fatalf("failed to generate DID-WBA header: %v", err)
		}
		fmt.Println("Generated Authorization header:")
		fmt.Println(header.String())
	case "json":
		authJSON, err := anp_auth.GenerateAuthJSON(privateKey, &doc, serviceDomain)
		if err != nil {
			log.Fatalf("failed to generate DID-WBA JSON payload: %v", err)
		}
		payload, err := json.MarshalIndent(authJSON, "", "  ")
		if err != nil {
			log.Fatalf("failed to marshal auth JSON: %v", err)
		}
		fmt.Println("Generated Authorization JSON:")
		fmt.Println(string(payload))
	default:
		log.Fatalf("unsupported format: %s (use 'header' or 'json')", outputFormat)
	}
}
